package keyservice

import (
	"errors"
	"net/http"

	"github.com/rs/zerolog"
	"github.com/tinywideclouds/go-key-service/internal/api"
	"github.com/tinywideclouds/go-key-service/keyservice/config"
	"github.com/tinywideclouds/go-key-service/pkg/keyservice"
	"github.com/tinywideclouds/go-microservice-base/pkg/microservice"
	"github.com/tinywideclouds/go-microservice-base/pkg/middleware"
)

// Wrapper now embeds the BaseServer to inherit standard server functionality.
type Wrapper struct {
	*microservice.BaseServer
	logger zerolog.Logger
}

// New creates and wires up the entire key service.
func New(
	cfg *config.Config,
	store keyservice.Store,
	authMiddleware func(http.Handler) http.Handler, // Accept middleware via DI
	logger zerolog.Logger,
	// --- REMOVED: httpReadyChan chan struct{} ---
) *Wrapper {
	// 1. Create the standard base server.
	baseServer := microservice.NewBaseServer(logger, cfg.HTTPListenAddr)

	// --- REMOVED: baseServer.SetReadyChannel(httpReadyChan) ---

	// 2. Create the service-specific API handlers.
	apiHandler := &api.API{Store: store, Logger: logger, JWTSecret: cfg.JWTSecret}

	// 3. Get the mux from the base server and register routes.
	mux := baseServer.Mux()

	// 4. Create CORS middleware from the config.
	corsMiddleware := middleware.NewCorsMiddleware(cfg.CorsConfig)

	// --- 5. Register V1 API Routes (Unchanged) ---
	v1StoreKeyHandler := http.HandlerFunc(apiHandler.StoreKeyHandler)
	mux.Handle("POST /keys/{entityURN}", corsMiddleware(authMiddleware(v1StoreKeyHandler)))

	v1GetKeyHandler := http.HandlerFunc(apiHandler.GetKeyHandler)
	mux.Handle("GET /keys/{entityURN}", corsMiddleware(v1GetKeyHandler))

	v1OptionsHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	mux.Handle("OPTIONS /keys/{entityURN}", corsMiddleware(v1OptionsHandler))

	// --- 6. Register NEW V2 API Routes ---
	v2StoreKeyHandler := http.HandlerFunc(apiHandler.StorePublicKeysHandler)
	// We use a new, non-conflicting path for V2
	mux.Handle("POST /api/v2/keys/{entityURN}", corsMiddleware(authMiddleware(v2StoreKeyHandler)))

	v2GetKeyHandler := http.HandlerFunc(apiHandler.GetPublicKeysHandler)
	mux.Handle("GET /api/v2/keys/{entityURN}", corsMiddleware(v2GetKeyHandler))

	v2OptionsHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	mux.Handle("OPTIONS /api/v2/keys/{entityURN}", corsMiddleware(v2OptionsHandler))

	return &Wrapper{
		BaseServer: baseServer,
		logger:     logger,
	}
}

// --- ADDED: Start method to encapsulate readiness logic ---

// Start runs the HTTP server and handles the readiness logic.
func (w *Wrapper) Start() error {
	// This method now contains the logic that was in main.go
	errChan := make(chan error, 1)
	httpReadyChan := make(chan struct{})
	w.BaseServer.SetReadyChannel(httpReadyChan)

	go func() {
		if err := w.BaseServer.Start(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			w.logger.Error().Err(err).Msg("HTTP server failed")
			errChan <- err
		}
		close(errChan)
	}()

	// Wait for EITHER the server to be ready OR for it to fail on startup
	select {
	case <-httpReadyChan:
		// This channel is closed by BaseServer.Start() *after* net.Listen() succeeds
		w.logger.Info().Msg("HTTP listener is active.")
		// Since key-service has no other startup tasks, it's safe to set ready.
		w.SetReady(true)
		w.logger.Info().Msg("Service is now ready.")

	case err := <-errChan:
		// Server failed before it could listen
		return err
	}

	// Wait for the server goroutine to exit (which happens on Shutdown)
	return <-errChan
}
