// --- File: keyservice/keyservice.go ---
package keyservice

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/tinywideclouds/go-key-service/internal/api"
	"github.com/tinywideclouds/go-key-service/keyservice/config"
	"github.com/tinywideclouds/go-key-service/pkg/keystore"
	"github.com/tinywideclouds/go-microservice-base/pkg/microservice"
	"github.com/tinywideclouds/go-microservice-base/pkg/middleware"
)

// Wrapper encapsulates the key service, embedding a BaseServer to provide
// standard microservice functionality (startup, shutdown, health checks).
type Wrapper struct {
	*microservice.BaseServer
	logger *slog.Logger
}

// NewKeyService creates and wires up the entire key service.
// It initializes the base server, creates the API handlers,
// and registers all routes with the appropriate middleware.
func NewKeyService(
	cfg *config.Config,
	store keystore.Store,
	authMiddleware func(http.Handler) http.Handler, // Accept middleware via DI
	logger *slog.Logger,
) *Wrapper {
	// 1. Create the standard base server.
	baseServer := microservice.NewBaseServer(logger, cfg.HTTPListenAddr)

	// 2. Create the service-specific API handlers.
	apiHandler := &api.API{Store: store, Logger: logger, JWTSecret: cfg.JWTSecret}

	// 3. Get the mux from the base server and register routes.
	mux := baseServer.Mux()

	// 4. Create CORS middleware from the config.
	corsMiddleware := middleware.NewCorsMiddleware(cfg.CorsConfig, logger)
	optionsHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})

	// 5. Register OPTIONS for CORS pre-flight
	mux.Handle("OPTIONS /keys/{entityURN}", corsMiddleware(optionsHandler))

	// 6. Register API Routes
	storeKeyHandler := http.HandlerFunc(apiHandler.StoreKeysHandler)
	mux.Handle("POST /keys/{entityURN}", corsMiddleware(authMiddleware(storeKeyHandler)))

	getKeyHandler := http.HandlerFunc(apiHandler.GetKeysHandler)
	mux.Handle("GET /keys/{entityURN}", corsMiddleware(getKeyHandler))

	return &Wrapper{
		BaseServer: baseServer,
		logger:     logger,
	}
}

// Start runs the HTTP server and handles service readiness logic.
// It blocks until the server is ready to accept connections,
// then sets the service's ready state.
// It returns any error encountered during startup or runtime.
func (w *Wrapper) Start() error {
	errChan := make(chan error, 1)
	httpReadyChan := make(chan struct{})
	w.BaseServer.SetReadyChannel(httpReadyChan)

	go func() {
		if err := w.BaseServer.Start(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			w.logger.Error("HTTP server failed", "err", err)
			errChan <- err
		}
		close(errChan)
	}()

	// Wait for EITHER the server to be ready OR for it to fail on startup
	select {
	case <-httpReadyChan:
		// This channel is closed by BaseServer.Start() *after* net.Listen() succeeds
		w.logger.Info("HTTP listener is active.")
		// Since key-service has no other startup tasks, it's safe to set ready.
		w.SetReady(true)
		w.logger.Info("Service is now ready.")

	case err := <-errChan:
		// Server failed before it could listen
		return err
	}

	// Wait for the server goroutine to exit (which happens on Shutdown)
	return <-errChan
}
