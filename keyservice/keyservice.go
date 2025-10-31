package keyservice

import (
	"net/http"

	"github.com/illmade-knight/go-microservice-base/pkg/microservice"
	"github.com/illmade-knight/go-microservice-base/pkg/middleware"
	"github.com/rs/zerolog"
	"github.com/tinywideclouds/go-key-service/internal/api"
	"github.com/tinywideclouds/go-key-service/keyservice/config"
	"github.com/tinywideclouds/go-key-service/pkg/keyservice"
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
) *Wrapper {
	// 1. Create the standard base server.
	baseServer := microservice.NewBaseServer(logger, cfg.HTTPListenAddr)

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
