package test

import (
	"io"       // IMPORTED
	"log/slog" // IMPORTED
	"net/http"
	"net/http/httptest"

	"cloud.google.com/go/firestore"
	fs "github.com/tinywideclouds/go-key-service/internal/storage/firestore"
	inmemorystore "github.com/tinywideclouds/go-key-service/internal/storage/inmemory"
	"github.com/tinywideclouds/go-key-service/keyservice"
	"github.com/tinywideclouds/go-key-service/keyservice/config"
	"github.com/tinywideclouds/go-microservice-base/pkg/middleware"
)

// NewTestServer creates and starts a new httptest.Server for end-to-end testing.
// It assembles the service with an in-memory store and a provided auth middleware.
func NewTestServer(authMiddleware func(http.Handler) http.Handler) *httptest.Server {
	// Use a default config for testing.
	cfg := &config.Config{
		HTTPListenAddr: ":0",
		CorsConfig: middleware.CorsConfig{
			AllowedOrigins: []string{"*"}, // Allow all for tests
			Role:           middleware.CorsRoleDefault,
		},
	}
	store := inmemorystore.New()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	service := keyservice.NewKeyService(cfg, store, authMiddleware, logger)
	server := httptest.NewServer(service.Mux())

	return server
}

// NewTestKeyService creates and starts a new httptest.Server for the key service,
// backed by a real (emulated) Firestore client.
func NewTestKeyService(
	fsClient *firestore.Client,
	collectionName string,
	authMiddleware func(http.Handler) http.Handler,
) *httptest.Server {
	cfg := &config.Config{
		HTTPListenAddr: ":0",
		CorsConfig: middleware.CorsConfig{
			AllowedOrigins: []string{"*"},
			Role:           middleware.CorsRoleDefault,
		},
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	store := fs.NewFirestoreStore(fsClient, collectionName, logger)

	service := keyservice.NewKeyService(cfg, store, authMiddleware, logger)
	server := httptest.NewServer(service.Mux())

	return server
}
