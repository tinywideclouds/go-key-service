package test

import (
	"net/http"
	"net/http/httptest"

	"cloud.google.com/go/firestore"
	"github.com/illmade-knight/go-microservice-base/pkg/middleware"
	"github.com/rs/zerolog"
	fs "github.com/tinywideclouds/go-key-service/internal/storage/firestore"
	inmemorystore "github.com/tinywideclouds/go-key-service/internal/storage/inmemory"
	"github.com/tinywideclouds/go-key-service/keyservice"
	"github.com/tinywideclouds/go-key-service/keyservice/config"
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
	logger := zerolog.Nop()

	service := keyservice.New(cfg, store, authMiddleware, logger)
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
	logger := zerolog.Nop()

	store := fs.New(fsClient, collectionName)

	service := keyservice.New(cfg, store, authMiddleware, logger)
	server := httptest.NewServer(service.Mux())

	return server
}
