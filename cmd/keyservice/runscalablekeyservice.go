// --- File: cmd/keyservice/runscalablekeyservice.go ---
package main

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"cloud.google.com/go/firestore"
	fs "github.com/tinywideclouds/go-key-service/internal/storage/firestore"
	"github.com/tinywideclouds/go-key-service/keyservice"
	"github.com/tinywideclouds/go-key-service/keyservice/config"
	keyservicepkg "github.com/tinywideclouds/go-key-service/pkg/keystore"
	"github.com/tinywideclouds/go-microservice-base/pkg/middleware"
	"gopkg.in/yaml.v3"
)

//go:embed local.yaml
var configFile []byte

func main() {
	// 1. Setup structured logging
	var logLevel slog.Level
	switch os.Getenv("LOG_LEVEL") {
	case "debug", "DEBUG":
		logLevel = slog.LevelDebug
	case "info", "INFO":
		logLevel = slog.LevelInfo
	case "warn", "WARN":
		logLevel = slog.LevelWarn
	case "error", "ERROR":
		logLevel = slog.LevelError
	default:
		logLevel = slog.LevelInfo
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: logLevel,
	}))
	slog.SetDefault(logger) // Set as the global default

	logger.Info("Starting Key Service", "logLevel", logLevel)

	ctx := context.Background()
	// --- 1. Load Configuration (Stage 1: From YAML) ---
	var yamlCfg config.YamlConfig

	if err := yaml.Unmarshal(configFile, &yamlCfg); err != nil {
		logger.Error("Failed to unmarshal embedded yaml config", "err", err)
		os.Exit(1)
	}

	baseCfg, err := config.NewConfigFromYaml(&yamlCfg, logger)
	if err != nil {
		logger.Error("Failed to build base configuration from YAML", "err", err)
		os.Exit(1)
	}

	// --- 2. Apply Overrides (Stage 2: From Env) ---
	cfg, err := config.UpdateConfigWithEnvOverrides(baseCfg, logger)
	if err != nil {
		logger.Error("Failed to finalize configuration with environment overrides", "err", err)
		os.Exit(1)
	}

	logger.Info("Configuration loaded", "run_mode", cfg.RunMode)

	// --- 3. Dependency Injection ---

	// 3a. Data Store
	store, err := newDependencies(ctx, cfg, logger)
	if err != nil {
		logger.Error("Failed to initialize core dependencies", "err", err)
		os.Exit(1)
	}

	// 3b. Authentication Middleware
	authMiddleware, err := newAuthMiddleware(cfg, logger)
	if err != nil {
		logger.Error("Failed to initialize authentication middleware", "err", err)
		os.Exit(1)
	}

	// --- 4. Create Service Instance ---
	service := keyservice.NewKeyService(cfg, store, authMiddleware, logger)

	// --- 5. Start Service and Handle Shutdown ---
	errChan := make(chan error, 1)
	go func() {
		logger.Info("Starting service...", "address", cfg.HTTPListenAddr)
		if startErr := service.Start(); startErr != nil && !errors.Is(startErr, http.ErrServerClosed) {
			errChan <- startErr
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-errChan:
		// This will catch startup errors or runtime errors
		logger.Error("Service failed", "err", err)
		os.Exit(1)
	case sig := <-quit:
		logger.Info("OS signal received, initiating shutdown.", "signal", sig.String())
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if shutdownErr := service.Shutdown(ctx); shutdownErr != nil {
			logger.Error("Service shutdown failed", "err", shutdownErr)
		} else {
			logger.Info("Service shutdown complete")
		}
	}
}

// newDependencies builds the service's data layer dependencies (Firestore client and the Store).
func newDependencies(ctx context.Context, cfg *config.Config, logger *slog.Logger) (keyservicepkg.Store, error) {
	logger.Debug("Connecting to Firestore", "project_id", cfg.ProjectID)
	fsClient, err := firestore.NewClient(ctx, cfg.ProjectID)
	if err != nil {
		logger.Error("Failed to create Firestore client", "project_id", cfg.ProjectID, "err", err)
		return nil, fmt.Errorf("failed to create Firestore client for project %s: %w", cfg.ProjectID, err)
	}

	// Use the collection name from the configuration
	store := fs.NewFirestoreStore(fsClient, cfg.FirestoreCollection, logger)
	logger.Info("Using Firestore key store", "project_id", cfg.ProjectID, "collection", cfg.FirestoreCollection)
	return store, nil
}

// newAuthMiddleware creates the JWT-validating middleware.
func newAuthMiddleware(cfg *config.Config, logger *slog.Logger) (func(http.Handler) http.Handler, error) {
	sanitizedIdentityURL := strings.Trim(cfg.IdentityServiceURL, "\"")
	logger.Debug("Discovering JWT config", "identity_url", sanitizedIdentityURL)

	jwksURL, err := middleware.DiscoverAndValidateJWTConfig(sanitizedIdentityURL, middleware.RSA256, logger)
	if err != nil {
		logger.Warn("JWT configuration validation failed. This may be fatal if auth is required.", "err", err)
		// We still try to start, but log the warning.
	} else {
		logger.Info("VERIFIED JWKS CONFIG")
	}

	authMiddleware, err := middleware.NewJWKSAuthMiddleware(jwksURL, logger)
	if err != nil {
		logger.Error("Failed to create auth middleware", "err", err)
		return nil, fmt.Errorf("failed to create auth middleware: %w", err)
	}
	logger.Debug("JWKS auth middleware created successfully")
	return authMiddleware, nil
}
