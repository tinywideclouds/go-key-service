package main

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"log/slog" // IMPORTED
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"cloud.google.com/go/firestore"
	// "github.com/rs/zerolog" // REMOVED
	fs "github.com/tinywideclouds/go-key-service/internal/storage/firestore"
	"github.com/tinywideclouds/go-key-service/keyservice"
	"github.com/tinywideclouds/go-key-service/keyservice/config"
	"github.com/tinywideclouds/go-microservice-base/pkg/middleware"
	"gopkg.in/yaml.v3"

	// Added for new dependency functions
	keyservicepkg "github.com/tinywideclouds/go-key-service/pkg/keyservice"
)

//go:embed local.yaml
var configFile []byte

func main() {
	// --- REFACTORED TO SLOG ---
	// 1. Setup structured logging (REFACTORED TO SLOG)
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
	// --- END REFACTOR ---

	ctx := context.Background() // Define context once
	// --- 1. Load Configuration (I/O Layer) ---
	var yamlCfg config.YamlConfig

	// I/O Step: Unmarshal the embedded bytes
	if err := yaml.Unmarshal(configFile, &yamlCfg); err != nil {
		logger.Error("Failed to unmarshal embedded yaml config", "err", err) // CHANGED
		os.Exit(1)                                                           // Use os.Exit for fatal startup errors
	}

	// 2. Build Base Config (Stage 1: Input to Base Config)
	baseCfg, err := config.NewConfigFromYaml(&yamlCfg, logger) // CHANGED
	if err != nil {
		logger.Error("Failed to build base configuration from YAML", "err", err) // CHANGED
		os.Exit(1)
	}

	// 3. Apply Overrides (Stage 2: Logic Application)
	cfg, err := config.UpdateConfigWithEnvOverrides(baseCfg, logger) // CHANGED
	if err != nil {
		logger.Error("Failed to finalize configuration with environment overrides", "err", err) // CHANGED
		os.Exit(1)
	}

	logger.Info("Configuration loaded", "run_mode", cfg.RunMode) // CHANGED

	// --- 2. Dependency Injection (REFACTORED) ---

	// 2a. Data Store
	store, err := newDependencies(ctx, cfg, logger) // CHANGED
	if err != nil {
		logger.Error("Failed to initialize core dependencies", "err", err) // CHANGED
		os.Exit(1)
	}

	// 2b. Authentication Middleware
	authMiddleware, err := newAuthMiddleware(cfg, logger) // CHANGED
	if err != nil {
		logger.Error("Failed to initialize authentication middleware", "err", err) // CHANGED
		os.Exit(1)
	}

	// 3. Create Service Instance
	// --- MODIFIED: Simplified call to New ---
	service := keyservice.New(cfg, store, authMiddleware, logger) // CHANGED

	// --- 4. Start Service and Handle Shutdown (MODIFIED) ---
	errChan := make(chan error, 1)
	go func() {
		logger.Info("Starting service...", "address", cfg.HTTPListenAddr) // CHANGED
		// The service.Start() call now handles its own readiness logic
		if startErr := service.Start(); startErr != nil && !errors.Is(startErr, http.ErrServerClosed) {
			errChan <- startErr
		}
	}()

	// --- REMOVED: The 'select' block for httpReadyChan is no longer needed here ---

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-errChan:
		// This will now catch startup errors *or* runtime errors
		logger.Error("Service failed", "err", err) // CHANGED
		os.Exit(1)
	case sig := <-quit:
		logger.Info("OS signal received, initiating shutdown.", "signal", sig.String()) // CHANGED
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if shutdownErr := service.Shutdown(ctx); shutdownErr != nil {
			logger.Error("Service shutdown failed", "err", shutdownErr) // CHANGED
		} else {
			logger.Info("Service shutdown complete") // CHANGED
		}
	}
}

// newDependencies builds the service's data layer dependencies (Firestore client and the Store).
func newDependencies(ctx context.Context, cfg *config.Config, logger *slog.Logger) (keyservicepkg.Store, error) { // CHANGED
	logger.Debug("Connecting to Firestore", "project_id", cfg.ProjectID) // ADDED
	fsClient, err := firestore.NewClient(ctx, cfg.ProjectID)
	if err != nil {
		logger.Error("Failed to create Firestore client", "project_id", cfg.ProjectID, "err", err) // ADDED
		return nil, fmt.Errorf("failed to create Firestore client for project %s: %w", cfg.ProjectID, err)
	}

	// The collection name should ideally come from config, but is hardcoded here for now.
	store := fs.NewFirestoreStore(fsClient, "public-keys", logger)
	logger.Info("Using Firestore key store", "project_id", cfg.ProjectID, "collection", "public-keys") // CHANGED
	return store, nil
}

// newAuthMiddleware creates the JWT-validating middleware.
func newAuthMiddleware(cfg *config.Config, logger *slog.Logger) (func(http.Handler) http.Handler, error) { // CHANGED
	sanitizedIdentityURL := strings.Trim(cfg.IdentityServiceURL, "\"")
	logger.Debug("Discovering JWT config", "identity_url", sanitizedIdentityURL) // ADDED

	jwksURL, err := middleware.DiscoverAndValidateJWTConfig(sanitizedIdentityURL, middleware.RSA256, logger) // CHANGED
	if err != nil {
		logger.Warn("JWT configuration validation failed. This may be fatal if auth is required.", "err", err) // CHANGED
		// We still try to start, but log the warning.
	} else {
		logger.Info("VERIFIED JWKS CONFIG") // CHANGED
	}

	authMiddleware, err := middleware.NewJWKSAuthMiddleware(jwksURL, logger) // CHANGED
	if err != nil {
		logger.Error("Failed to create auth middleware", "err", err) // ADDED
		return nil, fmt.Errorf("failed to create auth middleware: %w", err)
	}
	logger.Debug("JWKS auth middleware created successfully") // ADDED
	return authMiddleware, nil
}
