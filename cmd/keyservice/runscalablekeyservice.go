package main

import (
	"context"
	_ "embed"
	"errors"
	"fmt" // Added for new dependency functions
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"cloud.google.com/go/firestore"
	"github.com/rs/zerolog"
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
	logger := zerolog.New(os.Stdout).With().Timestamp().Logger()
	ctx := context.Background() // Define context once
	// --- 1. Load Configuration (I/O Layer) ---
	var yamlCfg config.YamlConfig

	// I/O Step: Unmarshal the embedded bytes
	if err := yaml.Unmarshal(configFile, &yamlCfg); err != nil {
		logger.Fatal().Err(err).Msg("Failed to unmarshal embedded yaml config")
	}

	// 2. Build Base Config (Stage 1: Input to Base Config)
	baseCfg, err := config.NewConfigFromYaml(&yamlCfg)
	if err != nil {
		logger.Fatal().Err(err).Msg("Failed to build base configuration from YAML")
	}

	// 3. Apply Overrides (Stage 2: Logic Application)
	cfg, err := config.UpdateConfigWithEnvOverrides(baseCfg)
	if err != nil {
		logger.Fatal().Err(err).Msg("Failed to finalize configuration with environment overrides")
	}

	logger.Info().Str("run_mode", cfg.RunMode).Msg("Configuration loaded")

	// --- 2. Dependency Injection (REFACTORED) ---

	// 2a. Data Store
	store, err := newDependencies(ctx, cfg, logger)
	if err != nil {
		logger.Fatal().Err(err).Msg("Failed to initialize core dependencies")
	}

	// 2b. Authentication Middleware
	authMiddleware, err := newAuthMiddleware(cfg, logger)
	if err != nil {
		logger.Fatal().Err(err).Msg("Failed to initialize authentication middleware")
	}

	// 3. Create Service Instance
	// --- MODIFIED: Simplified call to New ---
	service := keyservice.New(cfg, store, authMiddleware, logger)

	// --- 4. Start Service and Handle Shutdown (MODIFIED) ---
	errChan := make(chan error, 1)
	go func() {
		logger.Info().Str("address", cfg.HTTPListenAddr).Msg("Starting service...")
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
		logger.Fatal().Err(err).Msg("Service failed")
	case sig := <-quit:
		logger.Info().Str("signal", sig.String()).Msg("OS signal received, initiating shutdown.")
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if shutdownErr := service.Shutdown(ctx); shutdownErr != nil {
			logger.Error().Err(shutdownErr).Msg("Service shutdown failed")
		} else {
			logger.Info().Msg("Service shutdown complete")
		}
	}
}

// newDependencies builds the service's data layer dependencies (Firestore client and the Store).
func newDependencies(ctx context.Context, cfg *config.Config, logger zerolog.Logger) (keyservicepkg.Store, error) {
	fsClient, err := firestore.NewClient(ctx, cfg.ProjectID)
	if err != nil {
		return nil, fmt.Errorf("failed to create Firestore client for project %s: %w", cfg.ProjectID, err)
	}

	// The collection name should ideally come from config, but is hardcoded here for now.
	store := fs.New(fsClient, "public-keys")
	logger.Info().Str("project_id", cfg.ProjectID).Msg("Using Firestore key store")
	return store, nil
}

// newAuthMiddleware creates the JWT-validating middleware.
func newAuthMiddleware(cfg *config.Config, logger zerolog.Logger) (func(http.Handler) http.Handler, error) {
	sanitizedIdentityURL := strings.Trim(cfg.IdentityServiceURL, "\"")
	jwksURL, err := middleware.DiscoverAndValidateJWTConfig(sanitizedIdentityURL, "RS256", logger)
	if err != nil {
		logger.Warn().Err(err).Msg("JWT configuration validation failed")
	} else {
		logger.Info().Msg("VERIFIED JWKS CONFIG")
	}

	authMiddleware, err := middleware.NewJWKSAuthMiddleware(jwksURL)
	if err != nil {
		return nil, fmt.Errorf("failed to create auth middleware: %w", err)
	}
	return authMiddleware, nil
}
