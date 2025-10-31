package main

import (
	"context"
	"errors"
	"flag"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"cloud.google.com/go/firestore"
	"github.com/illmade-knight/go-microservice-base/pkg/middleware"
	"github.com/rs/zerolog"
	fs "github.com/tinywideclouds/go-key-service/internal/storage/firestore"
	"github.com/tinywideclouds/go-key-service/keyservice"
	"github.com/tinywideclouds/go-key-service/keyservice/config"
)

func main() {
	logger := zerolog.New(os.Stdout).With().Timestamp().Logger()

	// --- 1. Load Configuration from YAML ---
	var configPath string
	flag.StringVar(&configPath, "config", "./cmd/keyservice/local.yaml", "Path to config file")
	flag.Parse()

	// 2. LOAD THE CONSOLIDATED CONFIG
	// This one function now loads YAML, overrides with env vars,
	// validates required fields (like JWT_SECRET), and maps the CORS struct.
	cfg, err := config.Load(configPath)
	if err != nil {
		logger.Fatal().Err(err).Msg("Failed to load configuration")
	}

	// 3. ALL MANUAL CONFIG LOGIC IS DELETED
	// (No more os.Getenv checks for GCP_PROJECT_ID, IDENTITY_SERVICE_URL, etc.)
	// (No more manual creation of a separate serviceCfg struct)
	logger.Info().Str("run_mode", cfg.RunMode).Msg("Configuration loaded")

	// --- 2. Dependency Injection ---
	fsClient, err := firestore.NewClient(context.Background(), cfg.ProjectID)
	if err != nil {
		logger.Fatal().Err(err).Str("project_id", cfg.ProjectID).Msg("Failed to create Firestore client")
	}

	store := fs.New(fsClient, "public-keys")
	logger.Info().Str("project_id", cfg.ProjectID).Msg("Using Firestore key store")

	// Auth middleware setup (unchanged)
	sanitizedIdentityURL := strings.Trim(cfg.IdentityServiceURL, "\"")
	jwksURL, err := middleware.DiscoverAndValidateJWTConfig(sanitizedIdentityURL, "RS256", logger)
	if err != nil {
		logger.Warn().Err(err).Msg("JWT configuration validation failed")
	} else {
		logger.Info().Msg("VERIFIED JWKS CONFIG")
	}

	authMiddleware, err := middleware.NewJWKSAuthMiddleware(jwksURL)
	if err != nil {
		logger.Fatal().Err(err).Msg("Failed to create auth middleware")
	}

	// 4. THIS IS THE CLEANUP
	// We no longer create the old, temporary 'serviceCfg'.
	// We just pass the main 'cfg' directly into New().
	service := keyservice.New(cfg, store, authMiddleware, logger)
	service.SetReady(true)

	// --- 4. Start Service and Handle Shutdown ---
	// (This section is unchanged)
	errChan := make(chan error, 1)
	go func() {
		logger.Info().Str("address", cfg.HTTPListenAddr).Msg("Starting service...")
		if startErr := service.Start(); startErr != nil && !errors.Is(startErr, http.ErrServerClosed) {
			errChan <- startErr
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-errChan:
		logger.Fatal().Err(err).Msg("Service failed to start")
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
