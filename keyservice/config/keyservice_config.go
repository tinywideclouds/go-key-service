// --- File: keyservice/config/keyservice_config.go ---
package config

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/tinywideclouds/go-microservice-base/pkg/middleware"
)

// Config defines the *single*, authoritative configuration for the Key Service.
// It is created in two stages:
// 1. Loaded from YAML (see NewConfigFromYaml).
// 2. Updated with environment variables (see UpdateConfigWithEnvOverrides).
type Config struct {
	// Fields loaded from YAML
	RunMode             string `yaml:"run_mode"`
	ProjectID           string `yaml:"project_id"`
	HTTPListenAddr      string `yaml:"http_listen_addr"`
	IdentityServiceURL  string `yaml:"identity_service_url"`
	FirestoreCollection string `yaml:"firestore_collection"`

	Cors struct {
		AllowedOrigins []string `yaml:"allowed_origins"`
	} `yaml:"cors"`

	// CorsConfig is the processed, ready-to-use middleware config.
	CorsConfig middleware.CorsConfig `yaml:"-"` // Ignored by YAML

	// JWTSecret is populated from the "JWT_SECRET" env var.
	JWTSecret string `yaml:"-"` // Ignored by YAML
}

// UpdateConfigWithEnvOverrides takes the base configuration (created from YAML)
// and completes it by applying environment variables and final validation.
// This creates the final "Stage 2" runtime configuration.
func UpdateConfigWithEnvOverrides(cfg *Config, logger *slog.Logger) (*Config, error) {
	logger.Debug("Applying environment variable overrides...")

	// 1. Apply Environment Overrides
	if projectID := os.Getenv("GCP_PROJECT_ID"); projectID != "" {
		logger.Debug("Overriding config value", "key", "GCP_PROJECT_ID", "source", "env")
		cfg.ProjectID = projectID
	}
	if idURL := os.Getenv("IDENTITY_SERVICE_URL"); idURL != "" {
		logger.Debug("Overriding config value", "key", "IDENTITY_SERVICE_URL", "source", "env")
		cfg.IdentityServiceURL = idURL
	}
	// JWT Secret is exclusively environment-sourced
	if jwtSecret := os.Getenv("JWT_SECRET"); jwtSecret != "" {
		logger.Debug("Loaded config value", "key", "JWT_SECRET", "source", "env")
		cfg.JWTSecret = jwtSecret
	}

	// 2. Final Validation
	if cfg.JWTSecret == "" {
		logger.Error("Final config validation failed", "error", "JWT_SECRET is not set")
		return nil, fmt.Errorf("JWT_SECRET environment variable is not set or is empty")
	}

	logger.Debug("Configuration finalized and validated successfully")
	return cfg, nil
}
