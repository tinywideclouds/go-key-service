package config

import (
	"fmt"
	"log/slog" // IMPORTED
	"os"

	"github.com/tinywideclouds/go-microservice-base/pkg/middleware"
)

// Config defines the *single*, authoritative configuration for the Key Service.
type Config struct {
	// Fields loaded from YAML
	RunMode            string `yaml:"run_mode"`
	ProjectID          string `yaml:"project_id"`
	HTTPListenAddr     string `yaml:"http_listen_addr"`
	IdentityServiceURL string `yaml:"identity_service_url"`

	Cors struct {
		AllowedOrigins []string `yaml:"allowed_origins"`
	} `yaml:"cors"`

	// --- Fields Merged from pkg/keyservice/config.go ---

	// This will be populated by the Cors struct from YAML
	CorsConfig middleware.CorsConfig `yaml:"-"` // Ignored by YAML

	// This will be populated from the "JWT_SECRET" env var
	JWTSecret string `yaml:"-"` // Ignored by YAML
}

// UpdateConfigWithEnvOverrides takes the base configuration (created from YAML)
// and completes it by applying environment variables and final validation.
// Stage 2 complete: The final runtime Config is created.
func UpdateConfigWithEnvOverrides(cfg *Config, logger *slog.Logger) (*Config, error) { // CHANGED
	logger.Debug("Applying environment variable overrides...") // ADDED

	// 1. Apply Environment Overrides (Independent of YAML structure)
	if projectID := os.Getenv("GCP_PROJECT_ID"); projectID != "" {
		logger.Debug("Overriding config value", "key", "GCP_PROJECT_ID", "source", "env") // ADDED
		cfg.ProjectID = projectID
	}
	if idURL := os.Getenv("IDENTITY_SERVICE_URL"); idURL != "" {
		logger.Debug("Overriding config value", "key", "IDENTITY_SERVICE_URL", "source", "env") // ADDED
		cfg.IdentityServiceURL = idURL
	}
	// JWT Secret is exclusively environment-sourced
	if jwtSecret := os.Getenv("JWT_SECRET"); jwtSecret != "" {
		logger.Debug("Loaded config value", "key", "JWT_SECRET", "source", "env") // ADDED
		cfg.JWTSecret = jwtSecret
	}

	// 2. Final Validation
	if cfg.JWTSecret == "" {
		logger.Error("Final config validation failed", "error", "JWT_SECRET is not set") // ADDED
		return nil, fmt.Errorf("JWT_SECRET environment variable is not set or is empty")
	}

	// 3. Final Post-processing (CORS role cleanup if needed, but assumed done in Stage 1)
	logger.Debug("Configuration finalized and validated successfully") // ADDED
	return cfg, nil
}
