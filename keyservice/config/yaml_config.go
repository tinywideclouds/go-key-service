// --- File: keyservice/config/yaml_config.go ---
package config

import (
	"log/slog"

	"github.com/tinywideclouds/go-microservice-base/pkg/middleware"
)

// YamlConfig is the structure that mirrors the raw config.yaml file.
type YamlConfig struct {
	RunMode             string `yaml:"run_mode"`
	ProjectID           string `yaml:"project_id"`
	HTTPListenAddr      string `yaml:"http_listen_addr"`
	IdentityServiceURL  string `yaml:"identity_service_url"`
	FirestoreCollection string `yaml:"firestore_collection"` // ADDED
	Cors                struct {
		AllowedOrigins []string `yaml:"allowed_origins"`
		Role           string   `yaml:"cors_role"`
	} `yaml:"cors"`
}

// NewConfigFromYaml converts the YamlConfig into a clean, base Config struct.
// This struct is the "Stage 1" configuration, ready to be augmented by environment overrides.
func NewConfigFromYaml(baseCfg *YamlConfig, logger *slog.Logger) (*Config, error) {
	logger.Debug("Mapping YAML config to base config struct")

	// Map and Build initial Config structure
	cfg := &Config{
		RunMode:             baseCfg.RunMode,
		ProjectID:           baseCfg.ProjectID,
		HTTPListenAddr:      baseCfg.HTTPListenAddr,
		IdentityServiceURL:  baseCfg.IdentityServiceURL,
		FirestoreCollection: baseCfg.FirestoreCollection,
		// Map Cors data here since it's a direct YAML-to-Config mapping
		CorsConfig: middleware.CorsConfig{
			AllowedOrigins: baseCfg.Cors.AllowedOrigins,
			Role:           middleware.CorsRole(baseCfg.Cors.Role),
		},
	}
	// Note: JWTSecret is intentionally left blank here, as it's an override/injection point.

	logger.Debug("YAML config mapping complete",
		"run_mode", cfg.RunMode,
		"project_id", cfg.ProjectID,
		"http_listen_addr", cfg.HTTPListenAddr,
		"identity_service_url", cfg.IdentityServiceURL,
		"firestore_collection", cfg.FirestoreCollection,
		"cors_origins", cfg.CorsConfig.AllowedOrigins,
		"cors_role", cfg.CorsConfig.Role,
	)

	return cfg, nil
}
