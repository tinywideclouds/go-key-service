package config

import (
	"fmt"
	"os"

	"github.com/illmade-knight/go-microservice-base/pkg/middleware"
	"gopkg.in/yaml.v3"
)

// YamlConfig is the structure that mirrors the raw config.yaml file.
type YamlConfig struct {
	RunMode            string `yaml:"run_mode"`
	ProjectID          string `yaml:"project_id"`
	HTTPListenAddr     string `yaml:"http_listen_addr"`
	IdentityServiceURL string `yaml:"identity_service_url"`
	Cors               struct {
		AllowedOrigins []string `yaml:"allowed_origins"`
		Role           string   `yaml:"cors_role"`
	} `yaml:"cors"`
}

// NewConfigFromYaml converts the raw unmarshaled data (YamlConfig) into a clean, base Config struct.
// Stage 1 complete: The Config struct now exists, but without environment overrides.
func NewConfigFromYaml(baseCfg *YamlConfig) (*Config, error) {
	// 1. Map and Build initial Config structure
	cfg := &Config{
		RunMode:            baseCfg.RunMode,
		ProjectID:          baseCfg.ProjectID,
		HTTPListenAddr:     baseCfg.HTTPListenAddr,
		IdentityServiceURL: baseCfg.IdentityServiceURL,
		// Map Cors data here since it's a direct YAML-to-Config mapping
		CorsConfig: middleware.CorsConfig{
			AllowedOrigins: baseCfg.Cors.AllowedOrigins,
			Role:           middleware.CorsRole(baseCfg.Cors.Role),
		},
	}
	// Note: JWTSecret is intentionally left blank here, as it's an override/injection point (Stage 2)

	return cfg, nil
}

// LoadFromFile reads a YAML file and then overrides fields with
// environment variables using the standard library.
func LoadFromFile(path string) (*Config, error) {
	// 1. Load from YAML file
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file at %s: %w", path, err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse YAML config: %w", err)
	}

	// 2. Override with Environment Variables (using standard library)
	// (This logic is moved from runscalablekeyservice.go)
	if projectID := os.Getenv("GCP_PROJECT_ID"); projectID != "" {
		cfg.ProjectID = projectID
	}
	if idURL := os.Getenv("IDENTITY_SERVICE_URL"); idURL != "" {
		cfg.IdentityServiceURL = idURL
	}
	if jwtSecret := os.Getenv("JWT_SECRET"); jwtSecret != "" {
		cfg.JWTSecret = jwtSecret
	}

	// 3. Validate required environment variables
	if cfg.JWTSecret == "" {
		// The service will fail without this.
		return nil, fmt.Errorf("JWT_SECRET environment variable is not set or is empty")
	}

	// 4. Post-process: Map the loaded YAML struct to the middleware struct
	// (This logic is also moved from runscalablekeyservice.go)
	cfg.CorsConfig = middleware.CorsConfig{
		AllowedOrigins: cfg.Cors.AllowedOrigins,
		Role:           middleware.CorsRoleDefault,
	}

	return &cfg, nil
}
