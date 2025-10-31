package config

import (
	"fmt"
	"os"

	"github.com/illmade-knight/go-microservice-base/pkg/middleware"
	"gopkg.in/yaml.v3"
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

// Load reads a YAML file and then overrides fields with
// environment variables using the standard library.
func Load(path string) (*Config, error) {
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
