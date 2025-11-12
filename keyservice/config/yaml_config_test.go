// --- File: keyservice/config/yaml_config_test.go ---
package config_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tinywideclouds/go-key-service/keyservice/config"
	"github.com/tinywideclouds/go-microservice-base/pkg/middleware"
)

func TestNewConfigFromYaml(t *testing.T) {
	logger := newTestLogger()

	t.Run("Success - maps all fields correctly from YAML struct", func(t *testing.T) {
		// Arrange
		// This simulates the raw struct after unmarshaling the YAML file
		yamlCfg := &config.YamlConfig{
			RunMode:            "test-mode",
			ProjectID:          "yaml-project-id",
			HTTPListenAddr:     ":9090",
			IdentityServiceURL: "http://yaml-identity.com",
			// This is the fix for the hardcoded value
			FirestoreCollection: "my-keys-collection",
			Cors: struct {
				AllowedOrigins []string `yaml:"allowed_origins"`
				Role           string   `yaml:"cors_role"`
			}{
				AllowedOrigins: []string{"http://origin1.com", "http://origin2.com"},
				Role:           "my-custom-role",
			},
		}

		// Act
		cfg, err := config.NewConfigFromYaml(yamlCfg, logger)

		// Assert
		require.NoError(t, err)
		require.NotNil(t, cfg)

		// Check fields that were directly mapped
		assert.Equal(t, "test-mode", cfg.RunMode)
		assert.Equal(t, "yaml-project-id", cfg.ProjectID)
		assert.Equal(t, ":9090", cfg.HTTPListenAddr)
		assert.Equal(t, "http://yaml-identity.com", cfg.IdentityServiceURL)
		assert.Equal(t, "my-keys-collection", cfg.FirestoreCollection)

		// Check that the CORS struct was correctly processed and mapped
		assert.NotNil(t, cfg.CorsConfig)
		assert.Equal(t, []string{"http://origin1.com", "http://origin2.com"}, cfg.CorsConfig.AllowedOrigins)
		assert.Equal(t, middleware.CorsRole("my-custom-role"), cfg.CorsConfig.Role)

		// IMPORTANT: Check that fields set in Stage 2 are empty
		assert.Empty(t, cfg.JWTSecret, "JWTSecret should not be set at Stage 1")
	})
}
