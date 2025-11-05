// --- File: keyservice/config/keyservice_config_test.go ---
package config_test

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	// Import the package we are testing
	"github.com/tinywideclouds/go-key-service/keyservice/config"
)

// newBaseConfig creates a mock "Stage 1" config,
// simulating what NewConfigFromYaml would produce.
// We must now use the exported config.Config type.
func newBaseConfig() *config.Config {
	return &config.Config{
		RunMode:            "base-mode",
		ProjectID:          "base-project",
		HTTPListenAddr:     ":8080",
		IdentityServiceURL: "http://base-id-service.com",
		// JWTSecret is intentionally empty after Stage 1
	}
}

func TestUpdateConfigWithEnvOverrides(t *testing.T) {

	t.Run("Success - All overrides applied", func(t *testing.T) {
		// Arrange
		baseCfg := newBaseConfig()

		// Set all environment variables to override
		t.Setenv("GCP_PROJECT_ID", "env-project-override")
		t.Setenv("IDENTITY_SERVICE_URL", "http://env-id-service.com")
		t.Setenv("JWT_SECRET", "my-secret-key-from-env")

		// Act
		// This is the "Stage 2" function (now called as config.UpdateConfigWithEnvOverrides)
		cfg, err := config.UpdateConfigWithEnvOverrides(baseCfg)

		// Assert
		require.NoError(t, err)
		require.NotNil(t, cfg)

		// Check that overrides were applied
		assert.Equal(t, "env-project-override", cfg.ProjectID)
		assert.Equal(t, "http://env-id-service.com", cfg.IdentityServiceURL)
		assert.Equal(t, "my-secret-key-from-env", cfg.JWTSecret)

		// Check that non-overridden fields remain
		assert.Equal(t, "base-mode", cfg.RunMode)
		assert.Equal(t, ":8080", cfg.HTTPListenAddr)
	})

	t.Run("Success - Only required JWT_SECRET applied", func(t *testing.T) {
		// Arrange
		baseCfg := newBaseConfig()

		// Unset optional overrides to be sure
		os.Unsetenv("GCP_PROJECT_ID")
		os.Unsetenv("IDENTITY_SERVICE_URL")

		// Set *only* the required env var
		t.Setenv("JWT_SECRET", "my-secret-key-from-env")

		// Act
		cfg, err := config.UpdateConfigWithEnvOverrides(baseCfg)

		// Assert
		require.NoError(t, err)
		require.NotNil(t, cfg)

		// Check that base fields remain
		assert.Equal(t, "base-project", cfg.ProjectID)
		assert.Equal(t, "http://base-id-service.com", cfg.IdentityServiceURL)

		// Check that the required env var was set
		assert.Equal(t, "my-secret-key-from-env", cfg.JWTSecret)
	})

	t.Run("Failure - Missing required JWT_SECRET", func(t *testing.T) {
		// Arrange
		baseCfg := newBaseConfig()

		// Ensure JWT_SECRET is not set
		os.Unsetenv("JWT_SECRET")

		// Set other vars to ensure the check is specific to JWT_SECRET
		t.Setenv("GCP_PROJECT_ID", "env-project-override")

		// Act
		cfg, err := config.UpdateConfigWithEnvOverrides(baseCfg)

		// Assert
		assert.Error(t, err)
		assert.Nil(t, cfg)
		assert.Contains(t, err.Error(), "JWT_SECRET environment variable is not set or is empty")
	})
}
