// --- File: keyservice/config/config_test.go ---
// (This is the test for the newly refactored config.go)

package config

import (
	"os"
	"testing"

	"github.com/illmade-knight/go-microservice-base/pkg/middleware"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Helper function to create a temporary YAML config file for tests.
func createTempYAML(t *testing.T, content string) string {
	t.Helper()
	tmpfile, err := os.CreateTemp("", "config-*.yaml")
	require.NoError(t, err)
	t.Cleanup(func() { os.Remove(tmpfile.Name()) }) // Clean up the file after the test

	_, err = tmpfile.WriteString(content)
	require.NoError(t, err)
	err = tmpfile.Close()
	require.NoError(t, err)

	return tmpfile.Name()
}

func TestLoad(t *testing.T) {
	// Base YAML content for tests
	baseYAML := `
run_mode: "local"
project_id: "yaml-project"
http_listen_addr: ":8081"
identity_service_url: "http://yaml-id-service.com"
cors:
  allowed_origins:
    - "http://yaml-origin.com"
`

	t.Run("Success - Loads from YAML and Env Vars", func(t *testing.T) {
		// Arrange
		yamlPath := createTempYAML(t, baseYAML)

		// Set environment variables that will override YAML
		t.Setenv("GCP_PROJECT_ID", "env-project")
		t.Setenv("IDENTITY_SERVICE_URL", "http://env-id-service.com")
		t.Setenv("JWT_SECRET", "my-super-secret-jwt-key")

		// Act
		cfg, err := Load(yamlPath)

		// Assert
		require.NoError(t, err)
		require.NotNil(t, cfg)

		// Check YAML values
		assert.Equal(t, "local", cfg.RunMode)
		assert.Equal(t, ":8081", cfg.HTTPListenAddr)

		// Check Env Var Overrides
		assert.Equal(t, "env-project", cfg.ProjectID)
		assert.Equal(t, "http://env-id-service.com", cfg.IdentityServiceURL)
		assert.Equal(t, "my-super-secret-jwt-key", cfg.JWTSecret)

		// Check CORS struct mapping
		require.NotNil(t, cfg.CorsConfig)
		assert.Equal(t, []string{"http://yaml-origin.com"}, cfg.CorsConfig.AllowedOrigins)
		assert.Equal(t, middleware.CorsRoleDefault, cfg.CorsConfig.Role)
	})

	t.Run("Failure - Missing required JWT_SECRET", func(t *testing.T) {
		// Arrange
		yamlPath := createTempYAML(t, baseYAML)
		// We DO NOT set the JWT_SECRET env var
		t.Setenv("GCP_PROJECT_ID", "env-project") // Set other vars to ensure it's not them

		// Act
		cfg, err := Load(yamlPath)

		// Assert
		assert.Error(t, err)
		assert.Nil(t, cfg)
		assert.Contains(t, err.Error(), "JWT_SECRET environment variable is not set or is empty")
	})

	t.Run("Failure - Missing config file", func(t *testing.T) {
		// Arrange
		// (No file created)

		// Act
		cfg, err := Load("non-existent-file.yaml")

		// Assert
		assert.Error(t, err)
		assert.Nil(t, cfg)
		assert.Contains(t, err.Error(), "failed to read config file")
	})

	t.Run("Failure - Malformed YAML", func(t *testing.T) {
		// Arrange
		malformedYAML := `
run_mode: "local"
project_id: "yaml-project"
  http_listen_addr: ":8081" # <-- Bad indentation
`
		yamlPath := createTempYAML(t, malformedYAML)
		t.Setenv("JWT_SECRET", "my-super-secret-jwt-key") // Set required env var

		// Act
		cfg, err := Load(yamlPath)

		// Assert
		assert.Error(t, err)
		assert.Nil(t, cfg)
		assert.Contains(t, err.Error(), "failed to parse YAML config")
	})
}
