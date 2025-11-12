// --- File: keyservice/keyservice_test.go ---
//go:build integration

package keyservice_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/tinywideclouds/go-key-service/keyservice"
	"github.com/tinywideclouds/go-key-service/keyservice/config"

	"github.com/tinywideclouds/go-microservice-base/pkg/middleware"
	"github.com/tinywideclouds/go-microservice-base/pkg/response"

	"github.com/tinywideclouds/go-platform/pkg/keys/v1"
	"github.com/tinywideclouds/go-platform/pkg/net/v1"
)

// newTestLogger creates a discard logger for tests.
func newTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// MockStore
type MockStore struct {
	mock.Mock
}

// StorePublicKeys is the mock implementation for storing a PublicKeys struct.
func (m *MockStore) StorePublicKeys(ctx context.Context, entityURN urn.URN, keys keys.PublicKeys) error {
	args := m.Called(ctx, entityURN, keys)
	return args.Error(0)
}

// GetPublicKeys is the mock implementation for retrieving a PublicKeys struct.
func (mS *MockStore) GetPublicKeys(ctx context.Context, entityURN urn.URN) (keys.PublicKeys, error) {
	args := mS.Called(ctx, entityURN)
	// Handle nil return for error cases
	if args.Get(0) == nil {
		return keys.PublicKeys{}, args.Error(1)
	}
	return args.Get(0).(keys.PublicKeys), args.Error(1)
}

// createTestToken generates a valid JWT signed by the given private key.
func createTestToken(t *testing.T, privateKey *rsa.PrivateKey, userID string) string {
	t.Helper()

	token, err := jwt.NewBuilder().
		Subject(userID).
		IssuedAt(time.Now()).
		Expiration(time.Now().Add(10 * time.Minute)).
		Build()
	require.NoError(t, err)

	jwkKey, err := jwk.FromRaw(privateKey)
	require.NoError(t, err)
	_ = jwkKey.Set(jwk.KeyIDKey, "test-key-id")

	signedToken, err := jwt.Sign(token, jwt.WithKey(jwa.RS256, jwkKey))
	require.NoError(t, err)

	return string(signedToken)
}

// newMockAuthMiddleware simulates a working auth middleware.
func newMockAuthMiddleware(t *testing.T, logger *slog.Logger) func(http.Handler) http.Handler {
	t.Helper()
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				logger.Debug("MockAuth: Missing token")
				response.WriteJSONError(w, http.StatusUnauthorized, "Unauthorized: Missing token")
				return
			}
			tokenString := strings.TrimPrefix(authHeader, "Bearer ")
			if tokenString == authHeader {
				logger.Debug("MockAuth: Invalid token format")
				response.WriteJSONError(w, http.StatusUnauthorized, "Unauthorized: Invalid token format")
				return
			}

			// Parse the token insecurely *just for this test* to get the subject
			token, err := jwt.ParseInsecure([]byte(tokenString))
			if err != nil {
				logger.Debug("MockAuth: Invalid token", "err", err)
				response.WriteJSONError(w, http.StatusUnauthorized, "Unauthorized: Invalid token")
				return
			}
			userID := token.Subject()
			if userID == "" {
				logger.Debug("MockAuth: Invalid user ID in token")
				response.WriteJSONError(w, http.StatusUnauthorized, "Unauthorized: Invalid user ID in token")
				return
			}

			// --- FIX: Use the correct middleware helper to inject the user ID ---
			ctx := middleware.ContextWithUserID(r.Context(), userID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func TestKeyService_Integration(t *testing.T) {
	// 1. Setup shared resources
	logger := newTestLogger()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// 2. Setup mock Store
	mockStore := new(MockStore)

	// 3. Create the new consolidated Config
	cfg := &config.Config{
		HTTPListenAddr: ":0", // Use :0 for dynamic port
		JWTSecret:      "not-used-by-mock-auth",
		CorsConfig: middleware.CorsConfig{
			AllowedOrigins: []string{"http://test-origin.com"},
			Role:           middleware.CorsRoleDefault,
		},
	}

	// 5. Create Auth Middleware (using our new mock)
	authMiddleware := newMockAuthMiddleware(t, logger)

	// 6. Create the service with the new config
	// --- FIX: Use the new function name ---
	service := keyservice.NewKeyService(cfg, mockStore, authMiddleware, logger)

	// 7. Start the service
	keyServiceServer := httptest.NewServer(service.Mux())
	defer keyServiceServer.Close()

	t.Run("StoreKeys - Success 201", func(t *testing.T) {
		// Arrange
		authedUserID := "authed-user"
		testURN, _ := urn.New(urn.SecureMessaging, "user", authedUserID)
		token := createTestToken(t, privateKey, authedUserID)

		nativeKeys := keys.PublicKeys{
			EncKey: []byte{1, 2, 3},
			SigKey: []byte{4, 5, 6},
		}
		jsonBody := `{"encKey":"AQID","sigKey":"BAUG"}`

		mockStore.On("StorePublicKeys", mock.Anything, testURN, nativeKeys).Return(nil).Once()

		req, _ := http.NewRequest(http.MethodPost, keyServiceServer.URL+"/keys/"+testURN.String(), strings.NewReader(jsonBody))
		req.Header.Set("Authorization", "Bearer "+token)

		// Act
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		// Assert
		assert.Equal(t, http.StatusCreated, resp.StatusCode)
		mockStore.AssertExpectations(t)
	})

	t.Run("StoreKeys - Failure 403 (Mismatch User)", func(t *testing.T) {
		// Arrange
		authedUserID := "authed-user"
		differentURN, _ := urn.New(urn.SecureMessaging, "user", "different-user")
		token := createTestToken(t, privateKey, authedUserID)
		jsonBody := `{"encKey":"AQID","sigKey":"BAUG"}`

		// No store call is expected
		req, _ := http.NewRequest(http.MethodPost, keyServiceServer.URL+"/keys/"+differentURN.String(), strings.NewReader(jsonBody))
		req.Header.Set("Authorization", "Bearer "+token)

		// Act
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		// Assert
		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
		mockStore.AssertNotCalled(t, "StorePublicKeys")
	})

	t.Run("GetKeys - Success 200", func(t *testing.T) {
		// Arrange
		testURN, _ := urn.New(urn.SecureMessaging, "user", "user-to-get")

		nativeKeys := keys.PublicKeys{
			EncKey: []byte{1, 2, 3},
			SigKey: []byte{4, 5, 6},
		}
		expectedJSON := `{"encKey":"AQID","sigKey":"BAUG"}`

		mockStore.On("GetPublicKeys", mock.Anything, testURN).Return(nativeKeys, nil).Once()

		req, _ := http.NewRequest(http.MethodGet, keyServiceServer.URL+"/keys/"+testURN.String(), nil)

		// Act
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		// Assert
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		body, _ := io.ReadAll(resp.Body)
		assert.JSONEq(t, expectedJSON, string(body))
		assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
		mockStore.AssertExpectations(t)
	})

	t.Run("GetKeys - Failure 404", func(t *testing.T) {
		// Arrange
		testURN, _ := urn.New(urn.SecureMessaging, "user", "user-not-found")

		mockStore.On("GetPublicKeys", mock.Anything, testURN).Return(keys.PublicKeys{}, errors.New("not found")).Once()

		req, _ := http.NewRequest(http.MethodGet, keyServiceServer.URL+"/keys/"+testURN.String(), nil)

		// Act
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		// Assert
		assert.Equal(t, http.StatusNotFound, resp.StatusCode)
		mockStore.AssertExpectations(t)
	})
}
