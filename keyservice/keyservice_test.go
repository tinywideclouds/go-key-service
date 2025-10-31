//go:build integration

package keyservice_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/illmade-knight/go-microservice-base/pkg/middleware"
	"github.com/illmade-knight/go-microservice-base/pkg/response"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/tinywideclouds/go-key-service/internal/api"      // Import api for context key
	"github.com/tinywideclouds/go-key-service/keyservice"        // Use the package name
	"github.com/tinywideclouds/go-key-service/keyservice/config" // <-- Use new config

	// --- V2 Imports ---
	"github.com/tinywideclouds/go-platform/pkg/keys/v1"
	"github.com/tinywideclouds/go-platform/pkg/net/v1"
)

// --- MockStore (Corrected) ---
type MockStore struct {
	mock.Mock
}

// StoreKey is the mock implementation for storing a key.
func (m *MockStore) StoreKey(ctx context.Context, entityURN urn.URN, key []byte) error {
	args := m.Called(ctx, entityURN, key)
	return args.Error(0)
}

// GetKey is the mock implementation for retrieving a key.
func (m *MockStore) GetKey(ctx context.Context, entityURN urn.URN) ([]byte, error) {
	args := m.Called(ctx, entityURN)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]byte), args.Error(1)
}

// StorePublicKeys is the mock implementation for storing a V2 PublicKeys struct.
func (m *MockStore) StorePublicKeys(ctx context.Context, entityURN urn.URN, keys keys.PublicKeys) error {
	args := m.Called(ctx, entityURN, keys)
	return args.Error(0)
}

// GetPublicKeys is the mock implementation for retrieving a V2 PublicKeys struct.
//
// CORRECTED: This now returns a VALUE (keys.PublicKeys), not a pointer,
// matching the store.go interface and fixing the panic.
func (m *MockStore) GetPublicKeys(ctx context.Context, entityURN urn.URN) (keys.PublicKeys, error) {
	args := m.Called(ctx, entityURN)
	// Handle nil return for error cases
	if args.Get(0) == nil {
		return keys.PublicKeys{}, args.Error(1)
	}
	// This assertion is now valid and will not panic.
	return args.Get(0).(keys.PublicKeys), args.Error(1)
}

// --- Test Setup Helpers ---

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

// --- NEW Mock Auth Middleware ---
// newMockAuthMiddleware simulates a working auth middleware.
// It parses the token (without verification) to get the "sub" claim
// and injects it into the context, just as the real middleware would.
func newMockAuthMiddleware(t *testing.T) func(http.Handler) http.Handler {
	t.Helper()
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				response.WriteJSONError(w, http.StatusUnauthorized, "Unauthorized: Missing token")
				return
			}
			tokenString := strings.TrimPrefix(authHeader, "Bearer ")
			if tokenString == authHeader {
				response.WriteJSONError(w, http.StatusUnauthorized, "Unauthorized: Invalid token format")
				return
			}

			// Parse the token insecurely *just for this test* to get the subject
			token, err := jwt.ParseInsecure([]byte(tokenString))
			if err != nil {
				response.WriteJSONError(w, http.StatusUnauthorized, "Unauthorized: Invalid token")
				return
			}
			userID := token.Subject()
			if userID == "" {
				response.WriteJSONError(w, http.StatusUnauthorized, "Unauthorized: Invalid user ID in token")
				return
			}

			// Inject the user ID into the context
			ctx := context.WithValue(r.Context(), api.UserContextKey, userID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// --- Main Test Function ---

func TestKeyService_Integration(t *testing.T) {
	// 1. Setup shared resources
	logger := zerolog.Nop()
	// We still need the key to *sign* tokens, even if we don't verify them
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// 2. Setup mock Store
	mockStore := new(MockStore)

	// 3. Create the new consolidated Config
	cfg := &config.Config{
		HTTPListenAddr: ":0", // Use :0 for dynamic port
		// IdentityServiceURL is no longer needed for this test
		JWTSecret: "not-used-by-mock-auth",
		CorsConfig: middleware.CorsConfig{
			AllowedOrigins: []string{"http://test-origin.com"},
			Role:           middleware.CorsRoleDefault,
		},
	}

	// 5. Create Auth Middleware (using our new mock)
	authMiddleware := newMockAuthMiddleware(t)

	// 6. Create the service with the new config
	service := keyservice.New(cfg, mockStore, authMiddleware, logger)

	// 7. Start the service
	keyServiceServer := httptest.NewServer(service.Mux())
	defer keyServiceServer.Close()

	// --- V1 API Tests (Largely unchanged) ---

	t.Run("V1_StoreKey - Success 201", func(t *testing.T) {
		// Arrange
		testURN, _ := urn.New(urn.SecureMessaging, "user", "user-123")
		token := createTestToken(t, privateKey, "user-123")
		keyPayload := []byte("my-public-key-v1")

		mockStore.On("StoreKey", mock.Anything, testURN, keyPayload).Return(nil).Once()

		req, _ := http.NewRequest(http.MethodPost, keyServiceServer.URL+"/keys/"+testURN.String(), bytes.NewBuffer(keyPayload))
		req.Header.Set("Authorization", "Bearer "+token)

		// Act
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		// Assert
		assert.Equal(t, http.StatusCreated, resp.StatusCode)
		mockStore.AssertExpectations(t)
	})

	t.Run("V1_GetKey - Success 200 (public endpoint)", func(t *testing.T) {
		// Arrange
		testURN, _ := urn.New(urn.SecureMessaging, "user", "user-to-get")
		keyPayload := []byte("the-key-to-find-v1")

		mockStore.On("GetKey", mock.Anything, testURN).Return(keyPayload, nil).Once()

		req, _ := http.NewRequest(http.MethodGet, keyServiceServer.URL+"/keys/"+testURN.String(), nil)

		// Act
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		// Assert
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		body, _ := io.ReadAll(resp.Body)
		assert.Equal(t, keyPayload, body)
		mockStore.AssertExpectations(t)
	})

	// --- NEW V2 API Tests ---

	t.Run("V2_StorePublicKeys - Success 201", func(t *testing.T) {
		// Arrange
		authedUserID := "authed-v2-user"
		testURN, _ := urn.New(urn.SecureMessaging, "user", authedUserID)
		token := createTestToken(t, privateKey, authedUserID)

		nativeKeys := keys.PublicKeys{
			EncKey: []byte{1, 2, 3},
			SigKey: []byte{4, 5, 6},
		}
		// The JSON body our client will send (camelCase)
		jsonBody := `{"encKey":"AQID","sigKey":"BAUG"}`

		// We expect the *native* struct to be passed to the store
		mockStore.On("StorePublicKeys", mock.Anything, testURN, nativeKeys).Return(nil).Once()

		req, _ := http.NewRequest(http.MethodPost, keyServiceServer.URL+"/api/v2/keys/"+testURN.String(), strings.NewReader(jsonBody))
		req.Header.Set("Authorization", "Bearer "+token)

		// Act
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		// Assert
		assert.Equal(t, http.StatusCreated, resp.StatusCode)
		mockStore.AssertExpectations(t)
	})

	t.Run("V2_StorePublicKeys - Failure 403 (Mismatch User)", func(t *testing.T) {
		// Arrange
		authedUserID := "authed-v2-user"
		differentURN, _ := urn.New(urn.SecureMessaging, "user", "different-user")
		token := createTestToken(t, privateKey, authedUserID) // Token is for 'authed-v2-user'
		jsonBody := `{"encKey":"AQID","sigKey":"BAUG"}`

		// No store call is expected
		req, _ := http.NewRequest(http.MethodPost, keyServiceServer.URL+"/api/v2/keys/"+differentURN.String(), strings.NewReader(jsonBody))
		req.Header.Set("Authorization", "Bearer "+token)

		// Act
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		// Assert
		assert.Equal(t, http.StatusForbidden, resp.StatusCode) // This will now pass
		mockStore.AssertNotCalled(t, "StorePublicKeys")
	})

	t.Run("V2_GetPublicKeys - Success 200", func(t *testing.T) {
		// Arrange
		testURN, _ := urn.New(urn.SecureMessaging, "user", "v2-user-to-get")

		// This is the *native* struct our store will return
		nativeKeys := keys.PublicKeys{
			EncKey: []byte{1, 2, 3},
			SigKey: []byte{4, 5, 6},
		}
		// This is the *camelCase* JSON we expect our API to return
		expectedJSON := `{"encKey":"AQID","sigKey":"BAUG"}`

		// REFACTOR: The mock returns the VALUE, not a pointer
		mockStore.On("GetPublicKeys", mock.Anything, testURN).Return(nativeKeys, nil).Once()

		req, _ := http.NewRequest(http.MethodGet, keyServiceServer.URL+"/api/v2/keys/"+testURN.String(), nil)

		// Act
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		// Assert
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		body, _ := io.ReadAll(resp.Body)
		// This test is now valid and robust, as the handler will
		// call the value-receiver MarshalJSON() method.
		assert.JSONEq(t, expectedJSON, string(body))
		assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
		mockStore.AssertExpectations(t)
	})

	t.Run("V2_GetPublicKeys - Failure 404", func(t *testing.T) {
		// Arrange
		testURN, _ := urn.New(urn.SecureMessaging, "user", "v2-user-not-found")

		// REFACTOR: Return the zero-value for keys.PublicKeys
		mockStore.On("GetPublicKeys", mock.Anything, testURN).Return(keys.PublicKeys{}, errors.New("not found")).Once()

		req, _ := http.NewRequest(http.MethodGet, keyServiceServer.URL+"/api/v2/keys/"+testURN.String(), nil)

		// Act
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		// Assert
		assert.Equal(t, http.StatusNotFound, resp.StatusCode)
		mockStore.AssertExpectations(t)
	})
}
