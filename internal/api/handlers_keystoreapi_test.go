// REFACTOR: This test file is updated to validate the fully refactored,
// URN-aware API handlers.
//
// V2 REFACTOR: Updated MockStore to implement V2 interface. Added
// tests for StorePublicKeysHandler and GetPublicKeysHandler.

package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"       // IMPORTED
	"log/slog" // IMPORTED
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	// "github.com/rs/zerolog" // REMOVED
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/tinywideclouds/go-key-service/internal/api"
	"github.com/tinywideclouds/go-microservice-base/pkg/response"

	// --- V2 Imports ---
	"github.com/tinywideclouds/go-platform/pkg/keys/v1"
	"github.com/tinywideclouds/go-platform/pkg/net/v1"
)

// MockStore is a mock implementation of the keyservice.Store interface.
type MockStore struct {
	mock.Mock
}

// --- V1 Methods ---

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

// --- V2 Methods (NEW) ---

// StorePublicKeys is the mock implementation for storing a V2 PublicKeys struct.
func (m *MockStore) StorePublicKeys(ctx context.Context, entityURN urn.URN, keys keys.PublicKeys) error {
	args := m.Called(ctx, entityURN, keys)
	return args.Error(0)
}

// GetPublicKeys is the mock implementation for retrieving a V2 PublicKeys struct.
func (m *MockStore) GetPublicKeys(ctx context.Context, entityURN urn.URN) (keys.PublicKeys, error) {
	args := m.Called(ctx, entityURN)
	// Handle nil return for error cases
	if args.Get(0) == nil {
		return keys.PublicKeys{}, args.Error(1)
	}
	return args.Get(0).(keys.PublicKeys), args.Error(1)
}

// newTestLogger creates a discard logger for tests.
func newTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// --- V1 Tests (Complete) ---

func TestStoreKeyHandler_V1(t *testing.T) {
	logger := newTestLogger() // CHANGED
	authedUserID := "authed-user-123"
	userURN, err := urn.New(urn.SecureMessaging, "user", authedUserID)
	require.NoError(t, err)

	t.Run("Success - 201 Created", func(t *testing.T) {
		// Arrange
		mockStore := new(MockStore)
		keyPayload := []byte("my-public-key-blob")
		mockStore.On("StoreKey", mock.Anything, userURN, keyPayload).Return(nil)

		apiHandler := &api.API{Store: mockStore, Logger: logger} // CHANGED
		req := httptest.NewRequest(http.MethodPost, "/keys/"+userURN.String(), bytes.NewBuffer(keyPayload))
		req.SetPathValue("entityURN", userURN.String())
		// Inject the authenticated user ID into the context
		ctx := api.ContextWithUserID(context.Background(), authedUserID)
		rr := httptest.NewRecorder()

		// Act
		apiHandler.StoreKeyHandler(rr, req.WithContext(ctx))

		// Assert
		assert.Equal(t, http.StatusCreated, rr.Code)
		mockStore.AssertExpectations(t)
	})

	t.Run("Failure - 401 Unauthorized (No Context)", func(t *testing.T) {
		// Arrange
		mockStore := new(MockStore)
		apiHandler := &api.API{Store: mockStore, Logger: logger} // CHANGED
		req := httptest.NewRequest(http.MethodPost, "/keys/"+userURN.String(), bytes.NewBufferString("key"))
		req.SetPathValue("entityURN", userURN.String())
		rr := httptest.NewRecorder()

		// Act
		apiHandler.StoreKeyHandler(rr, req) // No context

		// Assert
		assert.Equal(t, http.StatusUnauthorized, rr.Code)
		mockStore.AssertNotCalled(t, "StoreKey")
	})

	t.Run("Failure - 403 Forbidden (Mismatch User)", func(t *testing.T) {
		// Arrange
		mockStore := new(MockStore)
		apiHandler := &api.API{Store: mockStore, Logger: logger} // CHANGED
		req := httptest.NewRequest(http.MethodPost, "/keys/"+userURN.String(), bytes.NewBufferString("key"))
		req.SetPathValue("entityURN", userURN.String())
		// Inject a *different* user ID into the context
		ctx := api.ContextWithUserID(context.Background(), "some-other-user")
		rr := httptest.NewRecorder()

		// Act
		apiHandler.StoreKeyHandler(rr, req.WithContext(ctx))

		// Assert
		assert.Equal(t, http.StatusForbidden, rr.Code)
		mockStore.AssertNotCalled(t, "StoreKey")
	})

	t.Run("Failure - 400 Bad URN", func(t *testing.T) {
		// Arrange
		mockStore := new(MockStore)
		apiHandler := &api.API{Store: mockStore, Logger: logger} // CHANGED
		// URN in path is invalid
		req := httptest.NewRequest(http.MethodPost, "/keys/urn:sm:user", bytes.NewBufferString("key"))
		req.SetPathValue("entityURN", "urn:sm:user")
		ctx := api.ContextWithUserID(context.Background(), authedUserID)
		rr := httptest.NewRecorder()

		// Act
		apiHandler.StoreKeyHandler(rr, req.WithContext(ctx))

		// Assert
		assert.Equal(t, http.StatusBadRequest, rr.Code)
		mockStore.AssertNotCalled(t, "StoreKey")
	})
}

func TestGetKeyHandler_V1(t *testing.T) {
	logger := newTestLogger() // CHANGED
	testURN, err := urn.New(urn.SecureMessaging, "user", "user-123")
	require.NoError(t, err)

	t.Run("Success - 200 OK", func(t *testing.T) {
		// Arrange
		mockKey := []byte("the-retrieved-key")
		mockStore := new(MockStore)
		mockStore.On("GetKey", mock.Anything, testURN).Return(mockKey, nil)

		apiHandler := &api.API{Store: mockStore, Logger: logger} // CHANGED
		req := httptest.NewRequest(http.MethodGet, "/keys/"+testURN.String(), nil)
		req.SetPathValue("entityURN", testURN.String())
		rr := httptest.NewRecorder()

		// Act
		apiHandler.GetKeyHandler(rr, req)

		// Assert
		assert.Equal(t, http.StatusOK, rr.Code)
		assert.Equal(t, mockKey, rr.Body.Bytes())
		assert.Equal(t, "application/octet-stream", rr.Header().Get("Content-Type"))
		mockStore.AssertExpectations(t)
	})

	t.Run("Failure - 404 Not Found", func(t *testing.T) {
		// Arrange
		notFoundURN, err := urn.New(urn.SecureMessaging, "user", "not-found")
		require.NoError(t, err)
		mockStore := new(MockStore)
		mockStore.On("GetKey", mock.Anything, notFoundURN).Return(nil, errors.New("not found"))

		apiHandler := &api.API{Store: mockStore, Logger: logger} // CHANGED
		req := httptest.NewRequest(http.MethodGet, "/keys/"+notFoundURN.String(), nil)
		req.SetPathValue("entityURN", notFoundURN.String())
		rr := httptest.NewRecorder()

		// Act
		apiHandler.GetKeyHandler(rr, req)

		// Assert
		assert.Equal(t, http.StatusNotFound, rr.Code)
		var errResp response.APIError
		err = json.Unmarshal(rr.Body.Bytes(), &errResp)
		require.NoError(t, err)
		assert.Equal(t, "Key not found", errResp.Error)
		mockStore.AssertExpectations(t)
	})
}

// --- V2 Tests (NEW) ---

func TestStorePublicKeysHandler_V2(t *testing.T) {
	logger := newTestLogger() // CHANGED
	authedUserID := "authed-v2-user"
	userURN, err := urn.New(urn.SecureMessaging, "user", authedUserID)
	require.NoError(t, err)

	// This is the native Go struct
	mockKeys := keys.PublicKeys{
		EncKey: []byte{1, 2, 3},
		SigKey: []byte{4, 5, 6},
	}

	// This is the JSON our client will send
	// (Our custom MarshalJSON will create this from a native struct)
	mockBodyJSON := `{"encKey":"AQID","sigKey":"BAUG"}`

	t.Run("Success - 201 Created", func(t *testing.T) {
		// Arrange
		mockStore := new(MockStore)
		// We assert that the store is called with the *native* Go struct
		mockStore.On("StorePublicKeys", mock.Anything, userURN, mockKeys).Return(nil)

		apiHandler := &api.API{Store: mockStore, Logger: logger} // CHANGED
		req := httptest.NewRequest(http.MethodPost, "/api/v2/keys/"+userURN.String(), strings.NewReader(mockBodyJSON))
		req.SetPathValue("entityURN", userURN.String())
		// Inject the authenticated user ID into the context
		ctx := api.ContextWithUserID(context.Background(), authedUserID)
		rr := httptest.NewRecorder()

		// Act
		apiHandler.StorePublicKeysHandler(rr, req.WithContext(ctx))

		// Assert
		assert.Equal(t, http.StatusCreated, rr.Code)
		mockStore.AssertExpectations(t)
	})

	t.Run("Failure - 401 Unauthorized (No Context)", func(t *testing.T) {
		// Arrange
		mockStore := new(MockStore)                              // No calls expected
		apiHandler := &api.API{Store: mockStore, Logger: logger} // CHANGED
		req := httptest.NewRequest(http.MethodPost, "/api/v2/keys/"+userURN.String(), strings.NewReader(mockBodyJSON))
		req.SetPathValue("entityURN", userURN.String())
		rr := httptest.NewRecorder()

		// Act
		apiHandler.StorePublicKeysHandler(rr, req) // No context

		// Assert
		assert.Equal(t, http.StatusUnauthorized, rr.Code)
		mockStore.AssertNotCalled(t, "StorePublicKeys")
	})

	t.Run("Failure - 403 Forbidden (Mismatch User)", func(t *testing.T) {
		// Arrange
		mockStore := new(MockStore)                              // No calls expected
		apiHandler := &api.API{Store: mockStore, Logger: logger} // CHANGED
		req := httptest.NewRequest(http.MethodPost, "/api/v2/keys/"+userURN.String(), strings.NewReader(mockBodyJSON))
		req.SetPathValue("entityURN", userURN.String())
		// Inject a *different* user ID into the context
		ctx := api.ContextWithUserID(context.Background(), "some-other-user")
		rr := httptest.NewRecorder()

		// Act
		apiHandler.StorePublicKeysHandler(rr, req.WithContext(ctx))

		// Assert
		assert.Equal(t, http.StatusForbidden, rr.Code)
		mockStore.AssertNotCalled(t, "StorePublicKeys")
	})

	t.Run("Failure - 400 Bad JSON", func(t *testing.T) {
		// Arrange
		mockStore := new(MockStore)                              // No calls expected
		apiHandler := &api.API{Store: mockStore, Logger: logger} // CHANGED
		req := httptest.NewRequest(http.MethodPost, "/api/v2/keys/"+userURN.String(), strings.NewReader(`{"bad-json`))
		req.SetPathValue("entityURN", userURN.String())
		ctx := api.ContextWithUserID(context.Background(), authedUserID)
		rr := httptest.NewRecorder()

		// Act
		apiHandler.StorePublicKeysHandler(rr, req.WithContext(ctx))

		// Assert
		assert.Equal(t, http.StatusBadRequest, rr.Code)
		mockStore.AssertNotCalled(t, "StorePublicKeys")
	})

	t.Run("Failure - 400 Missing Keys", func(t *testing.T) {
		// Arrange
		mockStore := new(MockStore)                              // No calls expected
		apiHandler := &api.API{Store: mockStore, Logger: logger} // CHANGED
		// Valid JSON, but sigKey is missing
		req := httptest.NewRequest(http.MethodPost, "/api/v2/keys/"+userURN.String(), strings.NewReader(`{"encKey":"AQID"}`))
		req.SetPathValue("entityURN", userURN.String())
		ctx := api.ContextWithUserID(context.Background(), authedUserID)
		rr := httptest.NewRecorder()

		// Act
		apiHandler.StorePublicKeysHandler(rr, req.WithContext(ctx))

		// Assert
		assert.Equal(t, http.StatusBadRequest, rr.Code)
		assert.Contains(t, rr.Body.String(), "encKey and sigKey must not be empty")
		mockStore.AssertNotCalled(t, "StorePublicKeys")
	})
}

func TestGetPublicKeysHandler_V2(t *testing.T) {
	logger := newTestLogger() // CHANGED
	userURN, err := urn.New(urn.SecureMessaging, "user", "test-user-v2")
	require.NoError(t, err)

	// This is the native Go struct we'll return from the mock store
	mockKeys := keys.PublicKeys{
		EncKey: []byte{1, 2, 3},
		SigKey: []byte{4, 5, 6},
	}

	// This is the JSON we expect our handler to produce
	// This MUST be camelCase, which our facade fix ensures.
	expectedJSON := `{"encKey":"AQID","sigKey":"BAUG"}`

	t.Run("Success - 200 OK", func(t *testing.T) {
		// Arrange
		mockStore := new(MockStore)
		mockStore.On("GetPublicKeys", mock.Anything, userURN).Return(mockKeys, nil)

		apiHandler := &api.API{Store: mockStore, Logger: logger} // CHANGED
		req := httptest.NewRequest(http.MethodGet, "/api/v2/keys/"+userURN.String(), nil)
		req.SetPathValue("entityURN", userURN.String())
		rr := httptest.NewRecorder()

		// Act
		apiHandler.GetPublicKeysHandler(rr, req)

		// Assert
		assert.Equal(t, http.StatusOK, rr.Code)
		// This is the assertion that was failing
		assert.JSONEq(t, expectedJSON, rr.Body.String())
		assert.Equal(t, "application/json", rr.Header().Get("Content-Type"))
		mockStore.AssertExpectations(t)
	})

	t.Run("Failure - 404 Not Found", func(t *testing.T) {
		// Arrange
		mockStore := new(MockStore)
		// We must return the zero-value for keys.PublicKeys
		mockStore.On("GetPublicKeys", mock.Anything, userURN).Return(keys.PublicKeys{}, errors.New("not found"))

		apiHandler := &api.API{Store: mockStore, Logger: logger} // CHANGED
		req := httptest.NewRequest(http.MethodGet, "/api/v2/keys/"+userURN.String(), nil)
		req.SetPathValue("entityURN", userURN.String())
		rr := httptest.NewRecorder()

		// Act
		apiHandler.GetPublicKeysHandler(rr, req)

		// Assert
		assert.Equal(t, http.StatusNotFound, rr.Code)
		var errResp response.APIError
		err = json.Unmarshal(rr.Body.Bytes(), &errResp)
		require.NoError(t, err)
		assert.Equal(t, "Key not found", errResp.Error)
		mockStore.AssertExpectations(t)
	})
}
