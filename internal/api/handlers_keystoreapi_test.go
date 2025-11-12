// --- File: internal/api/handlers_keystoreapi_test.go ---
package api_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/tinywideclouds/go-key-service/internal/api"
	"github.com/tinywideclouds/go-microservice-base/pkg/middleware"
	"github.com/tinywideclouds/go-microservice-base/pkg/response"

	"github.com/tinywideclouds/go-platform/pkg/keys/v1"
	urn "github.com/tinywideclouds/go-platform/pkg/net/v1"
)

// MockStore is a mock implementation of the keyservice.Store interface.
type MockStore struct {
	mock.Mock
}

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

func TestStoreKeysHandler(t *testing.T) {
	logger := newTestLogger()
	authedUserID := "authorized-user"
	userURN, err := urn.New(urn.SecureMessaging, "user", authedUserID)
	require.NoError(t, err)

	// This is the native Go struct
	mockKeys := keys.PublicKeys{
		EncKey: []byte{1, 2, 3},
		SigKey: []byte{4, 5, 6},
	}

	// This is the JSON our client will send
	mockBodyJSON := `{"encKey":"AQID","sigKey":"BAUG"}`

	t.Run("Success - 201 Created", func(t *testing.T) {
		// Arrange
		mockStore := new(MockStore)
		// We assert that the store is called with the *native* Go struct
		mockStore.On("StorePublicKeys", mock.Anything, userURN, mockKeys).Return(nil)

		apiHandler := &api.API{Store: mockStore, Logger: logger}
		req := httptest.NewRequest(http.MethodPost, "/keys/"+userURN.String(), strings.NewReader(mockBodyJSON))
		req.SetPathValue("entityURN", userURN.String())
		// Inject the authenticated user ID into the context
		ctx := middleware.ContextWithUserID(context.Background(), authedUserID)
		rr := httptest.NewRecorder()

		// Act
		apiHandler.StoreKeysHandler(rr, req.WithContext(ctx))

		// Assert
		assert.Equal(t, http.StatusCreated, rr.Code)
		mockStore.AssertExpectations(t)
	})

	t.Run("Failure - 401 Unauthorized (No Context)", func(t *testing.T) {
		// Arrange
		mockStore := new(MockStore) // No calls expected
		apiHandler := &api.API{Store: mockStore, Logger: logger}
		req := httptest.NewRequest(http.MethodPost, "/keys/"+userURN.String(), strings.NewReader(mockBodyJSON))
		req.SetPathValue("entityURN", userURN.String())
		rr := httptest.NewRecorder()

		// Act
		apiHandler.StoreKeysHandler(rr, req)

		// Assert
		assert.Equal(t, http.StatusUnauthorized, rr.Code)
		mockStore.AssertNotCalled(t, "StorePublicKeys")
	})

	t.Run("Failure - 403 Forbidden (Mismatch User)", func(t *testing.T) {
		// Arrange
		mockStore := new(MockStore) // No calls expected
		apiHandler := &api.API{Store: mockStore, Logger: logger}
		req := httptest.NewRequest(http.MethodPost, "/keys/"+userURN.String(), strings.NewReader(mockBodyJSON))
		req.SetPathValue("entityURN", userURN.String())
		// Inject a *different* user ID into the context
		ctx := middleware.ContextWithUserID(context.Background(), "some-other-user")
		rr := httptest.NewRecorder()

		// Act
		apiHandler.StoreKeysHandler(rr, req.WithContext(ctx))

		// Assert
		assert.Equal(t, http.StatusForbidden, rr.Code)
		mockStore.AssertNotCalled(t, "StorePublicKeys")
	})

	t.Run("Failure - 400 Bad JSON", func(t *testing.T) {
		mockStore := new(MockStore)
		apiHandler := &api.API{Store: mockStore, Logger: logger}
		req := httptest.NewRequest(http.MethodPost, "/keys/"+userURN.String(), strings.NewReader(`{"bad-json`))
		req.SetPathValue("entityURN", userURN.String())
		ctx := middleware.ContextWithUserID(context.Background(), authedUserID)
		rr := httptest.NewRecorder()

		// Act
		apiHandler.StoreKeysHandler(rr, req.WithContext(ctx))

		// Assert
		assert.Equal(t, http.StatusBadRequest, rr.Code)
		mockStore.AssertNotCalled(t, "StorePublicKeys")
	})

	t.Run("Failure - 400 Missing Keys", func(t *testing.T) {
		// Arrange
		mockStore := new(MockStore) // No calls expected
		apiHandler := &api.API{Store: mockStore, Logger: logger}
		// Valid JSON, but sigKey is missing
		req := httptest.NewRequest(http.MethodPost, "/keys/"+userURN.String(), strings.NewReader(`{"encKey":"AQID"}`))
		req.SetPathValue("entityURN", userURN.String())
		ctx := middleware.ContextWithUserID(context.Background(), authedUserID)
		rr := httptest.NewRecorder()

		// Act
		apiHandler.StoreKeysHandler(rr, req.WithContext(ctx))

		// Assert
		assert.Equal(t, http.StatusBadRequest, rr.Code)
		assert.Contains(t, rr.Body.String(), "encKey and sigKey must not be empty")
		mockStore.AssertNotCalled(t, "StorePublicKeys")
	})
}

func TestGetKeysHandler(t *testing.T) {
	logger := newTestLogger()
	userURN, err := urn.New(urn.SecureMessaging, "user", "test-user-v2")
	require.NoError(t, err)

	// This is the native Go struct we'll return from the mock store
	mockKeys := keys.PublicKeys{
		EncKey: []byte{1, 2, 3},
		SigKey: []byte{4, 5, 6},
	}

	// This is the JSON we expect our handler to produce
	expectedJSON := `{"encKey":"AQID","sigKey":"BAUG"}`

	t.Run("Success - 200 OK", func(t *testing.T) {
		// Arrange
		mockStore := new(MockStore)
		mockStore.On("GetPublicKeys", mock.Anything, userURN).Return(mockKeys, nil)

		apiHandler := &api.API{Store: mockStore, Logger: logger}
		req := httptest.NewRequest(http.MethodGet, "/keys/"+userURN.String(), nil)
		req.SetPathValue("entityURN", userURN.String())
		rr := httptest.NewRecorder()

		// Act
		apiHandler.GetKeysHandler(rr, req)

		// Assert
		assert.Equal(t, http.StatusOK, rr.Code)
		assert.JSONEq(t, expectedJSON, rr.Body.String())
		assert.Equal(t, "application/json", rr.Header().Get("Content-Type"))
		mockStore.AssertExpectations(t)
	})

	t.Run("Failure - 404 Not Found", func(t *testing.T) {
		// Arrange
		mockStore := new(MockStore)
		// We must return the zero-value for keys.PublicKeys
		mockStore.On("GetPublicKeys", mock.Anything, userURN).Return(keys.PublicKeys{}, errors.New("not found"))

		apiHandler := &api.API{Store: mockStore, Logger: logger}
		req := httptest.NewRequest(http.MethodGet, "/keys/"+userURN.String(), nil)
		req.SetPathValue("entityURN", userURN.String())
		rr := httptest.NewRecorder()

		// Act
		apiHandler.GetKeysHandler(rr, req)

		// Assert
		assert.Equal(t, http.StatusNotFound, rr.Code)
		var errResp response.APIError
		err = json.Unmarshal(rr.Body.Bytes(), &errResp)
		require.NoError(t, err)
		assert.Equal(t, "Key not found", errResp.Error)
		mockStore.AssertExpectations(t)
	})
}
