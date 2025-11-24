package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/tinywideclouds/go-key-service/internal/api"
	"github.com/tinywideclouds/go-microservice-base/pkg/middleware"
	"github.com/tinywideclouds/go-platform/pkg/keys/v1"
	urn "github.com/tinywideclouds/go-platform/pkg/net/v1"
)

// --- Mock Store ---
type MockStore struct {
	mock.Mock
}

func (m *MockStore) StorePublicKeys(ctx context.Context, u urn.URN, k keys.PublicKeys) error {
	args := m.Called(ctx, u, k)
	return args.Error(0)
}

func (m *MockStore) GetPublicKeys(ctx context.Context, u urn.URN) (keys.PublicKeys, error) {
	args := m.Called(ctx, u)
	return args.Get(0).(keys.PublicKeys), args.Error(1)
}

// --- Tests ---

func TestStoreKeysHandler(t *testing.T) {
	// Fixtures
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	mockStore := new(MockStore)
	handler := &api.API{
		Store:  mockStore,
		Logger: logger,
	}

	identityURN := "urn:auth:google:user-123"
	lookupURN := "urn:lookup:email:bob@test.com"
	otherURN := "urn:auth:apple:stranger-999"

	validBody := keys.PublicKeys{
		EncKey: []byte("enc-key"),
		SigKey: []byte("sig-key"),
	}
	bodyBytes, _ := json.Marshal(validBody)

	t.Run("Allow write to Identity URN (Standard)", func(t *testing.T) {
		// Setup: User is logged in as 'identityURN', has handle 'lookupURN'
		// Target: 'identityURN'
		req := httptest.NewRequest(http.MethodPost, "/keys/"+identityURN, bytes.NewBuffer(bodyBytes))
		ctx := middleware.ContextWithUser(req.Context(), identityURN, lookupURN, "")
		req = req.WithContext(ctx)
		// Add PathValue (Go 1.22 feature)
		req.SetPathValue("entityURN", identityURN)

		w := httptest.NewRecorder()

		// Expectation
		targetObj, _ := urn.Parse(identityURN)
		mockStore.On("StorePublicKeys", mock.Anything, targetObj, validBody).Return(nil).Once()

		// Act
		handler.StoreKeysHandler(w, req)

		// Assert
		assert.Equal(t, http.StatusCreated, w.Code)
		mockStore.AssertExpectations(t)
	})

	t.Run("Allow write to Lookup URN (The 'Handle' Feature)", func(t *testing.T) {
		// Setup: User is logged in as 'identityURN', has handle 'lookupURN'
		// Target: 'lookupURN' (Attempting to claim their public address)
		req := httptest.NewRequest(http.MethodPost, "/keys/"+lookupURN, bytes.NewBuffer(bodyBytes))
		ctx := middleware.ContextWithUser(req.Context(), identityURN, lookupURN, "")
		req = req.WithContext(ctx)
		req.SetPathValue("entityURN", lookupURN)

		w := httptest.NewRecorder()

		// Expectation
		targetObj, _ := urn.Parse(lookupURN)
		mockStore.On("StorePublicKeys", mock.Anything, targetObj, validBody).Return(nil).Once()

		// Act
		handler.StoreKeysHandler(w, req)

		// Assert
		assert.Equal(t, http.StatusCreated, w.Code)
		mockStore.AssertExpectations(t)
	})

	t.Run("Forbid write to Unmatched URN", func(t *testing.T) {
		// Setup: User is 'identityURN'
		// Target: 'otherURN' (Stranger)
		req := httptest.NewRequest(http.MethodPost, "/keys/"+otherURN, bytes.NewBuffer(bodyBytes))
		ctx := middleware.ContextWithUser(req.Context(), identityURN, lookupURN, "")
		req = req.WithContext(ctx)
		req.SetPathValue("entityURN", otherURN)

		w := httptest.NewRecorder()

		// Act
		handler.StoreKeysHandler(w, req)

		// Assert
		assert.Equal(t, http.StatusForbidden, w.Code)
		mockStore.AssertNotCalled(t, "StorePublicKeys")
	})
}
