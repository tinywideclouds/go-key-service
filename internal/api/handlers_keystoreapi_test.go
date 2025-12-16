package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/tinywideclouds/go-key-service/internal/api"
	"github.com/tinywideclouds/go-key-service/pkg/keystore"
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
		req := httptest.NewRequest(http.MethodPost, "/keys/"+identityURN, bytes.NewBuffer(bodyBytes))
		ctx := middleware.ContextWithUser(req.Context(), identityURN, lookupURN, "")
		req = req.WithContext(ctx)
		req.SetPathValue("entityURN", identityURN)

		w := httptest.NewRecorder()

		targetObj, _ := urn.Parse(identityURN)
		mockStore.On("StorePublicKeys", mock.Anything, targetObj, validBody).Return(nil).Once()

		handler.StoreKeysHandler(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)
		mockStore.AssertExpectations(t)
	})

	t.Run("Allow write to Lookup URN (The 'Handle' Feature)", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/keys/"+lookupURN, bytes.NewBuffer(bodyBytes))
		ctx := middleware.ContextWithUser(req.Context(), identityURN, lookupURN, "")
		req = req.WithContext(ctx)
		req.SetPathValue("entityURN", lookupURN)

		w := httptest.NewRecorder()

		targetObj, _ := urn.Parse(lookupURN)
		mockStore.On("StorePublicKeys", mock.Anything, targetObj, validBody).Return(nil).Once()

		handler.StoreKeysHandler(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)
		mockStore.AssertExpectations(t)
	})

	t.Run("Forbid write to Unmatched URN", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/keys/"+otherURN, bytes.NewBuffer(bodyBytes))
		ctx := middleware.ContextWithUser(req.Context(), identityURN, lookupURN, "")
		req = req.WithContext(ctx)
		req.SetPathValue("entityURN", otherURN)

		w := httptest.NewRecorder()

		handler.StoreKeysHandler(w, req)

		assert.Equal(t, http.StatusForbidden, w.Code)
		mockStore.AssertNotCalled(t, "StorePublicKeys")
	})
}

// ✅ NEW: Test Suite for the Regression Fix
func TestGetKeysHandler(t *testing.T) {
	// Fixtures
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	mockStore := new(MockStore)
	handler := &api.API{
		Store:  mockStore,
		Logger: logger,
	}

	validURN := "urn:auth:google:user-123"
	urnObj, _ := urn.Parse(validURN)

	validKeys := keys.PublicKeys{EncKey: []byte("enc"), SigKey: []byte("sig")}

	t.Run("Returns 200 OK with keys when found", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/keys/"+validURN, nil)
		req.SetPathValue("entityURN", validURN)
		w := httptest.NewRecorder()

		mockStore.On("GetPublicKeys", mock.Anything, urnObj).Return(validKeys, nil).Once()

		handler.GetKeysHandler(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		// Optional: Check body content
		var respKeys keys.PublicKeys
		_ = json.NewDecoder(w.Body).Decode(&respKeys)
		assert.Equal(t, validKeys, respKeys)

		mockStore.AssertExpectations(t)
	})

	t.Run("Returns 404 Not Found when store returns ErrNotFound", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/keys/"+validURN, nil)
		req.SetPathValue("entityURN", validURN)
		w := httptest.NewRecorder()

		// ✅ VERIFY: Sentinel Error mapping
		mockStore.On("GetPublicKeys", mock.Anything, urnObj).Return(keys.PublicKeys{}, keystore.ErrNotFound).Once()

		handler.GetKeysHandler(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
		mockStore.AssertExpectations(t)
	})

	t.Run("Returns 500 Internal Server Error when store fails generically", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/keys/"+validURN, nil)
		req.SetPathValue("entityURN", validURN)
		w := httptest.NewRecorder()

		// ✅ VERIFY: Generic Error mapping (The Startup Regression Fix)
		// We simulate a DB connection error here
		mockStore.On("GetPublicKeys", mock.Anything, urnObj).Return(keys.PublicKeys{}, errors.New("connection refused")).Once()

		handler.GetKeysHandler(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
		mockStore.AssertExpectations(t)
	})
}
