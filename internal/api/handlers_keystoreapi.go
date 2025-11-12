// --- File: internal/api/handlers_keystoreapi.go ---
package api

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/tinywideclouds/go-key-service/pkg/keystore"
	"github.com/tinywideclouds/go-microservice-base/pkg/middleware"
	"github.com/tinywideclouds/go-microservice-base/pkg/response"

	"github.com/tinywideclouds/go-platform/pkg/keys/v1"
	urn "github.com/tinywideclouds/go-platform/pkg/net/v1"
)

// API holds the dependencies for the key service HTTP handlers,
// such as the data store and logger.
type API struct {
	Store     keystore.Store
	Logger    *slog.Logger
	JWTSecret string
}

// StoreKeysHandler handles the POST /keys/{entityURN} request.
// It validates the authenticated user, parses the request body,
// and persists the public keys to the store.
func (a *API) StoreKeysHandler(w http.ResponseWriter, r *http.Request) {
	// 1. Auth: Get the authenticated user's ID from the JWT context.
	authedUserID, ok := middleware.GetUserIDFromContext(r.Context())
	if !ok {
		a.Logger.Debug("StoreKeys: Failed. No user ID in token context.")
		response.WriteJSONError(w, http.StatusUnauthorized, "Unauthorized: No user ID in token")
		return
	}

	// 2. Path: Get the URN from the path.
	entityURNStr := r.PathValue("entityURN")
	entityURN, err := urn.Parse(entityURNStr)
	if err != nil {
		a.Logger.Warn("StoreKeys: Invalid URN format", "err", err, "raw_urn", entityURNStr)
		response.WriteJSONError(w, http.StatusBadRequest, "Invalid URN format")
		return
	}

	logger := a.Logger.With("entity_urn", entityURN.String())

	// 3. Authz: User can only store their own key.
	// --- FIX: Compare the authenticated ID with the URN's ID, not the full URN string. ---
	if entityURN.EntityID() != authedUserID {
		logger.Warn("StoreKeys: Forbidden. User tried to store key for another entity",
			"authed_user", authedUserID,
			"target_entity_id", entityURN.EntityID())
		response.WriteJSONError(w, http.StatusForbidden, "Forbidden: You can only store your own key")
		return
	}

	// 4. Body: Decode directly into our native struct.
	var keysToStore keys.PublicKeys
	if err := json.NewDecoder(r.Body).Decode(&keysToStore); err != nil {
		logger.Warn("StoreKeys: Failed to unmarshal JSON body", "err", err)
		response.WriteJSONError(w, http.StatusBadRequest, "Invalid JSON body format")
		return
	}

	// 5. Validate that we actually have keys
	if len(keysToStore.EncKey) == 0 || len(keysToStore.SigKey) == 0 {
		logger.Warn("StoreKeys: Store request missing encKey or sigKey")
		response.WriteJSONError(w, http.StatusBadRequest, "encKey and sigKey must not be empty")
		return
	}

	// 6. Store: Use the store method
	if err := a.Store.StorePublicKeys(r.Context(), entityURN, keysToStore); err != nil {
		logger.Error("StoreKeys: Failed to store public keys", "err", err)
		response.WriteJSONError(w, http.StatusInternalServerError, "Failed to store public keys")
		return
	}

	w.WriteHeader(http.StatusCreated)
	logger.Info("StoreKeys: Successfully stored public keys")
}

// GetKeysHandler handles the GET /keys/{entityURN} request.
// It retrieves the public keys for a given entity and returns them as JSON.
func (a *API) GetKeysHandler(w http.ResponseWriter, r *http.Request) {
	// 1. Path: Get the URN from the path.
	entityURNStr := r.PathValue("entityURN")
	entityURN, err := urn.Parse(entityURNStr)
	if err != nil {
		a.Logger.Warn("GetKeys: Invalid URN format", "err", err, "raw_urn", entityURNStr)
		response.WriteJSONError(w, http.StatusBadRequest, "Invalid URN format")
		return
	}

	logger := a.Logger.With("entity_urn", entityURN.String())

	// 2. Store: Use the store method to retrieve the Go struct
	retrievedKeys, err := a.Store.GetPublicKeys(r.Context(), entityURN)
	if err != nil {
		logger.Warn("GetKeys: Key not found", "err", err)
		response.WriteJSONError(w, http.StatusNotFound, "Key not found")
		return
	}

	// 3. Respond: Encode the native struct directly using standard json.
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(retrievedKeys); err != nil {
		logger.Error("GetKeys: Failed to marshal keys to JSON", "err", err)
		http.Error(w, "Failed to serialize response", http.StatusInternalServerError)
		return
	}

	logger.Info("GetKeys: Successfully retrieved public keys")
}
