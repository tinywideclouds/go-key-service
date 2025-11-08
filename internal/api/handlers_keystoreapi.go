package api

import (
	"encoding/json" // <-- Use standard JSON library
	"io"
	"log/slog" // IMPORTED
	"net/http"

	// "github.com/rs/zerolog" // REMOVED
	"github.com/tinywideclouds/go-key-service/pkg/keyservice"
	"github.com/tinywideclouds/go-microservice-base/pkg/middleware"
	"github.com/tinywideclouds/go-microservice-base/pkg/response"

	// --- V2 Imports ---
	// We no longer need the 'keysv1' (Pb) or 'protojson' imports here
	"github.com/tinywideclouds/go-platform/pkg/keys/v1"
	urn "github.com/tinywideclouds/go-platform/pkg/net/v1"
)

// API now includes the JWTSecret for the middleware.
type API struct {
	Store     keyservice.Store
	Logger    *slog.Logger // CHANGED
	JWTSecret string
}

// --- V1 API Handlers (Unchanged) ---

// StoreKeyHandler manages the POST requests for entity keys (V1).
func (a *API) StoreKeyHandler(w http.ResponseWriter, r *http.Request) {
	// 1. Get the authenticated user's ID securely from the JWT context.
	authedUserID, ok := middleware.GetUserIDFromContext(r.Context())
	if !ok {
		a.Logger.Debug("V1 StoreKey: Failed. No user ID in token context.") // ADDED
		response.WriteJSONError(w, http.StatusUnauthorized, "Unauthorized: No user ID in token")
		return
	}

	// 2. Get the URN from the path.
	entityURNStr := r.PathValue("entityURN")
	entityURN, err := urn.Parse(entityURNStr)
	if err != nil {
		a.Logger.Warn("V1 StoreKey: Invalid URN format", "err", err, "raw_urn", entityURNStr) // CHANGED
		response.WriteJSONError(w, http.StatusBadRequest, "Invalid URN format")
		return
	}

	entityString := entityURN.String()

	logger := a.Logger.With("entity_urn", entityString) // CHANGED

	// 3. Enforce: User can only store their own key.
	if entityString != authedUserID {
		logger.Warn("V1 StoreKey: Forbidden. User tried to store key for another entity", "authed_user", authedUserID, "entityURN", entityString) // CHANGED
		response.WriteJSONError(w, http.StatusForbidden, "Forbidden: You can only store your own key")
		return
	}

	// 4. Read the raw key blob from the request body.
	key, err := io.ReadAll(r.Body)
	if err != nil {
		logger.Error("V1 StoreKey: Failed to read request body", "err", err) // CHANGED
		response.WriteJSONError(w, http.StatusInternalServerError, "Failed to read request body")
		return
	}
	if len(key) == 0 {
		logger.Debug("V1 StoreKey: Failed. Request body was empty.") // ADDED
		response.WriteJSONError(w, http.StatusBadRequest, "Request body must not be empty")
		return
	}
	logger.Info("[Checkpoint 2: RECEIPT] Key received from client", "byteLength", len(key)) // CHANGED

	if err := a.Store.StoreKey(r.Context(), entityURN, key); err != nil {
		logger.Error("V1 StoreKey: Failed to store key", "err", err) // CHANGED
		response.WriteJSONError(w, http.StatusInternalServerError, "Failed to store key")
		return
	}
	w.WriteHeader(http.StatusCreated)
	logger.Info("V1 StoreKey: Successfully stored public key") // CHANGED
}

// GetKeyHandler remains public as clients need to fetch others' public keys (V1).
func (a *API) GetKeyHandler(w http.ResponseWriter, r *http.Request) {
	entityURNStr := r.PathValue("entityURN")
	entityURN, err := urn.Parse(entityURNStr)
	if err != nil {
		a.Logger.Warn("V1 GetKey: Invalid URN format", "err", err, "raw_urn", entityURNStr) // CHANGED
		response.WriteJSONError(w, http.StatusBadRequest, "Invalid URN format")
		return
	}

	logger := a.Logger.With("entity_urn", entityURN.String()) // CHANGED
	key, err := a.Store.GetKey(r.Context(), entityURN)
	if err != nil {
		logger.Warn("V1 GetKey: Key not found", "err", err) // CHANGED
		response.WriteJSONError(w, http.StatusNotFound, "Key not found")
		return
	}

	logger.Info("[Checkpoint 3: RETRIEVAL] Key retrieved from store", "byteLength", len(key)) // CHANGED
	w.Header().Set("Content-Type", "application/octet-stream")
	_, _ = w.Write(key)
}

// --- NEW V2 API Handlers (Simplified) ---

// StorePublicKeysHandler manages the POST requests for V2 PublicKeys.
func (a *API) StorePublicKeysHandler(w http.ResponseWriter, r *http.Request) {
	// 1. Auth: Get the authenticated user's ID from the JWT context.
	authedUserID, ok := middleware.GetUserIDFromContext(r.Context())
	if !ok {
		a.Logger.Debug("V2 StoreKeys: Failed. No user ID in token context.") // ADDED
		response.WriteJSONError(w, http.StatusUnauthorized, "Unauthorized: No user ID in token")
		return
	}

	// 2. Path: Get the URN from the path.
	entityURNStr := r.PathValue("entityURN")
	entityURN, err := urn.Parse(entityURNStr)
	if err != nil {
		a.Logger.Warn("V2 StoreKeys: Invalid URN format", "err", err, "raw_urn", entityURNStr) // CHANGED
		response.WriteJSONError(w, http.StatusBadRequest, "Invalid URN format")
		return
	}

	entityString := entityURN.String()
	logger := a.Logger.With("entity_urn", entityString) // CHANGED

	// 3. Authz: User can only store their own key.
	if entityString != authedUserID {
		logger.Warn("V2 StoreKeys: Forbidden. User tried to store key for another entity", "authed_user", authedUserID, "entity_urn", entityString) // CHANGED
		response.WriteJSONError(w, http.StatusForbidden, "Forbidden: You can only store your own key")
		return
	}

	// 4. Body: Decode directly into our native struct using standard json.
	// Our custom UnmarshalJSON() method on keys.PublicKeys will be called.
	var keysToStore keys.PublicKeys
	if err := json.NewDecoder(r.Body).Decode(&keysToStore); err != nil {
		logger.Warn("V2 StoreKeys: Failed to unmarshal JSON body", "err", err) // CHANGED
		response.WriteJSONError(w, http.StatusBadRequest, "Invalid JSON body format")
		return
	}

	// 5. Validate that we actually have keys
	if len(keysToStore.EncKey) == 0 || len(keysToStore.SigKey) == 0 {
		logger.Warn("V2 StoreKeys: Store request missing encKey or sigKey") // CHANGED
		response.WriteJSONError(w, http.StatusBadRequest, "encKey and sigKey must not be empty")
		return
	}

	// 6. Store: Use the new V2 store method
	if err := a.Store.StorePublicKeys(r.Context(), entityURN, keysToStore); err != nil {
		logger.Error("V2 StoreKeys: Failed to store public keys", "err", err) // CHANGED
		response.WriteJSONError(w, http.StatusInternalServerError, "Failed to store public keys")
		return
	}

	w.WriteHeader(http.StatusCreated)
	logger.Info("V2 StoreKeys: Successfully stored public keys") // CHANGED
}

// GetPublicKeysHandler manages the GET requests for V2 PublicKeys.
func (a *API) GetPublicKeysHandler(w http.ResponseWriter, r *http.Request) {
	// 1. Path: Get the URN from the path.
	entityURNStr := r.PathValue("entityURN")
	entityURN, err := urn.Parse(entityURNStr)
	if err != nil {
		a.Logger.Warn("V2 GetKeys: Invalid URN format", "err", err, "raw_urn", entityURNStr) // CHANGED
		response.WriteJSONError(w, http.StatusBadRequest, "Invalid URN format")
		return
	}

	logger := a.Logger.With("entity_urn", entityURN.String()) // CHANGED

	// 2. Store: Use the V2 store method to retrieve the Go struct
	retrievedKeys, err := a.Store.GetPublicKeys(r.Context(), entityURN)
	if err != nil {
		logger.Warn("V2 GetKeys: Key not found", "err", err) // CHANGED
		response.WriteJSONError(w, http.StatusNotFound, "Key not found")
		return
	}

	// 3. Respond: Encode the native struct directly using standard json.
	// Our custom MarshalJSON() method on keys.PublicKeys will be called,
	// which uses protojson to correctly handle base64 encoding.
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(retrievedKeys); err != nil {
		// This error is for the *developer*, not the user.
		logger.Error("V2 GetKeys: Failed to marshal keys to JSON", "err", err) // CHANGED
		// Don't use WriteJSONError, as the response may be half-written
		http.Error(w, "Failed to serialize response", http.StatusInternalServerError)
		return
	}

	logger.Info("V2 GetKeys: Successfully retrieved public keys") // CHANGED
}
