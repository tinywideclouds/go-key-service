package api

import (
	"context"
	"encoding/json" // <-- Use standard JSON library
	"io"
	"net/http"

	"github.com/illmade-knight/go-microservice-base/pkg/response"
	"github.com/rs/zerolog"
	"github.com/tinywideclouds/go-key-service/pkg/keyservice"

	// --- V2 Imports ---
	// We no longer need the 'keysv1' (Pb) or 'protojson' imports here
	"github.com/tinywideclouds/go-platform/pkg/keys/v1"
	"github.com/tinywideclouds/go-platform/pkg/net/v1"
)

// API now includes the JWTSecret for the middleware.
type API struct {
	Store     keyservice.Store
	Logger    zerolog.Logger
	JWTSecret string
}

type contextKey string

// UserContextKey is the key used to store the authenticated user's ID from the JWT.
const UserContextKey contextKey = "userID"

// GetUserIDFromContext safely retrieves the user ID from the request context.
func GetUserIDFromContext(ctx context.Context) (string, bool) {
	userID, ok := ctx.Value(UserContextKey).(string)
	return userID, ok
}

// ContextWithUserID is a helper function for tests to inject a user ID
// into a context, simulating a successful authentication from middleware.
func ContextWithUserID(ctx context.Context, userID string) context.Context {
	return context.WithValue(ctx, UserContextKey, userID)
}

// --- V1 API Handlers (Unchanged) ---

// StoreKeyHandler manages the POST requests for entity keys (V1).
func (a *API) StoreKeyHandler(w http.ResponseWriter, r *http.Request) {
	// 1. Get the authenticated user's ID securely from the JWT context.
	authedUserID, ok := GetUserIDFromContext(r.Context())
	if !ok {
		response.WriteJSONError(w, http.StatusUnauthorized, "Unauthorized: No user ID in token")
		return
	}

	// 2. Get the URN from the path.
	entityURNStr := r.PathValue("entityURN")
	entityURN, err := urn.Parse(entityURNStr)
	if err != nil {
		a.Logger.Warn().Err(err).Str("raw_urn", entityURNStr).Msg("Invalid URN format")
		response.WriteJSONError(w, http.StatusBadRequest, "Invalid URN format")
		return
	}

	logger := a.Logger.With().Str("entity_urn", entityURN.String()).Logger()

	// 3. Enforce: User can only store their own key.
	if entityURN.EntityID() != authedUserID {
		logger.Warn().Str("authed_user", authedUserID).Msg("Forbidden: User tried to store key for another entity")
		response.WriteJSONError(w, http.StatusForbidden, "Forbidden: You can only store your own key")
		return
	}

	// 4. Read the raw key blob from the request body.
	key, err := io.ReadAll(r.Body)
	if err != nil {
		logger.Error().Err(err).Msg("Failed to read request body")
		response.WriteJSONError(w, http.StatusInternalServerError, "Failed to read request body")
		return
	}
	if len(key) == 0 {
		response.WriteJSONError(w, http.StatusBadRequest, "Request body must not be empty")
		return
	}
	logger.Info().Int("byteLength", len(key)).Msg("[Checkpoint 2: RECEIPT] Key received from client")

	if err := a.Store.StoreKey(r.Context(), entityURN, key); err != nil {
		logger.Error().Err(err).Msg("Failed to store key")
		response.WriteJSONError(w, http.StatusInternalServerError, "Failed to store key")
		return
	}
	w.WriteHeader(http.StatusCreated)
	logger.Info().Msg("Successfully stored public key")
}

// GetKeyHandler remains public as clients need to fetch others' public keys (V1).
func (a *API) GetKeyHandler(w http.ResponseWriter, r *http.Request) {
	entityURNStr := r.PathValue("entityURN")
	entityURN, err := urn.Parse(entityURNStr)
	if err != nil {
		a.Logger.Warn().Err(err).Str("raw_urn", entityURNStr).Msg("Invalid URN format")
		response.WriteJSONError(w, http.StatusBadRequest, "Invalid URN format")
		return
	}

	logger := a.Logger.With().Str("entity_urn", entityURN.String()).Logger()
	key, err := a.Store.GetKey(r.Context(), entityURN)
	if err != nil {
		logger.Warn().Err(err).Msg("Key not found")
		response.WriteJSONError(w, http.StatusNotFound, "Key not found")
		return
	}

	logger.Info().Int("byteLength", len(key)).Msg("[Checkpoint 3: RETRIEVAL] Key retrieved from store")
	w.Header().Set("Content-Type", "application/octet-stream")
	_, _ = w.Write(key)
}

// --- NEW V2 API Handlers (Simplified) ---

// StorePublicKeysHandler manages the POST requests for V2 PublicKeys.
func (a *API) StorePublicKeysHandler(w http.ResponseWriter, r *http.Request) {
	// 1. Auth: Get the authenticated user's ID from the JWT context.
	authedUserID, ok := GetUserIDFromContext(r.Context())
	if !ok {
		response.WriteJSONError(w, http.StatusUnauthorized, "Unauthorized: No user ID in token")
		return
	}

	// 2. Path: Get the URN from the path.
	entityURNStr := r.PathValue("entityURN")
	entityURN, err := urn.Parse(entityURNStr)
	if err != nil {
		a.Logger.Warn().Err(err).Str("raw_urn", entityURNStr).Msg("V2: Invalid URN format")
		response.WriteJSONError(w, http.StatusBadRequest, "Invalid URN format")
		return
	}

	logger := a.Logger.With().Str("entity_urn", entityURN.String()).Logger()

	// 3. Authz: User can only store their own key.
	if entityURN.EntityID() != authedUserID {
		logger.Warn().Str("authed_user", authedUserID).Msg("V2 Forbidden: User tried to store key for another entity")
		response.WriteJSONError(w, http.StatusForbidden, "Forbidden: You can only store your own key")
		return
	}

	// 4. Body: Decode directly into our native struct using standard json.
	// Our custom UnmarshalJSON() method on keys.PublicKeys will be called.
	var keysToStore keys.PublicKeys
	if err := json.NewDecoder(r.Body).Decode(&keysToStore); err != nil {
		logger.Warn().Err(err).Msg("V2: Failed to unmarshal JSON body")
		response.WriteJSONError(w, http.StatusBadRequest, "Invalid JSON body format")
		return
	}

	// 5. Validate that we actually have keys
	if len(keysToStore.EncKey) == 0 || len(keysToStore.SigKey) == 0 {
		logger.Warn().Msg("V2: Store request missing encKey or sigKey")
		response.WriteJSONError(w, http.StatusBadRequest, "encKey and sigKey must not be empty")
		return
	}

	// 6. Store: Use the new V2 store method
	if err := a.Store.StorePublicKeys(r.Context(), entityURN, keysToStore); err != nil {
		logger.Error().Err(err).Msg("V2: Failed to store public keys")
		response.WriteJSONError(w, http.StatusInternalServerError, "Failed to store public keys")
		return
	}

	w.WriteHeader(http.StatusCreated)
	logger.Info().Msg("V2: Successfully stored public keys")
}

// GetPublicKeysHandler manages the GET requests for V2 PublicKeys.
func (a *API) GetPublicKeysHandler(w http.ResponseWriter, r *http.Request) {
	// 1. Path: Get the URN from the path.
	entityURNStr := r.PathValue("entityURN")
	entityURN, err := urn.Parse(entityURNStr)
	if err != nil {
		a.Logger.Warn().Err(err).Str("raw_urn", entityURNStr).Msg("V2: Invalid URN format")
		response.WriteJSONError(w, http.StatusBadRequest, "Invalid URN format")
		return
	}

	logger := a.Logger.With().Str("entity_urn", entityURN.String()).Logger()

	// 2. Store: Use the V2 store method to retrieve the Go struct
	retrievedKeys, err := a.Store.GetPublicKeys(r.Context(), entityURN)
	if err != nil {
		logger.Warn().Err(err).Msg("V2: Key not found")
		response.WriteJSONError(w, http.StatusNotFound, "Key not found")
		return
	}

	// 3. Respond: Encode the native struct directly using standard json.
	// Our custom MarshalJSON() method on keys.PublicKeys will be called,
	// which uses protojson to correctly handle base64 encoding.
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(retrievedKeys); err != nil {
		// This error is for the *developer*, not the user.
		logger.Error().Err(err).Msg("V2: Failed to marshal keys to JSON")
		// Don't use WriteJSONError, as the response may be half-written
		http.Error(w, "Failed to serialize response", http.StatusInternalServerError)
		return
	}

	logger.Info().Msg("V2: Successfully retrieved public keys")
}
