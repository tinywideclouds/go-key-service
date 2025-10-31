// REFACTOR: This test file is updated to validate the URN-based and
// context-aware in-memory store implementation.
//
// V2 REFACTOR: Added tests for V2 (StorePublicKeys, GetPublicKeys) and
// V2-getter backward compatibility with V1-setter data.

package inmemory_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tinywideclouds/go-key-service/internal/storage/inmemory"
	"github.com/tinywideclouds/go-key-service/pkg/keyservice"

	// --- Use Corrected V2 Imports ---
	"github.com/tinywideclouds/go-platform/pkg/keys/v1"
	"github.com/tinywideclouds/go-platform/pkg/net/v1"
)

// setupSuite initializes a new in-memory Store for testing.
func setupSuite(t *testing.T) (context.Context, keyservice.Store) {
	t.Helper()
	store := inmemory.New()
	return context.Background(), store
}

func TestInMemoryStore_V1_Integration(t *testing.T) {
	ctx, store := setupSuite(t)

	// Arrange
	userURN, err := urn.New(urn.SecureMessaging, "user", "user-123")
	require.NoError(t, err)
	deviceURN, err := urn.New(urn.SecureMessaging, "device", "device-abc")
	require.NoError(t, err)

	userKey := []byte("user-public-key-v1")
	deviceKey := []byte("device-public-key-v1")

	// Act & Assert: Store and retrieve a user key
	err = store.StoreKey(ctx, userURN, userKey)
	require.NoError(t, err)

	retrievedUserKey, err := store.GetKey(ctx, userURN)
	require.NoError(t, err)
	assert.Equal(t, userKey, retrievedUserKey)

	// Act & Assert: Store and retrieve a device key
	err = store.StoreKey(ctx, deviceURN, deviceKey)
	require.NoError(t, err)

	retrievedDeviceKey, err := store.GetKey(ctx, deviceURN)
	require.NoError(t, err)
	assert.Equal(t, deviceKey, retrievedDeviceKey)

	// Act & Assert: Get non-existent key
	nonExistentURN, err := urn.New(urn.SecureMessaging, "user", "not-found")
	require.NoError(t, err)
	_, err = store.GetKey(ctx, nonExistentURN)
	assert.Error(t, err)
}

// --- NEW V2 Tests ---

func TestInMemoryStore_V2_Integration(t *testing.T) {
	ctx, store := setupSuite(t)

	// Arrange
	userURN, err := urn.New(urn.SecureMessaging, "user", "v2-user-123")
	require.NoError(t, err)

	v2Keys := keys.PublicKeys{
		EncKey: []byte("v2-enc-key"),
		SigKey: []byte("v2-sig-key"),
	}

	// Act & Assert: Store and retrieve a V2 key struct
	err = store.StorePublicKeys(ctx, userURN, v2Keys)
	require.NoError(t, err)

	retrievedKeys, err := store.GetPublicKeys(ctx, userURN)
	require.NoError(t, err)
	assert.Equal(t, v2Keys, retrievedKeys)

	// Act & Assert: Get non-existent key
	nonExistentURN, err := urn.New(urn.SecureMessaging, "user", "v2-not-found")
	require.NoError(t, err)
	_, err = store.GetPublicKeys(ctx, nonExistentURN)
	assert.Error(t, err)
}

func TestInMemoryStore_V2_Get_BackwardCompatibility(t *testing.T) {
	ctx, store := setupSuite(t)

	// Arrange: Store a V1 key
	v1UserURN, err := urn.New(urn.SecureMessaging, "user", "v1-compat-user")
	require.NoError(t, err)
	v1Key := []byte("this-is-a-v1-key")

	err = store.StoreKey(ctx, v1UserURN, v1Key) // Use V1 store method
	require.NoError(t, err)

	// Act: Retrieve the V1 key using the V2 GetPublicKeys method
	retrievedV2Keys, err := store.GetPublicKeys(ctx, v1UserURN)
	require.NoError(t, err)

	// Assert: The V1 key should be in the EncKey field, and SigKey should be empty
	expectedKeys := keys.PublicKeys{
		EncKey: v1Key,
		SigKey: []byte{},
	}
	assert.Equal(t, expectedKeys, retrievedV2Keys)
}
