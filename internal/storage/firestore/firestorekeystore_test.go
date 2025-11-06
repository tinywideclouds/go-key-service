//go:build integration

// REFACTOR: This new test file provides local unit tests for the Firestore
// store, ensuring it correctly implements the URN-based interface.
//
// V2 REFACTOR: Added tests for StorePublicKeys and GetPublicKeys.
// Added a test for V2-getter backward compatibility with V1 data.

package firestore_test

import (
	"context"
	"io"       // IMPORTED
	"log/slog" // IMPORTED
	"testing"
	"time"

	"cloud.google.com/go/firestore"
	"github.com/illmade-knight/go-test/emulators"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	fsAdapter "github.com/tinywideclouds/go-key-service/internal/storage/firestore"
	"github.com/tinywideclouds/go-key-service/pkg/keyservice" // Still need this for setupSuite

	// --- Use Corrected V2 Imports ---
	"github.com/tinywideclouds/go-platform/pkg/keys/v1"
	"github.com/tinywideclouds/go-platform/pkg/net/v1"
)

// newTestLogger creates a discard logger for tests.
func newTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// setupSuite initializes a Firestore emulator and a new Store for testing.
func setupSuite(t *testing.T) (context.Context, *firestore.Client, keyservice.Store) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	t.Cleanup(cancel)

	const projectID = "test-project-keystore"
	const collectionName = "public-keys"

	logger := newTestLogger() // ADDED

	firestoreConn := emulators.SetupFirestoreEmulator(t, ctx, emulators.GetDefaultFirestoreConfig(projectID))
	fsClient, err := firestore.NewClient(context.Background(), projectID, firestoreConn.ClientOptions...)
	require.NoError(t, err)
	t.Cleanup(func() { _ = fsClient.Close() })

	store := fsAdapter.New(fsClient, collectionName, logger) // CHANGED

	return ctx, fsClient, store
}

func TestFirestoreStore_V1_Integration(t *testing.T) {
	ctx, _, store := setupSuite(t)

	// Arrange
	userURN, err := urn.New("user", "user-123", urn.SecureMessaging)
	require.NoError(t, err)
	deviceURN, err := urn.New("device", "device-abc", urn.SecureMessaging)
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
	nonExistentURN, err := urn.New("user", "not-found", urn.SecureMessaging)
	require.NoError(t, err)
	_, err = store.GetKey(ctx, nonExistentURN)
	assert.Error(t, err)
}

// --- NEW V2 Tests ---

func TestFirestoreStore_V2_Integration(t *testing.T) {
	ctx, _, store := setupSuite(t)

	// Arrange
	userURN, err := urn.New("user", "v2-user-123", urn.SecureMessaging)
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
	nonExistentURN, err := urn.New("user", "v2-not-found", urn.SecureMessaging)
	require.NoError(t, err)
	_, err = store.GetPublicKeys(ctx, nonExistentURN)
	assert.Error(t, err)
}

func TestFirestoreStore_V2_Get_BackwardCompatibility(t *testing.T) {
	ctx, _, store := setupSuite(t)

	// Arrange: Store a V1 key
	v1UserURN, err := urn.New("user", "v1-compat-user", urn.SecureMessaging)
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
