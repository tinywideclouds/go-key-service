// --- File: internal/storage/firestore/firestorekeystore_test.go ---
//go:build integration

package firestore_test

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"cloud.google.com/go/firestore"
	"github.com/illmade-knight/go-test/emulators"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	fsAdapter "github.com/tinywideclouds/go-key-service/internal/storage/firestore"
	"github.com/tinywideclouds/go-key-service/pkg/keystore"

	"github.com/tinywideclouds/go-platform/pkg/keys/v1"
	"github.com/tinywideclouds/go-platform/pkg/net/v1"
)

// newTestLogger creates a discard logger for tests.
func newTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// setupSuite initializes a Firestore emulator and a new Store for testing.
func setupSuite(t *testing.T) (context.Context, *firestore.Client, keystore.Store) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	t.Cleanup(cancel)

	const projectID = "test-project-keystore"
	const collectionName = "public-keys"

	logger := newTestLogger()

	firestoreConn := emulators.SetupFirestoreEmulator(t, ctx, emulators.GetDefaultFirestoreConfig(projectID))
	fsClient, err := firestore.NewClient(context.Background(), projectID, firestoreConn.ClientOptions...)
	require.NoError(t, err)
	t.Cleanup(func() { _ = fsClient.Close() })

	store := fsAdapter.NewFirestoreStore(fsClient, collectionName, logger)

	return ctx, fsClient, store
}

func TestFirestoreStore_Integration(t *testing.T) {
	ctx, _, store := setupSuite(t)

	// Arrange
	// --- FIX: Corrected argument order for urn.New ---
	userURN, err := urn.New(urn.SecureMessaging, "user", "user-123")
	require.NoError(t, err)

	testKeys := keys.PublicKeys{
		EncKey: []byte("test-enc-key"),
		SigKey: []byte("test-sig-key"),
	}

	// Act & Assert: Store and retrieve a key struct
	err = store.StorePublicKeys(ctx, userURN, testKeys)
	require.NoError(t, err)

	retrievedKeys, err := store.GetPublicKeys(ctx, userURN)
	require.NoError(t, err)
	assert.Equal(t, testKeys, retrievedKeys)

	// Act & Assert: Get non-existent key
	// --- FIX: Corrected argument order for urn.New ---
	nonExistentURN, err := urn.New(urn.SecureMessaging, "user", "not-found")
	require.NoError(t, err)
	_, err = store.GetPublicKeys(ctx, nonExistentURN)
	assert.Error(t, err)
}
