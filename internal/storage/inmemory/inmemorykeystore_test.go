// --- File: internal/storage/inmemory/inmemorykeystore_test.go ---
package inmemory_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tinywideclouds/go-key-service/internal/storage/inmemory"
	"github.com/tinywideclouds/go-key-service/pkg/keystore"

	"github.com/tinywideclouds/go-platform/pkg/keys/v1"
	"github.com/tinywideclouds/go-platform/pkg/net/v1"
)

// setupSuite initializes a new in-memory Store for testing.
func setupSuite(t *testing.T) (context.Context, keystore.Store) {
	t.Helper()
	store := inmemory.New()
	return context.Background(), store
}

func TestInMemoryStore_Integration(t *testing.T) {
	ctx, store := setupSuite(t)

	// Arrange
	userURN, err := urn.New(urn.SecureMessaging, "user", "user-123")
	require.NoError(t, err)

	testKeys := keys.PublicKeys{
		EncKey: []byte("enc-key"),
		SigKey: []byte("sig-key"),
	}

	// Act & Assert: Store and retrieve a key struct
	err = store.StorePublicKeys(ctx, userURN, testKeys)
	require.NoError(t, err)

	retrievedKeys, err := store.GetPublicKeys(ctx, userURN)
	require.NoError(t, err)
	assert.Equal(t, testKeys, retrievedKeys)

	// Act & Assert: Get non-existent key
	nonExistentURN, err := urn.New(urn.SecureMessaging, "user", "not-found")
	require.NoError(t, err)
	_, err = store.GetPublicKeys(ctx, nonExistentURN)
	assert.Error(t, err)
}
