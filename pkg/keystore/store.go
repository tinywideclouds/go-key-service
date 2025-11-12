// --- File: pkg/keystore/store.go ---
// Package keystore contains the public domain models, interfaces, and
// configuration for the key service. It defines the public contract.
package keystore

import (
	"context"

	"github.com/tinywideclouds/go-platform/pkg/keys/v1"
	urn "github.com/tinywideclouds/go-platform/pkg/net/v1"
)

// Store defines the public interface for key persistence.
// Any component that can store and retrieve keys (in-memory, Firestore, etc.)
// must implement this interface.
type Store interface {
	// StorePublicKeys persists the provided PublicKeys struct for a specific entity.
	// It should overwrite any existing keys for that entity.
	StorePublicKeys(ctx context.Context, entityURN urn.URN, keys keys.PublicKeys) error

	// GetPublicKeys retrieves the PublicKeys struct for a specific entity.
	// If no keys are found, it should return an error.
	GetPublicKeys(ctx context.Context, entityURN urn.URN) (keys.PublicKeys, error)
}
