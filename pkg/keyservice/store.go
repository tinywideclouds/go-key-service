// REFACTOR: This file is updated to use the canonical urn.URN type from the
// go-secure-messaging library. This makes the key service a generic store for
// any entity in our system. Context has also been added to the interface
// methods to align with best practices.
//
// V2 REFACTOR: Added StorePublicKeys and GetPublicKeys to support the
// "Sealed Sender" model, which requires storing/retrieving both
// encryption and signing keys.

// Package keyservice contains the public domain models, interfaces, and
// configuration for the key service. It defines the public contract.
package keyservice

import (
	"context"

	"github.com/tinywideclouds/go-platform/pkg/keys/v1"
	"github.com/tinywideclouds/go-platform/pkg/net/v1"
)

// Store defines the public interface for key persistence.
// Any component that can store and retrieve keys (in-memory, Firestore, etc.)
// must implement this interface.
type Store interface {
	// --- V1 API Methods ---
	// (These store/retrieve only a single key blob, used by /api/keys/{urn})

	StoreKey(ctx context.Context, entityURN urn.URN, key []byte) error
	GetKey(ctx context.Context, entityURN urn.URN) ([]byte, error)

	// --- V2 API Methods ---
	// (These store/retrieve the PublicKeys struct, used by /api/v2/keys/{urn})

	// StorePublicKeys stores the V2 PublicKeys struct.
	StorePublicKeys(ctx context.Context, entityURN urn.URN, keys keys.PublicKeys) error
	// GetPublicKeys retrieves the V2 PublicKeys struct.
	GetPublicKeys(ctx context.Context, entityURN urn.URN) (keys.PublicKeys, error)
}
