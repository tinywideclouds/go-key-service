// REFACTOR: This file is updated to implement the full V2 keyservice.Store
// interface, including StorePublicKeys and GetPublicKeys.
//
// V2 REFACTOR: The internal map now stores the keys.PublicKeys struct
// to support both V1 and V2 data. The V1 methods (StoreKey, GetKey)
// are adapted to use this struct, ensuring backward compatibility.

// Package inmemory provides a thread-safe in-memory key store.
package inmemory

import (
	"context"
	"fmt"
	"sync"

	// --- Use Corrected V2 Imports ---
	"github.com/tinywideclouds/go-platform/pkg/keys/v1"
	"github.com/tinywideclouds/go-platform/pkg/net/v1"
)

// Store is a concrete, thread-safe in-memory implementation of the keyservice.Store interface.
type Store struct {
	sync.RWMutex
	// Store the V2 PublicKeys struct, which can also represent V1 data.
	keys map[string]keys.PublicKeys
}

// New creates a new in-memory key store.
func New() *Store {
	return &Store{keys: make(map[string]keys.PublicKeys)}
}

// --- V1 API Methods (Adapted for V2 storage) ---

// StoreKey adds a key to the in-memory map.
// It stores the V1 key in the EncKey field of the PublicKeys struct.
func (s *Store) StoreKey(ctx context.Context, entityURN urn.URN, key []byte) error {
	s.Lock()
	defer s.Unlock()
	// Store as a V2 struct for compatibility
	s.keys[entityURN.String()] = keys.PublicKeys{
		EncKey: key,
		SigKey: []byte{}, // V1 keys have no corresponding SigKey
	}
	return nil
}

// GetKey retrieves a key from the in-memory map.
// It returns only the EncKey field, maintaining the V1 API contract.
func (s *Store) GetKey(ctx context.Context, entityURN urn.URN) ([]byte, error) {
	s.RLock()
	defer s.RUnlock()
	keyStruct, ok := s.keys[entityURN.String()]
	if !ok {
		return nil, fmt.Errorf("key for entity %s not found", entityURN.String())
	}
	// V1 getter only returns the encryption key
	return keyStruct.EncKey, nil
}

// --- V2 API Methods (New) ---

// StorePublicKeys stores the V2 PublicKeys struct.
func (s *Store) StorePublicKeys(ctx context.Context, entityURN urn.URN, keys keys.PublicKeys) error {
	s.Lock()
	defer s.Unlock()
	s.keys[entityURN.String()] = keys
	return nil
}

// GetPublicKeys retrieves the V2 PublicKeys struct.
// This method will also correctly retrieve keys stored via the V1 StoreKey method.
func (s *Store) GetPublicKeys(ctx context.Context, entityURN urn.URN) (keys.PublicKeys, error) {
	s.RLock()
	defer s.RUnlock()
	keyStruct, ok := s.keys[entityURN.String()]
	if !ok {
		return keys.PublicKeys{}, fmt.Errorf("key for entity %s not found", entityURN.String())
	}
	return keyStruct, nil
}
