// --- File: internal/storage/inmemory/inmemorykeystore.go ---
// Package inmemory provides a thread-safe in-memory key store.
package inmemory

import (
	"context"
	"fmt"
	"sync"

	"github.com/tinywideclouds/go-platform/pkg/keys/v1"
	"github.com/tinywideclouds/go-platform/pkg/net/v1"
)

// Store is a concrete, thread-safe in-memory implementation of the keystore.Store interface.
type Store struct {
	sync.RWMutex
	keys map[string]keys.PublicKeys
}

// New creates a new, initialized in-memory key store.
func New() *Store {
	return &Store{keys: make(map[string]keys.PublicKeys)}
}

// StorePublicKeys stores the PublicKeys struct in the map, keyed by the URN's string representation.
// This operation is thread-safe.
func (s *Store) StorePublicKeys(ctx context.Context, entityURN urn.URN, keys keys.PublicKeys) error {
	s.Lock()
	defer s.Unlock()
	s.keys[entityURN.String()] = keys
	return nil
}

// GetPublicKeys retrieves the PublicKeys struct from the map.
// It returns an error if no key is found for the given URN.
// This operation is thread-safe.
func (s *Store) GetPublicKeys(ctx context.Context, entityURN urn.URN) (keys.PublicKeys, error) {
	s.RLock()
	defer s.RUnlock()
	keyStruct, ok := s.keys[entityURN.String()]
	if !ok {
		return keys.PublicKeys{}, fmt.Errorf("key for entity %s not found", entityURN.String())
	}
	return keyStruct, nil
}
