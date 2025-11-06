// context-aware keyservice.Store interface. All Firestore operations now use
// the canonical string representation of the URN as the document key.
//
// V2 REFACTOR: Added StorePublicKeys and GetPublicKeys. These methods
// store/retrieve a new v2KeyDocument struct that holds both encKey and sigKey.
// The V1 methods remain unchanged for backward compatibility.

// Package firestore provides a key store implementation using Google Cloud Firestore.
package firestore

import (
	"context"
	"fmt"
	"log/slog" // IMPORTED

	"cloud.google.com/go/firestore"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/tinywideclouds/go-platform/pkg/keys/v1"
	urn "github.com/tinywideclouds/go-platform/pkg/net/v1"
)

// v1KeyDocument is the structure stored in a Firestore document for the V1 API.
// It only contains the single public (encryption) key.
type v1KeyDocument struct {
	PublicKey []byte `firestore:"publicKey"`
}

// v2KeyDocument is the new structure stored for the V2 API.
// It stores both the encryption and signing keys.
type v2KeyDocument struct {
	EncKey []byte `firestore:"encKey"`
	SigKey []byte `firestore:"sigKey"`
}

// Store is a concrete implementation of the keyservice.Store interface using Firestore.
type Store struct {
	client     *firestore.Client
	collection *firestore.CollectionRef
	logger     *slog.Logger // ADDED
}

// NewFirestoreStore creates a new Firestore-backed store.
func NewFirestoreStore(client *firestore.Client, collectionName string, logger *slog.Logger) *Store { // CHANGED
	return &Store{
		client:     client,
		collection: client.Collection(collectionName),
		logger:     logger.With("component", "firestore_store", "collection", collectionName), // ADDED
	}
}

// --- V1 API Methods (Unchanged) ---

// StoreKey creates or overwrites a document with the entity's public key (V1).
func (s *Store) StoreKey(ctx context.Context, entityURN urn.URN, key []byte) error {
	entityKey := entityURN.String()
	doc := s.collection.Doc(entityKey)

	s.logger.Debug("Storing V1 key", "key", entityKey) // ADDED

	// Uses the v1KeyDocument struct
	_, err := doc.Set(ctx, v1KeyDocument{PublicKey: key})
	if err != nil {
		s.logger.Error("Failed to store V1 key", "key", entityKey, "err", err) // ADDED
		return fmt.Errorf("failed to store v1 key for entity %s: %w", entityKey, err)
	}
	s.logger.Debug("Successfully stored V1 key", "key", entityKey) // ADDED
	return nil
}

// GetKey retrieves an entity's public key from a Firestore document (V1).
func (s *Store) GetKey(ctx context.Context, entityURN urn.URN) ([]byte, error) {
	entityKey := entityURN.String()
	s.logger.Debug("Getting V1 key", "key", entityKey) // ADDED

	doc, err := s.collection.Doc(entityKey).Get(ctx)
	if err != nil {
		if status.Code(err) == codes.NotFound {
			s.logger.Debug("V1 key not found", "key", entityKey) // ADDED
			return nil, fmt.Errorf("key for entity %s not found", entityKey)
		}
		s.logger.Warn("Failed to get V1 key document", "key", entityKey, "err", err) // ADDED
		return nil, fmt.Errorf("failed to get v1 key for entity %s: %w", entityKey, err)
	}

	var kd v1KeyDocument
	if err := doc.DataTo(&kd); err != nil {
		s.logger.Error("Failed to parse V1 key document", "key", entityKey, "err", err) // ADDED
		return nil, fmt.Errorf("failed to parse v1 key document for entity %s: %w", entityKey, err)
	}

	s.logger.Debug("Successfully retrieved V1 key", "key", entityKey) // ADDED
	return kd.PublicKey, nil
}

// --- V2 API Methods (New) ---

// StorePublicKeys creates or overwrites a document with the V2 PublicKeys struct.
func (s *Store) StorePublicKeys(ctx context.Context, entityURN urn.URN, keys keys.PublicKeys) error {
	entityKey := entityURN.String()
	doc := s.collection.Doc(entityKey)
	s.logger.Debug("Storing V2 keys", "key", entityKey) // ADDED

	// Uses the new v2KeyDocument struct
	v2Doc := v2KeyDocument{
		EncKey: keys.EncKey,
		SigKey: keys.SigKey,
	}

	_, err := doc.Set(ctx, v2Doc)
	if err != nil {
		s.logger.Error("Failed to store V2 keys", "key", entityKey, "err", err) // ADDED
		return fmt.Errorf("failed to store v2 public keys for entity %s: %w", entityKey, err)
	}
	s.logger.Debug("Successfully stored V2 keys", "key", entityKey) // ADDED
	return nil
}

// GetPublicKeys retrieves a V2 PublicKeys struct from a Firestore document.
//
// NOTE: This method can also read V1 documents for backward compatibility.
// If only a V1 `publicKey` field is found, it will be returned as the `EncKey`
// with an empty `SigKey`.
func (s *Store) GetPublicKeys(ctx context.Context, entityURN urn.URN) (keys.PublicKeys, error) {
	entityKey := entityURN.String()
	s.logger.Debug("Getting V2 keys", "key", entityKey) // ADDED

	doc, err := s.collection.Doc(entityKey).Get(ctx)
	if err != nil {
		if status.Code(err) == codes.NotFound {
			s.logger.Debug("V2 keys not found", "key", entityKey) // ADDED
			return keys.PublicKeys{}, fmt.Errorf("key for entity %s not found", entityKey)
		}
		s.logger.Warn("Failed to get V2 key document", "key", entityKey, "err", err) // ADDED
		return keys.PublicKeys{}, fmt.Errorf("failed to get key for entity %s: %w", entityKey, err)
	}

	// Try to parse as V2 document first
	var v2Doc v2KeyDocument
	if err := doc.DataTo(&v2Doc); err == nil {
		// Success: Check if it's a real V2 doc (has non-nil EncKey or SigKey)
		if v2Doc.EncKey != nil || v2Doc.SigKey != nil {
			s.logger.Debug("Successfully retrieved V2 keys (V2 format)", "key", entityKey) // ADDED
			return keys.PublicKeys{
				EncKey: v2Doc.EncKey,
				SigKey: v2Doc.SigKey,
			}, nil
		}
	}

	s.logger.Debug("V2 doc parse failed or was empty, attempting V1 compatibility fallback", "key", entityKey, "err", err) // ADDED

	// If V2 parse failed or resulted in empty struct, try V1
	var v1Doc v1KeyDocument
	if err := doc.DataTo(&v1Doc); err == nil {
		// Success: Found a V1 document
		if v1Doc.PublicKey != nil {
			s.logger.Debug("Successfully retrieved V2 keys (V1 fallback)", "key", entityKey) // ADDED
			// Return it as a V2 struct for compatibility
			return keys.PublicKeys{
				EncKey: v1Doc.PublicKey, // V1 key is treated as EncKey
				SigKey: []byte{},        // SigKey is empty
			}, nil
		}
	}

	s.logger.Error("Failed to parse key document as V1 or V2", "key", entityKey) // ADDED

	// If we're here, the document was found but couldn't be parsed
	// as either a V1 or V2 struct.
	return keys.PublicKeys{}, fmt.Errorf("failed to parse key document for entity %s: unknown format", entityKey)
}
