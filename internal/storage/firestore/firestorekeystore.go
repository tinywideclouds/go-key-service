// --- File: internal/storage/firestore/firestorekeystore.go ---
// Package firestore provides a key store implementation using Google Cloud Firestore.
package firestore

import (
	"context"
	"fmt"
	"log/slog"

	"cloud.google.com/go/firestore"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/tinywideclouds/go-platform/pkg/keys/v1"
	urn "github.com/tinywideclouds/go-platform/pkg/net/v1"
)

// KeyDocument defines the Firestore schema for storing public keys.
// This is an internal implementation detail of the firestore package.
type KeyDocument struct {
	EncKey []byte `firestore:"encKey"`
	SigKey []byte `firestore:"sigKey"`
}

// Store is a concrete implementation of the keyservice.Store interface using Firestore.
// It maps entity URNs to Firestore documents.
type Store struct {
	client     *firestore.Client
	collection *firestore.CollectionRef
	logger     *slog.Logger
}

// NewFirestoreStore creates a new Firestore-backed store.
func NewFirestoreStore(client *firestore.Client, collectionName string, logger *slog.Logger) *Store {
	return &Store{
		client:     client,
		collection: client.Collection(collectionName),
		logger:     logger.With("component", "firestore_store", "collection", collectionName),
	}
}

// StorePublicKeys creates or overwrites a document in Firestore with the
// provided PublicKeys struct. The document ID is the URN's string representation.
func (s *Store) StorePublicKeys(ctx context.Context, entityURN urn.URN, keys keys.PublicKeys) error {
	entityKey := entityURN.String()
	doc := s.collection.Doc(entityKey)
	s.logger.Debug("Storing keys", "key", entityKey)

	docData := KeyDocument{
		EncKey: keys.EncKey,
		SigKey: keys.SigKey,
	}

	_, err := doc.Set(ctx, docData)
	if err != nil {
		s.logger.Error("Failed to store keys", "key", entityKey, "err", err)
		return fmt.Errorf("failed to store public keys for entity %s: %w", entityKey, err)
	}
	s.logger.Debug("Successfully stored keys", "key", entityKey)
	return nil
}

// GetPublicKeys retrieves a PublicKeys struct from a Firestore document.
// It returns an error if the document is not found or cannot be parsed.
func (s *Store) GetPublicKeys(ctx context.Context, entityURN urn.URN) (keys.PublicKeys, error) {
	entityKey := entityURN.String()
	s.logger.Debug("Getting keys", "key", entityKey)

	doc, err := s.collection.Doc(entityKey).Get(ctx)
	if err != nil {
		if status.Code(err) == codes.NotFound {
			s.logger.Debug("Keys not found", "key", entityKey)
			return keys.PublicKeys{}, fmt.Errorf("key for entity %s not found", entityKey)
		}
		s.logger.Warn("Failed to get key document", "key", entityKey, "err", err)
		return keys.PublicKeys{}, fmt.Errorf("failed to get key for entity %s: %w", entityKey, err)
	}

	var kDoc KeyDocument
	if err := doc.DataTo(&kDoc); err == nil {
		// Success: Check if it's a real doc (has non-nil EncKey or SigKey)
		if kDoc.EncKey != nil || kDoc.SigKey != nil {
			s.logger.Debug("Successfully retrieved keys ", "key", entityKey)
			return keys.PublicKeys{
				EncKey: kDoc.EncKey,
				SigKey: kDoc.SigKey,
			}, nil
		}
	}

	// This case handles a document that exists but doesn't match our struct
	return keys.PublicKeys{}, fmt.Errorf("failed to parse key document for entity %s: unknown format", entityKey)
}
