package keystore

import "errors"

// ErrNotFound is returned when a specific entity URN cannot be found in the store.
// This allows the API layer to distinguish between a missing record (404)
// and a database failure (500).
var ErrNotFound = errors.New("key not found")
