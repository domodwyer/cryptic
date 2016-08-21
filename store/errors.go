package store

import "errors"

var (
	// ErrNotFound is returned when a secret is not found in the store.
	ErrNotFound = errors.New("store: secret not found")

	// ErrInvalidName is returned when a name isn't supported (or is ridiculous, like "").
	ErrInvalidName = errors.New("store: invalid secret name")

	// ErrAlreadyExists is returned when attempting to Put() a secret with the
	// same name as an existing entry.
	ErrAlreadyExists = errors.New("store: secret already exists")
)
