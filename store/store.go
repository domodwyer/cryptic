package store

import "github.com/domodwyer/cryptic/encryptor"

// Putter defines the interface for storing secrets in a back-end store.
type Putter interface {
	Put(name string, data *encryptor.EncryptedData) error
}

// Getter defines the interface for fetching secrets from the back-end store.
type Getter interface {
	Get(name string) (*encryptor.EncryptedData, error)
}

// Deleter defines the interface for deleting secrets from the back-end store.
type Deleter interface {
	Delete(name string) error
}

// Interface combines the Putter, Getter and Deleter interface
type Interface interface {
	Putter
	Getter
	Deleter
}
