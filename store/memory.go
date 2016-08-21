package store

import (
	"sync"

	"github.com/domodwyer/cryptic/encryptor"
)

type rwLocker interface {
	sync.Locker
	RLock()
	RUnlock()
}

// Memory is an in-memory data store. Contents are not persisted in any way
// after the process ends.
type Memory struct {
	secrets map[string]encryptor.EncryptedData
	mu      rwLocker
}

// NewMemory returns an initalised memory store.
func NewMemory() *Memory {
	return &Memory{
		secrets: map[string]encryptor.EncryptedData{},
		mu:      &sync.RWMutex{},
	}
}

// Put stores data under the given name.
func (s *Memory) Put(name string, data *encryptor.EncryptedData) error {
	if name == "" {
		return ErrInvalidName
	}

	if _, err := s.Get(name); err != ErrNotFound {
		return ErrAlreadyExists
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.secrets[name] = *data
	return nil
}

// Get fetches the EncryptedData stored under name.
func (s *Memory) Get(name string) (*encryptor.EncryptedData, error) {
	if name == "" {
		return nil, ErrInvalidName
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	d, ok := s.secrets[name]
	if !ok {
		return nil, ErrNotFound
	}

	return &d, nil
}

// Delete removes a secret from the memory store.
func (s *Memory) Delete(name string) error {
	if name == "" {
		return ErrInvalidName
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.secrets[name]; !ok {
		return ErrNotFound
	}

	delete(s.secrets, name)
	return nil
}
