package store

import (
	"reflect"
	"testing"

	"github.com/domodwyer/cryptic/encryptor"
)

// mockLock is used to check the lock state after our methods return
type mockLock struct {
	isLocked  bool
	isRLocked bool
}

func (m *mockLock) Lock()    { m.isLocked = true }
func (m *mockLock) Unlock()  { m.isLocked = false }
func (m *mockLock) RLock()   { m.isRLocked = true }
func (m *mockLock) RUnlock() { m.isRLocked = false }

// TestMemoryGet ensures we're developing with a in-memory store that actually
// works
func TestMemoryGet(t *testing.T) {
	tests := []struct {
		// Test description.
		name string
		// Receiver fields.
		rsecrets map[string]encryptor.EncryptedData
		// Parameters.
		pname string
		// Expected results.
		want    *encryptor.EncryptedData
		wantErr error
	}{
		{
			"Empty == ErrNotFound",
			map[string]encryptor.EncryptedData{},
			"missing",
			nil,
			ErrNotFound,
		},
		{
			"No name",
			map[string]encryptor.EncryptedData{},
			"",
			nil,
			ErrInvalidName,
		},
		{
			"Some entries, not this one",
			map[string]encryptor.EncryptedData{
				"kings": {Ciphertext: []byte("a 🐐")},
				"bugs":  {Ciphertext: []byte("oh noes! 💣")},
			},
			"missing",
			nil,
			ErrNotFound,
		},
		{
			"Get a goat",
			map[string]encryptor.EncryptedData{
				"kings": {Ciphertext: []byte("a 🐐")},
				"bugs":  {Ciphertext: []byte("oh noes! 💣")},
			},
			"kings",
			&encryptor.EncryptedData{Ciphertext: []byte("a 🐐")},
			nil,
		},
	}
	for _, tt := range tests {
		lock := &mockLock{}

		b := &Memory{
			secrets: tt.rsecrets,
			mu:      lock,
		}

		got, err := b.Get(tt.pname)
		if err != tt.wantErr {
			t.Errorf("%q. Memory.Get() error = %v, wantErr %v", tt.name, err, tt.wantErr)
			continue
		}
		if !reflect.DeepEqual(got, tt.want) {
			t.Errorf("%q. Memory.Get() = %v, want %v", tt.name, got, tt.want)
		}

		// Ensure we always release our locks
		if lock.isLocked {
			t.Errorf("%q. Memory.Get() is still locked!", tt.name)
		}

		if lock.isRLocked {
			t.Errorf("%q. Memory.Get() is still read locked!", tt.name)
		}
	}
}

// TestMemoryDelete ensures correct errors are returned, and entries are
// actually removed
func TestMemoryDelete(t *testing.T) {
	tests := []struct {
		// Test description.
		name string
		// Receiver fields.
		rsecrets map[string]encryptor.EncryptedData
		// Parameters.
		pname string
		// Expected results.
		want    map[string]encryptor.EncryptedData
		wantErr error
	}{
		{
			"Empty == ErrNotFound",
			map[string]encryptor.EncryptedData{},
			"missing",
			map[string]encryptor.EncryptedData{},
			ErrNotFound,
		},
		{
			"Some entries, not this one",
			map[string]encryptor.EncryptedData{
				"kings": {Ciphertext: []byte("a 🐐")},
				"bugs":  {Ciphertext: []byte("oh noes! 💣")},
			},
			"missing",
			map[string]encryptor.EncryptedData{
				"kings": {Ciphertext: []byte("a 🐐")},
				"bugs":  {Ciphertext: []byte("oh noes! 💣")},
			},
			ErrNotFound,
		},
		{
			"Get a goat",
			map[string]encryptor.EncryptedData{
				"kings": {Ciphertext: []byte("a 🐐")},
				"bugs":  {Ciphertext: []byte("oh noes! 💣")},
			},
			"kings",
			map[string]encryptor.EncryptedData{
				"bugs": {Ciphertext: []byte("oh noes! 💣")},
			},
			nil,
		},
	}
	for _, tt := range tests {
		lock := &mockLock{}

		b := &Memory{
			secrets: tt.rsecrets,
			mu:      lock,
		}

		if err := b.Delete(tt.pname); err != tt.wantErr {
			t.Errorf("%q. Memory.Delete() error = %v, wantErr %v", tt.name, err, tt.wantErr)
			continue
		}
		if !reflect.DeepEqual(tt.rsecrets, tt.want) {
			t.Errorf("%q. Memory.Delete() = %v, want %v", tt.name, tt.rsecrets, tt.want)
		}

		// Ensure we always release our locks
		if lock.isLocked {
			t.Errorf("%q. Memory.Delete() is still locked!", tt.name)
		}

		if lock.isRLocked {
			t.Errorf("%q. Memory.Delete() is still read locked!", tt.name)
		}
	}
}

func TestMemoryPut(t *testing.T) {
	tests := []struct {
		// Test description.
		name string
		// Receiver fields.
		rsecrets map[string]encryptor.EncryptedData
		// Parameters.
		pname string
		data  *encryptor.EncryptedData
		// Expected results.
		want    map[string]encryptor.EncryptedData
		wantErr error
	}{
		{
			"Single",
			map[string]encryptor.EncryptedData{},
			"test",
			&encryptor.EncryptedData{},
			map[string]encryptor.EncryptedData{
				"test": {},
			},
			nil,
		},
		{
			"No overwrite",
			map[string]encryptor.EncryptedData{
				"test": {Ciphertext: []byte("marker")},
			},
			"test",
			&encryptor.EncryptedData{Ciphertext: []byte("newVal")},
			map[string]encryptor.EncryptedData{
				"test": {Ciphertext: []byte("marker")},
			},
			ErrAlreadyExists,
		},
	}
	for _, tt := range tests {
		lock := &mockLock{}

		s := &Memory{
			secrets: tt.rsecrets,
			mu:      lock,
		}

		err := s.Put(tt.pname, tt.data)
		if err != tt.wantErr {
			t.Errorf("%q. Memory.Put() error = %v, wantErr %v", tt.name, err, tt.wantErr)
		}

		if err != nil {
			continue
		}

		if !reflect.DeepEqual(tt.want, s.secrets) {
			t.Errorf("%q. Memory.Put() = %v, want %v", tt.name, s.secrets, tt.want)
		}

		// Ensure we always release our locks
		if lock.isLocked {
			t.Errorf("%q. Memory.Get() is still locked!", tt.name)
		}

		if lock.isRLocked {
			t.Errorf("%q. Memory.Get() is still read locked!", tt.name)
		}
	}
}
