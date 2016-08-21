// +build integration

package store

import (
	"os"
	"reflect"
	"testing"

	"github.com/domodwyer/cryptic/encryptor"
	"gopkg.in/redis.v4"
)

// Because go-redis returns thing such as redis.StatusCmd{} with unexported
// fields, we cannot really mock out the redis client and get it to do what we
// want, therefore we have to use a live redis instance. Maybe go-redis should
// return an interface?

func TestRedisPut(t *testing.T) {

	// If we don't have a host to connect to, skip all the redis integration
	// tests
	if os.Getenv("REDIS_HOST") == "" {
		t.Skip("no REDIS_HOST environment variable set, skipping integration tests")
	}

	c := redis.NewClient(&redis.Options{
		Addr: os.Getenv("REDIS_HOST"),
	})

	// Remove used test keys
	if err := c.Del("integration_test_key").Err(); err != nil {
		t.Errorf("redis: removing test keys: %s", err)
		return
	}

	tests := []struct {
		// Test description.
		name string
		// Parameters.
		pname string
		data  *encryptor.EncryptedData
		// Expected results.
		wantErr error
	}{
		{
			"Example",
			"integration_test_key",
			&encryptor.EncryptedData{},
			nil,
		},
		{
			"No overwrite",
			"integration_test_key",
			&encryptor.EncryptedData{},
			ErrAlreadyExists,
		},
		{
			"No name",
			"",
			&encryptor.EncryptedData{},
			ErrInvalidName,
		},
	}
	for _, tt := range tests {
		s := Redis{Redis: c}

		if err := s.Put(tt.pname, tt.data); err != tt.wantErr {
			t.Errorf("%q. Redis.Put() error = %v, wantErr %v", tt.name, err, tt.wantErr)
		}
	}
}

func TestRedisGet(t *testing.T) {

	// If we don't have a host to connect to, skip all the redis integration
	// tests
	if os.Getenv("REDIS_HOST") == "" {
		t.Skip("no REDIS_HOST environment variable set, skipping integration tests")
	}

	c := redis.NewClient(&redis.Options{
		Addr: os.Getenv("REDIS_HOST"),
	})

	s := Redis{Redis: c}
	if err := s.Put("integration_test_key2", &encryptor.EncryptedData{Ciphertext: []byte("marker")}); err != nil {
		t.Errorf("redis: setting up integration test key: %s", err)
		return
	}

	tests := []struct {
		// Test description.
		name string
		// Parameters.
		pname string
		// Expected results.
		want    *encryptor.EncryptedData
		wantErr error
	}{
		{
			"Example",
			"integration_test_key2",
			&encryptor.EncryptedData{
				Ciphertext: []byte("marker"),
				Context:    map[string]interface{}{},
			},
			nil,
		},
		{
			"Not found",
			"integration_test_key_missing",
			nil,
			ErrNotFound,
		},
		{
			"No name",
			"",
			nil,
			ErrInvalidName,
		},
	}

	for _, tt := range tests {
		got, err := s.Get(tt.pname)
		if err != tt.wantErr {
			t.Errorf("%q. Redis.Get() error = %v, wantErr %v", tt.name, err, tt.wantErr)
			continue
		}
		if !reflect.DeepEqual(got, tt.want) {
			t.Errorf("%q. Redis.Get() = %v, want %v", tt.name, got, tt.want)
		}
	}

	// Remove used test keys
	if err := c.Del("integration_test_key2").Err(); err != nil {
		t.Errorf("redis: removing test keys: %s", err)
		return
	}
}

func TestRedisDelete(t *testing.T) {

	// If we don't have a host to connect to, skip all the redis integration
	// tests
	if os.Getenv("REDIS_HOST") == "" {
		t.Skip("no REDIS_HOST environment variable set, skipping integration tests")
	}

	c := redis.NewClient(&redis.Options{
		Addr: os.Getenv("REDIS_HOST"),
	})

	s := Redis{Redis: c}
	if err := s.Put("integration_test_key3", &encryptor.EncryptedData{Ciphertext: []byte("marker")}); err != nil {
		t.Errorf("redis: setting up integration test key: %s", err)
		return
	}

	tests := []struct {
		// Test description.
		name string
		// Parameters.
		pname string
		// Expected results.
		wantErr error
	}{
		{
			"Example",
			"integration_test_key3",
			nil,
		},
		{
			"Not found",
			"integration_test_key3",
			ErrNotFound,
		},
	}
	for _, tt := range tests {
		if err := s.Delete(tt.pname); err != tt.wantErr {
			t.Errorf("%q. Redis.Delete() error = %v, wantErr %v", tt.name, err, tt.wantErr)
		}
	}

	// Remove used test keys
	if err := c.Del("integration_test_key3").Err(); err != nil {
		t.Errorf("redis: removing test keys: %s", err)
		return
	}
}
