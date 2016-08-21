package store

import (
	"time"

	"github.com/domodwyer/cryptic/encryptor"

	"gopkg.in/redis.v4"
)

// Redis abstracts storing secrets in a redis backend.
//
// If you're using a cluster of redis servers, you can initalise a Redis struct
// directly and pass in an initalised Client using redis.NewFailoverClient.
type Redis struct {
	Redis redisInterface
}

type redisInterface interface {
	Get(key string) *redis.StringCmd
	Set(key string, value interface{}, expiration time.Duration) *redis.StatusCmd
	Del(keys ...string) *redis.IntCmd
}

// NewRedis returns an initalised Redis store.
func NewRedis(opts *redis.Options) *Redis {
	return &Redis{
		Redis: redis.NewClient(opts),
	}
}

// Put stores the given secret in redis, with no expiration set.
func (s *Redis) Put(name string, data *encryptor.EncryptedData) error {
	if name == "" {
		return ErrInvalidName
	}

	// TODO: the Get() and Put() should be done in a transaction using the redis
	// WATCH command to avoid race conditions - opportunistic locking.

	// Ensure we're not overwriting something
	if _, err := s.Get(name); err != ErrNotFound {
		return ErrAlreadyExists
	}

	// Because EncryptedData implements BinaryMarshaller, we can pass it
	// directly to redis - the redis library will marshal it for us.
	if err := s.Redis.Set(name, data, 0).Err(); err != nil {
		return err
	}

	return nil
}

// Get fetches the secret from redis.
func (s *Redis) Get(name string) (*encryptor.EncryptedData, error) {
	if name == "" {
		return nil, ErrInvalidName
	}

	resp := s.Redis.Get(name)
	if err := resp.Err(); err != nil {
		// Check if it's the (annoyingly) unexported "redis: nil" error by
		// checking the byte length. No bytes, no results.
		b, _ := resp.Bytes()
		if len(b) < 1 {
			return nil, ErrNotFound
		}

		return nil, err
	}

	// Let the redis library unmarshal our data, because EncryptedData
	// implements BinaryUnmarshaler
	d := &encryptor.EncryptedData{}
	if err := resp.Scan(d); err != nil {
		return nil, err
	}

	return d, nil
}

// Delete removes the secret from redis.
func (s *Redis) Delete(name string) error {
	// TODO: Transaction same as Put()
	if _, err := s.Get(name); err != nil {
		return ErrNotFound
	}

	resp := s.Redis.Del(name)
	if err := resp.Err(); err != nil {
		return err
	}

	return nil
}
