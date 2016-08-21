package config

import (
	"time"

	"github.com/spf13/viper"
)

// Redis defines config getters for the Redis store parameters.
type Redis interface {
	RedisHost() string
	RedisDbIndex() int
	RedisPassword() string
	RedisMaxRetries() int
	RedisReadTimeout() time.Duration
	RedisWriteTimeout() time.Duration
}

// RedisHost returns the configured redis hostname (in the format ip:port).
func (v viperStore) RedisHost() string {
	return viper.GetString("Redis.Host")
}

// RedisDbIndex returns the configured redis database index.
func (v viperStore) RedisDbIndex() int {
	return viper.GetInt("Redis.DbIndex")
}

// RedisPassword returns the configured redis password.
func (v viperStore) RedisPassword() string {
	return viper.GetString("Redis.Password")
}

// RedisMaxRetries returns the configured maximum number of retries for redis
// operations.
func (v viperStore) RedisMaxRetries() int {
	return viper.GetInt("Redis.MaxRetries")
}

// RedisReadTimeout returns the configured redis read timeout.
func (v viperStore) RedisReadTimeout() time.Duration {
	return viper.GetDuration("Redis.ReadTimeout")
}

// RedisWriteTimeout returns the configured redis write timeout.
func (v viperStore) RedisWriteTimeout() time.Duration {
	return viper.GetDuration("Redis.WriteTimeout")
}
