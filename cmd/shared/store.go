package shared

import (
	"database/sql"
	"errors"
	"fmt"

	"gopkg.in/redis.v4"

	"github.com/domodwyer/cryptic/config"
	"github.com/domodwyer/cryptic/store"

	// Import the MySQL driver
	_ "github.com/go-sql-driver/mysql"
)

// GetStore returns a concrete type that implements store.Interface based on the
// configured Store value in the config file.
func GetStore(config config.Store) (store.Interface, error) {
	var backend store.Interface
	var err error

	switch config.Store() {
	case "db":
		// Compose the DSN
		dsn := fmt.Sprintf("%s:%s@tcp(%s)]/%s",
			config.DBUsername(),
			config.DBPassword(),
			config.DBHost(),
			config.DBName(),
		)

		// Connect to DB
		db, err := sql.Open("mysql", dsn)
		if err != nil {
			return nil, err
		}

		// Configure DB store
		opts := &store.DBOpts{
			Table: config.DBTable(),
			Key:   config.DBKeyColumn(),
			Value: config.DBValueColumn(),
		}

		backend, err = store.NewDB(db, opts)

	case "redis":
		backend = store.NewRedis(&redis.Options{
			Addr:         config.RedisHost(),
			Password:     config.RedisPassword(),
			DB:           config.RedisDbIndex(),
			MaxRetries:   config.RedisMaxRetries(),
			ReadTimeout:  config.RedisReadTimeout(),
			WriteTimeout: config.RedisWriteTimeout(),
		})

	default:
		err = errors.New("unknown store")
	}

	if err != nil {
		return nil, err
	}

	return backend, nil
}
