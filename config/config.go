package config

import (
	"log"
	"sync"

	"github.com/spf13/viper"
)

// Interface combines the Store and Encryptor interfaces
type Interface interface {
	Store
	Encryptor
}

// Store defines the interface providing getters related to stores
type Store interface {
	SelectedStore
	Redis
	DB
}

// Encryptor defines the interface providing getters related to encryptors
type Encryptor interface {
	SelectedEncryptor
	KMS
	AES
	KDF
}

type viperStore struct{}

var vs *viperStore
var once sync.Once

func init() {
	defaults := map[string]interface{}{
		"Store":     "redis",
		"Encryptor": "kms",

		// KMS config
		"KMS.KeyID":  "",
		"KMS.Region": "eu-west-1",

		// AES config
		"AES.Key":     "",
		"AES.HmacKey": "",

		// Redis store config
		"Redis.Host":         "127.0.0.1:6379",
		"Redis.DbIndex":      0,
		"Redis.Password":     "",
		"Redis.ReadTimeout":  "3s",
		"Redis.WriteTimeout": "5s",
		"Redis.MaxRetries":   0,

		// DB store config
		"DB.Host":        "127.0.0.1:3306",
		"DB.Username":    "root",
		"DB.Password":    "",
		"DB.Name":        "cryptic",
		"DB.Table":       "secrets",
		"DB.KeyColumn":   "name",
		"DB.ValueColumn": "data",
	}

	// First match takes preference
	viper.AddConfigPath(".")
	viper.AddConfigPath("/etc/cryptic/")

	for k, v := range defaults {
		viper.SetDefault(k, v)
	}

	viper.SetConfigName("cryptic")

	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.UnsupportedConfigError); ok {
			log.Print("config: failed to load config file, using defaults")
		} else {
			log.Fatalf("config: init error (%v)", err)
		}
	}

}

// New returns a config accessor that implements Interface as singleton
func New() Interface {
	newInstance := func() {
		vs = &viperStore{}
	}

	once.Do(newInstance)

	return vs
}
