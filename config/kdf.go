package config

import "github.com/spf13/viper"

// KDF defines the configuration options for PBKDF2 support
type KDF interface {
	KDFKey() string
}

// KDFKey returns the configured KDF key.
func (v viperStore) KDFKey() string {
	return viper.GetString("AES.Key")
}
