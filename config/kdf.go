package config

import "github.com/spf13/viper"

// AES defines config getters for the AES Encryptor parameters.
type KDF interface {
	KDFKey() string
}

// KDFKey returns the configured KDF key.
func (v viperStore) KDFKey() string {
	return viper.GetString("AES.Key")
}
