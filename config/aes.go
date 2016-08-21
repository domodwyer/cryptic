package config

import "github.com/spf13/viper"

// AES defines config getters for the AES Encryptor parameters.
type AES interface {
	AESKey() string
	AESHmacKey() string
}

// AESKey returns the configured AES key.
func (v viperStore) AESKey() string {
	return viper.GetString("AES.Key")
}

// AESHmacKey returns the configured HMAC key used by the AES encryptor.
func (v viperStore) AESHmacKey() string {
	return viper.GetString("AES.HmacKey")
}
