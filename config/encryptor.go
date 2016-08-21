package config

import (
	"strings"

	"github.com/spf13/viper"
)

// SelectedEncryptor defines config getters for the Encryptor type.
type SelectedEncryptor interface {
	Encryptor() string
}

// Encryptor returns the configued Encryptor type name.
func (v viperStore) Encryptor() string {
	return strings.ToLower(viper.GetString("Encryptor"))
}
