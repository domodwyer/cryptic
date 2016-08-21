package config

import (
	"strings"

	"github.com/spf13/viper"
)

// SelectedStore defines config getters for the Store type.
type SelectedStore interface {
	Store() string
}

// Store returns the configued Store type name.
func (v viperStore) Store() string {
	return strings.ToLower(viper.GetString("Store"))
}
