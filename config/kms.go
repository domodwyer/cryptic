package config

import "github.com/spf13/viper"

// KMS defines config getters for the KMS Encryptor parameters.
type KMS interface {
	KMSKeyID() string
	KMSRegion() string
}

// KMSKeyID returns the configured KMS key ID.
func (v viperStore) KMSKeyID() string {
	return viper.GetString("KMS.KeyID")
}

// KMSRegion returns the configured AWS region used for calls to KMS.
func (v viperStore) KMSRegion() string {
	return viper.GetString("KMS.Region")
}
