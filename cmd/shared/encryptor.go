package shared

import (
	"errors"

	"github.com/domodwyer/cryptic/config"
	"github.com/domodwyer/cryptic/encryptor"
)

// GetEncryptor returns a concrete type that implements EncryptDecryptor based
// on the configured Encryptor value in the config file.
func GetEncryptor(config config.Encryptor) (encryptor.EncryptDecryptor, error) {
	switch config.Encryptor() {
	case "aes-pbkdf2":
		return encryptor.NewKDF([]byte(config.KDFKey()))

	case "aes":
		return encryptor.NewAES([]byte(config.AESKey()), []byte(config.AESHmacKey()))


	case "kms":
		if config.KMSKeyID() == "" {
			return nil, errors.New("kms: No key ID set")
		}
		return encryptor.NewKMS(config.KMSKeyID(), config.KMSRegion()), nil

	default:
		return nil, errors.New("unknown decryptor")
	}
}
