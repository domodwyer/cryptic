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

	case "aes-gcm-pbkdf2":
		enc, err := encryptor.NewKDF([]byte(config.KDFKey()))
		if err != nil {
			return nil, err
		}

		// Set the encryption provider to AESGCM
		enc.Provider = func(key []byte) (encryptor.EncryptDecryptor, error) {
			return encryptor.NewAESGCM(key[:32])
		}

		return enc, nil

	case "aes-gcm":
		return encryptor.NewAESGCM([]byte(config.AESKey()))

	case "kms":
		if config.KMSKeyID() == "" {
			return nil, errors.New("kms: No key ID set")
		}
		return encryptor.NewKMS(config.KMSKeyID(), config.KMSRegion()), nil

	default:
		return nil, errors.New("unknown decryptor")
	}
}
