package shared

import (
	"errors"

	"github.com/domodwyer/cryptic/config"
	"github.com/domodwyer/cryptic/encryptor"
)

// GetEncryptor returns a concrete type that implements EncryptDecryptor based
// on the configured Encryptor value in the config file.
func GetEncryptor(config config.Encryptor) (encryptor.EncryptDecryptor, error) {
	var enc encryptor.EncryptDecryptor
	var err error

	switch config.Encryptor() {
	case "aes":
		enc, err = encryptor.NewAES([]byte(config.AESKey()), []byte(config.AESHmacKey()))

	case "kms":
		if config.KMSKeyID() == "" {
			err = errors.New("kms: No key ID set")
		} else {
			enc = encryptor.NewKMS(config.KMSKeyID(), config.KMSRegion())
		}

	default:
		err = errors.New("unknown decryptor")
	}

	if err != nil {
		return nil, err
	}

	return enc, nil
}
