package encryptor

// NopEncryptor returns a EncryptedData struct that's not encrypted in any way
// for development purposes.
//
// It does nothing! It should not be used for production, obviously.
type NopEncryptor struct{}

// Encrypt does nothing! It simply returns an initalised EncryptedData struct
// with NO ENCRYPTION.
//
// Don't use it for anything other than tests. Seriously.
func (e NopEncryptor) Encrypt(secret []byte) (*EncryptedData, error) {
	return &EncryptedData{
		Ciphertext: secret,
		HMAC:       []byte("--ignored--"),
		Type:       Nop,
	}, nil
}

// Decrypt extracts the plain-text secret from data
func (e NopEncryptor) Decrypt(data *EncryptedData) ([]byte, error) {
	return data.Ciphertext, nil
}
