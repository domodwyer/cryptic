package encryptor

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
)

// AESGCMEncryptor provides AES encryption of secrets using GCM (Galois Counter
// Mode) to ensure data integrity.
type AESGCMEncryptor struct {
	gcm cipher.AEAD
}

// NewAESGCM returns an initalised Encryptor using AES with GCM (Galois Counter
// Mode) to ensure data integrity.
func NewAESGCM(aesKey []byte) (*AESGCMEncryptor, error) {
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, ErrKeyTooShort
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		// This will never happen, AES uses 128-bit blocks
		return nil, err
	}

	return &AESGCMEncryptor{gcm: gcm}, nil
}

// Encrypt generates a unique nonce for each encryption, and encrypts the
// plain-text secret with the configured AES key.
func (e *AESGCMEncryptor) Encrypt(plaintext []byte) (*EncryptedData, error) {
	// Generate a random nonce
	nonce := make([]byte, e.gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		// No entropy? You've got bigger problems
		return nil, err
	}

	// Encrypt, appending the ciphertext to the nonce slice
	return &EncryptedData{
		Ciphertext: e.gcm.Seal(nonce, nonce, plaintext, nil),
		Type:       AESGCM,
	}, nil
}

// Decrypt ensures data was encrypted with AESGCMEncryptor before decrypting the
// cipher-text (which also ensures data integrity) and returning the plain-text.
func (e *AESGCMEncryptor) Decrypt(data *EncryptedData) ([]byte, error) {
	// Ensure we're operating on something that AESGCMEncryptor encrypted
	if data.Type != AESGCM {
		return nil, ErrWrongType
	}

	// Ensure our input slice is at least gcm.NonceSize() to avoid an
	// out-of-bounds access
	if len(data.Ciphertext) < e.gcm.NonceSize() {
		return nil, ErrInvalidCiphertext
	}

	return e.gcm.Open(
		nil,
		data.Ciphertext[:e.gcm.NonceSize()],
		data.Ciphertext[e.gcm.NonceSize():],
		nil,
	)
}
