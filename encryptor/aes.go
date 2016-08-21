package encryptor

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"io"
)

// AESCTREncryptor provides AES encryption of secrets with SHA-512 used for
// message authentication.
type AESCTREncryptor struct {
	aesKey  []byte
	hmacKey []byte
	block   cipher.Block
}

// NewAES returns an initialised Encryptor using AES in CTR (counter) mode and
// SHA-512 for message authentication.
func NewAES(aesKey, hmacKey []byte) (*AESCTREncryptor, error) {
	if len(hmacKey) == 0 {
		return nil, ErrHmacKeyTooShort
	}

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, ErrKeyTooShort
	}

	return &AESCTREncryptor{
		aesKey:  aesKey,
		hmacKey: hmacKey,
		block:   block,
	}, nil
}

// Encrypt generates a unique IV for each encryption, and encrypts the
// plain-text secret with the configured AES key.
//
// A HMAC is then generated using SHA256 with the configured HMAC key.
func (e *AESCTREncryptor) Encrypt(secret []byte) (*EncryptedData, error) {
	ciphertext := make([]byte, aes.BlockSize+len(secret))

	// Generate a random IV
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		// No entropy? You've got bigger problems
		return nil, err
	}

	stream := cipher.NewCTR(e.block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], secret)

	// Generate our HMAC
	mac := hmac.New(sha256.New, e.hmacKey)
	mac.Write(ciphertext)

	return &EncryptedData{
		Ciphertext: ciphertext,
		HMAC:       mac.Sum(nil),
		Type:       AESCTR,
	}, nil
}

// Decrypt checks data has been created previously by AESCTREncryptor, validates
// the HMAC in constant time to prevent a timing side-channel attack (and detect
// any corruption of the ciphertext), and decrypts the cipher-text, returning
// the original plain-text.
func (e *AESCTREncryptor) Decrypt(data *EncryptedData) ([]byte, error) {
	// Ensure we're operating on something that AESCTREncryptor encrypted, and
	// not data from something else
	if data.Type != AESCTR {
		return nil, ErrWrongType
	}

	mac := hmac.New(sha256.New, e.hmacKey)
	mac.Write(data.Ciphertext)

	// Ensure the HMAC matches what we were expecting, use constant time
	// comparison
	if !hmac.Equal(mac.Sum(nil), data.HMAC) {
		return nil, ErrInvalidHmac
	}

	// Extract the IV
	if len(data.Ciphertext) < aes.BlockSize {
		return nil, ErrInvalidCiphertext
	}

	iv := data.Ciphertext[:aes.BlockSize]
	buf := data.Ciphertext[aes.BlockSize:]

	stream := cipher.NewCTR(e.block, iv)
	stream.XORKeyStream(buf, buf)

	return buf, nil
}
