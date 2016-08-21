package encryptor

import "errors"

var (
	// ErrWrongType indicates a EncryptedData struct was created with a
	// different Encryptor than what is being used to decrypt.
	ErrWrongType = errors.New("encryptor: wrong encryptor type")

	// ErrInvalidHmac indicates message authentication has failed.
	ErrInvalidHmac = errors.New("encryptor: invalid HMAC")

	// ErrKeyTooShort indicates the encryption key provided is too short to be
	// useful.
	ErrKeyTooShort = errors.New("encryptor: key provided is too short")

	// ErrHmacKeyTooShort indicates the HMAC key is too short to be useful.
	ErrHmacKeyTooShort = errors.New("encryptor: HMAC key is required")

	//ErrInvalidCiphertext indicates the ciphertext cannot be decrypted.
	ErrInvalidCiphertext = errors.New("encryptor: invalid ciphertext")

	// ErrMissingContext indicates required contextual data is missing.
	ErrMissingContext = errors.New("encryptor: missing required context data")
)
