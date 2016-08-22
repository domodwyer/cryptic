package encryptor

import (
	"crypto/rand"
	"crypto/sha512"

	"golang.org/x/crypto/pbkdf2"
)

const kdfKeySize = 64

type KDF struct {
	Provider   EncryptionProvider
	SaltSize   int
	Iterations int
	SourceKey  []byte
}

type kdfParameters struct {
	Salt       []byte
	OrigType   uint8
	Iterations int
}

func NewKDF(sourceKey []byte) (*KDF, error) {
	if len(sourceKey) < 1 {
		return nil, ErrKeyTooShort
	}

	builder := func(key []byte) (EncryptDecryptor, error) {
		return NewAES(key[:32], key[32:])
	}

	return &KDF{
		Provider:   builder,
		SaltSize:   16,
		Iterations: 4096,
		SourceKey:  sourceKey,
	}, nil
}

func (e KDF) Encrypt(secret []byte) (*EncryptedData, error) {
	// Get a random salt
	salt := make([]byte, e.SaltSize)
	_, err := rand.Read(salt)
	if err != nil {
		// No entropy? You've got bigger problems
		return nil, err
	}

	// Derive a key
	key := pbkdf2.Key(e.SourceKey, salt, e.Iterations, kdfKeySize, sha512.New)

	// Get a new encryptor using the provided key
	enc, err := e.Provider(key)
	if err != nil {
		return nil, err
	}

	// Let our encryption provider do it's thing
	data, err := enc.Encrypt(secret)
	if err != nil {
		return nil, err
	}

	if data.Context == nil {
		data.Context = map[string]interface{}{}
	}

	p := kdfParameters{
		Salt:       salt,
		Iterations: e.Iterations,
		OrigType:   data.Type,
	}

	// Store the original Encryptor type in the context
	data.Context["kdf"] = p
	data.Type = Pbkdf2

	return data, nil
}

func (e KDF) Decrypt(data *EncryptedData) ([]byte, error) {
	// Ensure this data used KDF
	if data.Type != Pbkdf2 {
		return []byte{}, ErrWrongType
	}

	// Extract the KDF context
	ctxInt, ok := data.Context["kdf"]
	if !ok {
		return []byte{}, ErrMissingContext
	}

	ctx, ok := ctxInt.(kdfParameters)
	if !ok {
		return []byte{}, ErrMissingContext
	}

	// Generate the key
	key := pbkdf2.Key(e.SourceKey, ctx.Salt, ctx.Iterations, kdfKeySize, sha512.New)

	// Give it to the decryption provider
	dec, err := e.Provider(key)
	if err != nil {
		return []byte{}, err
	}

	// Get a mutable copy of data so we don't alter the original and replace the type
	mutable := *data
	mutable.Type = ctx.OrigType

	return dec.Decrypt(&mutable)
}
