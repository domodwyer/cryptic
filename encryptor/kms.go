package encryptor

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"
)

// KMS is used to wrap the output of any other Encryptor using Amazon KMS, by
// default using AES-256.
type KMS struct {
	svc      kmsInterface
	keyID    string
	KeySize  int64
	Provider EncryptionProvider
}

// EncryptionProvider implementers should return an initalised Encryptor where
// key is the unwrapped key material for initalisation.
type EncryptionProvider func(key []byte) (EncryptDecryptor, error)

type kmsInterface interface {
	GenerateDataKey(input *kms.GenerateDataKeyInput) (*kms.GenerateDataKeyOutput, error)
	Decrypt(input *kms.DecryptInput) (*kms.DecryptOutput, error)
}

// NewKMS returns an initialised Encryptor using Amazon KMS to wrap the
// underlying Encryptor's keys used to encrypt secrets.
//
// By default, KMS uses AESCTREncryptor with a 32 byte key (AES-256).
func NewKMS(keyID, region string) *KMS {

	// By default, we use AES-256, which takes a 32 byte key, and we use the
	// rest for the HMAC key

	builder := func(key []byte) (EncryptDecryptor, error) {
		// Ensure we have at least a 64 byte key to split
		if len(key) < 64 {
			return nil, ErrKeyTooShort
		}

		return NewAES(key[:32], key[32:])
	}

	return &KMS{
		svc:      kms.New(session.New(), &aws.Config{Region: aws.String(region)}),
		keyID:    keyID,
		KeySize:  64,
		Provider: builder,
	}
}

// Encrypt generates a new encryption key using Amazon KMS, passing it to the
// configured EncryptionProvider as the encryption key to encrypt the secret.
func (e *KMS) Encrypt(secret []byte) (*EncryptedData, error) {
	// Ask KMS for a 64 byte encryption key
	resp, err := e.svc.GenerateDataKey(&kms.GenerateDataKeyInput{
		KeyId:         &e.keyID,
		NumberOfBytes: aws.Int64(e.KeySize),
	})
	if err != nil {
		return nil, err
	}

	// Get a new encryptor using the provided key
	enc, err := e.Provider(resp.Plaintext)
	if err != nil {
		return nil, err
	}

	// Let our encryption provider do it's thing
	data, err := enc.Encrypt(secret)
	if err != nil {
		return nil, err
	}

	// Now data holds an EncryptedData struct, but we need to mutate it before
	// returning - change the Type and add our contextual info

	if data.Context == nil {
		data.Context = map[string]interface{}{}
	}

	// Store the original Encryptor type in the context
	data.Context["kms_type"] = data.Type
	data.Type = KMSWrapped

	// Store our KMS wrapped key in the context
	data.Context["kms_key"] = resp.CiphertextBlob

	return data, nil
}

// Decrypt decrypts the embedded encyption key using Amazon KMS, and then passes
// the plain-text key to the EncryptionProvider to decrypt the secret.
func (e *KMS) Decrypt(data *EncryptedData) ([]byte, error) {
	// Ensure this data was wrapped
	if data.Type != KMSWrapped {
		return []byte{}, ErrWrongType
	}

	// Extract the encrypted key
	kmsKeyInt, ok := data.Context["kms_key"]
	if !ok {
		return []byte{}, ErrMissingContext
	}

	kmsKey, ok := kmsKeyInt.([]byte)
	if !ok {
		return []byte{}, ErrMissingContext
	}

	// Extract the orignal type early so we can avoid calling KMS unless we're
	// good to go
	origTypeInt, ok := data.Context["kms_type"]
	if !ok {
		return []byte{}, ErrMissingContext
	}

	origType, ok := origTypeInt.(uint8)
	if !ok {
		return []byte{}, ErrMissingContext
	}

	// Decrypt the key
	resp, err := e.svc.Decrypt(&kms.DecryptInput{CiphertextBlob: kmsKey})
	if err != nil {
		return []byte{}, err
	}

	// Feed the key back into our Decryptor
	dec, err := e.Provider(resp.Plaintext)
	if err != nil {
		return []byte{}, err
	}

	// Get a mutable copy of data so we don't alter the original and replace the type
	mutable := *data
	mutable.Type = origType

	return dec.Decrypt(&mutable)
}
