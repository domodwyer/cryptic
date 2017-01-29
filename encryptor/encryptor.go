package encryptor

// Used to identify different Encryptor types
const (
	Nop uint8 = iota
	AESCTR
	KMSWrapped
	Pbkdf2
	AESGCM
)

// Encryptor defines the Encrypt method, used to encrypt the given plain-text.
type Encryptor interface {
	Encrypt(secret []byte) (*EncryptedData, error)
}

// Decryptor defines the Decrypt method, used to decrypt the given cipher-text.
type Decryptor interface {
	Decrypt(data *EncryptedData) ([]byte, error)
}

// EncryptDecryptor defines the methods used by our encryptor structs.
type EncryptDecryptor interface {
	Encryptor
	Decryptor
}

// EncryptionProvider implementers should return an initalised Encryptor where
// key is the key material for initalisation.
type EncryptionProvider func(key []byte) (EncryptDecryptor, error)
