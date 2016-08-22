package encryptor

import (
	"bytes"
	"encoding/gob"
)

// EncryptedData holds the result of a call to Encrypt(), where Ciphertext is
// the encrypted input, HMAC is the Encryptor-designated hash (typically SHA512)
// of Ciphertext, and Context provides Encryptor-specific information for
// decryption.
//
// Context should not hold any secret information, as the entire EncryptedData
// struct is stored in plain-text by the storage back-end.
type EncryptedData struct {
	Ciphertext []byte
	HMAC       []byte
	Type       uint8
	Context    map[string]interface{}
}

func init() {
	gob.Register(kdfParameters{})
}

// MarshalBinary returns the EncryptedData struct encoded into a slice of bytes
// using Gob.
func (e EncryptedData) MarshalBinary() ([]byte, error) {
	buf := bytes.Buffer{}
	enc := gob.NewEncoder(&buf)

	if err := enc.Encode(e.Ciphertext); err != nil {
		return nil, err
	}

	if err := enc.Encode(e.HMAC); err != nil {
		return nil, err
	}

	if err := enc.Encode(e.Type); err != nil {
		return nil, err
	}

	if err := enc.Encode(e.Context); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// UnmarshalBinary returns an EncryptedData struct decoded from a slice of bytes
// using Gob.
func (e *EncryptedData) UnmarshalBinary(data []byte) error {
	dec := gob.NewDecoder(bytes.NewReader(data))

	if err := dec.Decode(&e.Ciphertext); err != nil {
		return err
	}

	if err := dec.Decode(&e.HMAC); err != nil {
		return err
	}

	if err := dec.Decode(&e.Type); err != nil {
		return err
	}

	if err := dec.Decode(&e.Context); err != nil {
		return err
	}

	return nil
}
