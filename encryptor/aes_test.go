package encryptor

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"testing"
)

// TestNewAES ensures the AESCTREncryptor struct is correctly initialised.
func TestNewAES(t *testing.T) {
	tests := []struct {
		// Test description.
		name string
		// Parameters.
		aesKey  []byte
		hmacKey []byte
		// Expected results.
		want    AESCTREncryptor
		wantErr error
	}{
		{
			"Correct",
			[]byte("12345678901234567890123456789012"),
			[]byte("SECRETSM8"),
			AESCTREncryptor{
				aesKey:  []byte("12345678901234567890123456789012"),
				hmacKey: []byte("SECRETSM8"),
			},
			nil,
		},
		{
			"AES key required",
			[]byte{},
			[]byte("SECRETSM8"),
			AESCTREncryptor{},
			ErrKeyTooShort,
		},
		{
			"HMAC key required",
			[]byte("12345678901234567890123456789012"),
			[]byte{},
			AESCTREncryptor{},
			ErrHmacKeyTooShort,
		},
		{
			"Error with wrong AES key length",
			[]byte("short"),
			[]byte("SECRETSM8"),
			AESCTREncryptor{},
			ErrKeyTooShort,
		},
	}
	for _, tt := range tests {
		got, err := NewAES(tt.aesKey, tt.hmacKey)

		if err != tt.wantErr {
			t.Errorf("%q. NewAES() error = %v, wantErr %v", tt.name, err, tt.wantErr)
		}

		if err != nil {
			continue
		}

		if bytes.Compare(tt.want.aesKey, got.aesKey) != 0 {
			t.Errorf("%q. NewAES() easKey = %v, want %v", tt.name, got.aesKey, tt.want.aesKey)
		}

		if bytes.Compare(tt.want.hmacKey, got.hmacKey) != 0 {
			t.Errorf("%q. NewAES() easKey = %v, want %v", tt.name, got.hmacKey, tt.want.hmacKey)
		}
	}
}

// TestAesCTREncryptorIntegration ensures Encrypt() and Decrypt() work together
// to produce the same plain-text as the original input.
func TestAESCTREncryptorIntegration(t *testing.T) {
	tests := []struct {
		// Test description.
		name string
		// Parameters.
		want []byte
	}{
		{
			"Simple string",
			[]byte("i am a secret"),
		},
		{
			"Binary",
			[]byte{
				0xb0, 0x75, 0x11, 0x62, 0xa2, 0x3e, 0x5f, 0x2f,
				0xca, 0xa3, 0x00, 0x1d, 0x51, 0x89, 0xc8, 0xe7,
				0xb5, 0x15, 0xb9, 0x5c, 0x9b, 0x3e, 0x26, 0x5f,
				0xb2, 0x6b, 0x97, 0x41, 0x16, 0x2c, 0x47, 0x10,
			},
		},
	}

	for _, tt := range tests {
		e, err := NewAES([]byte("anAesTestKey1234"), []byte("hmacKey"))
		if err != nil {
			t.Errorf("%q. NewAES() = %s", tt.name, err)
			continue
		}

		encrypted, err := e.Encrypt(tt.want)
		if err != nil {
			t.Errorf("%q. Encrypt() = %s", tt.name, err)
			continue
		}

		got, err := e.Decrypt(encrypted)
		if err != nil {
			t.Errorf("%q. Decrypt() = %s", tt.name, err)
			continue
		}

		if !bytes.Equal(got, tt.want) {
			t.Errorf("%q. Secret mismatch, got %v, want %v", tt.name, string(got), string(tt.want))
		}
	}
}

// TestAESCTREncryptorEncrypt ensures the EncryptedData result has the correct
// HMAC, and the correct Type. Actual encrypted cipher-text is checked by the
// integration test.
func TestAESCTREncryptorEncrypt(t *testing.T) {
	tests := []struct {
		// Test description.
		name string
		// Parameters.
		aesKey  []byte
		hmacKey []byte
		secret  []byte
		// Expected results.
		wantErr bool
	}{
		{
			"Example",
			[]byte("iamakey!iamakey!"),
			[]byte("hmacKey"),
			[]byte("I am a super secret secret"),
			false,
		},
	}
	for _, tt := range tests {
		e, err := NewAES(tt.aesKey, tt.hmacKey)
		if err != nil {
			t.Errorf("%q. NewAES() error = %v", tt.name, err)
			continue
		}

		got, err := e.Encrypt(tt.secret)
		if (err != nil) != tt.wantErr {
			t.Errorf("%q. AESCTREncryptor.Encrypt() error = %v, wantErr %v", tt.name, err, tt.wantErr)
			continue
		}

		// Check type
		if got.Type != AESCTR {
			t.Errorf("%q. AESCTREncryptor.Encrypt() result type = %v, want %v", tt.name, got.Type, AESCTR)
		}

		// Check HMAC
		mac := hmac.New(sha256.New, tt.hmacKey)
		mac.Write(got.Ciphertext)
		if hmac := mac.Sum(nil); !bytes.Equal(hmac, got.HMAC) {
			t.Errorf("%q. AESCTREncryptor.Encrypt() HMAC = %v, want %v", tt.name, got.HMAC, hmac)
		}
	}
}

// TestAESCTREncryptorDecrypt ensures an error is returned if either the HMAC is
// invalid, or Decode() is passed a EncryptedData struct of the wrong type. We
// also check the correct secrets are returned from sample cipher-text.
func TestAESCTREncryptorDecrypt(t *testing.T) {
	tests := []struct {
		// Test description.
		name string
		// Parameters
		data *EncryptedData
		// Expected results.
		want           []byte
		wantDecryptErr error
		wantOutputErr  bool
	}{
		{
			"Known good",
			&EncryptedData{
				Ciphertext: []byte{
					0x50, 0xc7, 0x16, 0xf8, 0xe8, 0x26, 0x4a, 0xe1, 0xed, 0x1f, 0xe7, 0x82, 0xc2, 0x6f,
					0x41, 0xa3, 0x63, 0x17, 0x18, 0xd9, 0x04, 0x92, 0xbe, 0x68, 0x4d, 0xb3, 0x59, 0xbf,
					0x59, 0x9d, 0xef, 0x3b, 0x92, 0x99, 0x12, 0x3f, 0xc6, 0x59, 0xd9, 0x81, 0xad, 0x78,
				},
				HMAC: []byte{
					0xe8, 0xda, 0xfc, 0x58, 0x5a, 0x84, 0x27, 0x97, 0x13, 0x39, 0x04, 0x7c, 0x85, 0x8e, 0x10, 0xc4,
					0x88, 0x4d, 0x2e, 0xfe, 0x90, 0x5f, 0xc1, 0x8d, 0x93, 0xf5, 0xe5, 0xb4, 0x8a, 0xc5, 0xd6, 0xca,
				},
				Type: AESCTR,
			},
			[]byte("I am a super secret secret"),
			nil,
			false,
		},
		{
			"Wrong Encryptor type",
			&EncryptedData{
				Ciphertext: []byte{
					0x50, 0xc7, 0x16, 0xf8, 0xe8, 0x26, 0x4a, 0xe1, 0xed, 0x1f, 0xe7, 0x82, 0xc2, 0x6f,
					0x41, 0xa3, 0x63, 0x17, 0x18, 0xd9, 0x04, 0x92, 0xbe, 0x68, 0x4d, 0xb3, 0x59, 0xbf,
					0x59, 0x9d, 0xef, 0x3b, 0x92, 0x99, 0x12, 0x3f, 0xc6, 0x59, 0xd9, 0x81, 0xad, 0x78,
				},
				HMAC: []byte{
					0xe8, 0xda, 0xfc, 0x58, 0x5a, 0x84, 0x27, 0x97, 0x13, 0x39, 0x04, 0x7c, 0x85, 0x8e, 0x10, 0xc4,
					0x88, 0x4d, 0x2e, 0xfe, 0x90, 0x5f, 0xc1, 0x8d, 0x93, 0xf5, 0xe5, 0xb4, 0x8a, 0xc5, 0xd6, 0xca,
				},
				Type: Nop,
			},
			[]byte{},
			ErrWrongType,
			false,
		},
		{
			"Cipher-text too short (no IV)",
			&EncryptedData{
				Ciphertext: []byte{0x42},
				HMAC: []byte{
					0xe8, 0xda, 0xfc, 0x58, 0x5a, 0x84, 0x27, 0x97, 0x13, 0x39, 0x04, 0x7c, 0x85, 0x8e, 0x10, 0xc4,
					0x88, 0x4d, 0x2e, 0xfe, 0x90, 0x5f, 0xc1, 0x8d, 0x93, 0xf5, 0xe5, 0xb4, 0x8a, 0xc5, 0xd6, 0xca,
				},
				Type: AESCTR,
			},
			[]byte{},
			ErrInvalidHmac,
			false,
		},
		{
			"Bad HMAC",
			&EncryptedData{
				Ciphertext: []byte{
					0x50, 0xc7, 0x16, 0xf8, 0xe8, 0x26, 0x4a, 0xe1, 0xed, 0x1f, 0xe7, 0x82, 0xc2, 0x6f,
					0x41, 0xa3, 0x63, 0x17, 0x18, 0xd9, 0x04, 0x92, 0xbe, 0x68, 0x4d, 0xb3, 0x59, 0xbf,
					0x59, 0x9d, 0xef, 0x3b, 0x92, 0x99, 0x12, 0x3f, 0xc6, 0x59, 0xd9, 0x81, 0xad, 0x78,
				},
				HMAC: []byte{
					0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
					0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
				},
				Type: AESCTR,
			},
			[]byte{},
			ErrInvalidHmac,
			false,
		},
		{
			"Wrong plain-text",
			&EncryptedData{
				Ciphertext: []byte{
					0x50, 0xc7, 0x16, 0xf8, 0xe8, 0x26, 0x4a, 0xe1, 0xed, 0x1f, 0xe7, 0x82, 0xc2, 0x6f,
					0x41, 0xa3, 0x63, 0x17, 0x18, 0xd9, 0x04, 0x92, 0xbe, 0x68, 0x4d, 0xb3, 0x59, 0xbf,
					0x59, 0x9d, 0xef, 0x3b, 0x92, 0x99, 0x12, 0x3f, 0xc6, 0x59, 0xd9, 0x81, 0xad, 0x78,
				},
				HMAC: []byte{
					0xe8, 0xda, 0xfc, 0x58, 0x5a, 0x84, 0x27, 0x97, 0x13, 0x39, 0x04, 0x7c, 0x85, 0x8e, 0x10, 0xc4,
					0x88, 0x4d, 0x2e, 0xfe, 0x90, 0x5f, 0xc1, 0x8d, 0x93, 0xf5, 0xe5, 0xb4, 0x8a, 0xc5, 0xd6, 0xca,
				},
				Type: AESCTR,
			},
			[]byte("wrong plain-text"),
			nil,
			true,
		},
	}
	for _, tt := range tests {
		e, err := NewAES([]byte("iamakey!iamakey!"), []byte("hmacKey"))
		if err != nil {
			t.Errorf("%q. NewAES() error = %v", tt.name, err)
			continue
		}

		got, err := e.Decrypt(tt.data)
		if err != tt.wantDecryptErr {
			t.Errorf("%q. AESCTREncryptor.Decrypt() error = %v, wantDecryptErr %v", tt.name, err, tt.wantDecryptErr)
			continue
		}

		if tt.wantOutputErr == bytes.Equal(tt.want, got) {
			t.Errorf("%q. AESCTREncryptor.Decrypt() got = %v, want %v", tt.name, got, tt.want)
			continue
		}
	}
}
