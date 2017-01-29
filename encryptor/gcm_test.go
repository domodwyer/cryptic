package encryptor

import (
	"bytes"
	"testing"
)

// TestNewAESGCM ensures invalid input returns the correct error types.
func TestNewAESGCM(t *testing.T) {
	tests := []struct {
		// Test description.
		name string
		// Parameters.
		aesKey []byte
		// Expected results.
		wantErr error
	}{
		{
			"Correct",
			[]byte("12345678901234567890123456789012"),
			nil,
		},
		{
			"AES key required",
			[]byte{},
			ErrKeyTooShort,
		},
		{
			"Error with wrong AES key length",
			[]byte("short"),
			ErrKeyTooShort,
		},
	}
	for _, tt := range tests {
		_, err := NewAESGCM(tt.aesKey)

		if err != tt.wantErr {
			t.Errorf("%q. NewAESGCM() error = %v, wantErr %v", tt.name, err, tt.wantErr)
		}
	}
}

// TestAesGCMEncryptorIntegration ensures Encrypt() and Decrypt() work together
// to produce the same plain-text as the original input.
func TestAESGCMEncryptorIntegration(t *testing.T) {
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
		e, err := NewAESGCM([]byte("anAesTestKey1234"))
		if err != nil {
			t.Errorf("%q. NewAESGCM() = %s", tt.name, err)
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

// TestAESGCMEncrypt ensures the EncryptedData returned from Encrypt() has the
// correct attributes set.
func TestAESGCMEncryptorEncrypt(t *testing.T) {
	e, err := NewAESGCM([]byte("anAesTestKey1234"))
	if err != nil {
		t.Fatalf("Encrypt. NewAESGCM() = %s", err)
	}

	encrypted, err := e.Encrypt([]byte("i am a secret"))
	if err != nil {
		t.Fatalf("Encrypt. Encrypt() = %s", err)
	}

	if encrypted.Type != AESGCM {
		t.Fatalf("Type. Encrypt() got = %v, want %v", encrypted.Type, AESGCM)
	}
}

// TestAESGCMEncryptorDecrypt ensures an error is returned if either the HMAC is
// invalid, or Decode() is passed a EncryptedData struct of the wrong type. We
// also check the correct secrets are returned from sample cipher-text.
func TestAESGCMEncryptorDecrypt(t *testing.T) {
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
					0xef, 0x49, 0x98, 0x28, 0xd1, 0x45, 0x99, 0xa9, 0xf6, 0x79, 0x06, 0x3d, 0x76, 0xec,
					0x0f, 0xc7, 0xfb, 0x2b, 0x2b, 0xe9, 0xd3, 0xcf, 0x6e, 0xa2, 0xed, 0x7f, 0x10, 0x70,
					0x4f, 0x01, 0xce, 0x9f, 0x18, 0x7a, 0x67, 0xc7, 0xb4, 0x6e, 0x91, 0x45, 0x60,
				},
				Type: AESGCM,
			},
			[]byte("it's a secret"),
			nil,
			false,
		},
		{
			"Wrong Encryptor type",
			&EncryptedData{
				Ciphertext: []byte{
					0xef, 0x49, 0x98, 0x28, 0xd1, 0x45, 0x99, 0xa9, 0xf6, 0x79, 0x06, 0x3d, 0x76, 0xec,
					0x0f, 0xc7, 0xfb, 0x2b, 0x2b, 0xe9, 0xd3, 0xcf, 0x6e, 0xa2, 0xed, 0x7f, 0x10, 0x70,
					0x4f, 0x01, 0xce, 0x9f, 0x18, 0x7a, 0x67, 0xc7, 0xb4, 0x6e, 0x91, 0x45, 0x60,
				},
				Type: Nop,
			},
			[]byte{},
			ErrWrongType,
			false,
		},
		{
			"Cipher-text too short (no nonce)",
			&EncryptedData{
				Ciphertext: []byte{0x42},
				Type:       AESGCM,
			},
			[]byte{},
			ErrInvalidCiphertext,
			false,
		},
		{
			"Wrong plain-text",
			&EncryptedData{
				Ciphertext: []byte{
					0xef, 0x49, 0x98, 0x28, 0xd1, 0x45, 0x99, 0xa9, 0xf6, 0x79, 0x06, 0x3d, 0x76, 0xec,
					0x0f, 0xc7, 0xfb, 0x2b, 0x2b, 0xe9, 0xd3, 0xcf, 0x6e, 0xa2, 0xed, 0x7f, 0x10, 0x70,
					0x4f, 0x01, 0xce, 0x9f, 0x18, 0x7a, 0x67, 0xc7, 0xb4, 0x6e, 0x91, 0x45, 0x60,
				},
				Type: AESGCM,
			},
			[]byte("wrong plain-text"),
			nil,
			true,
		},
	}
	for _, tt := range tests {
		e, err := NewAESGCM([]byte("anAesTestKey1234"))
		if err != nil {
			t.Errorf("%q. NewAESGCM() error = %v", tt.name, err)
			continue
		}

		got, err := e.Decrypt(tt.data)
		if err != tt.wantDecryptErr {
			t.Errorf("%q. AESGCMEncryptor.Decrypt() error = %v, wantDecryptErr %v", tt.name, err, tt.wantDecryptErr)
			continue
		}

		if tt.wantOutputErr == bytes.Equal(tt.want, got) {
			t.Errorf("%q. AESGCMEncryptor.Decrypt() got = %v, want %v", tt.name, got, tt.want)
			continue
		}
	}
}
