package encryptor

import (
	"bytes"
	"reflect"
	"testing"
)

// TestAESKDFEncryptorIntegration ensures a key is generated, secret encrypted
// with AES, and decrypted to the same plaintext
func TestAESKDFEncryptorIntegration(t *testing.T) {
	tests := []struct {
		// Test description.
		name string
		// Parameters.
		want []byte
		skey []byte
	}{
		{
			"Simple string",
			[]byte("i am a secret"),
			[]byte("smallkey!"),
		},
		{
			"Binary",
			[]byte{
				0xb0, 0x75, 0x11, 0x62, 0xa2, 0x3e, 0x5f, 0x2f,
				0xca, 0xa3, 0x00, 0x1d, 0x51, 0x89, 0xc8, 0xe7,
				0xb5, 0x15, 0xb9, 0x5c, 0x9b, 0x3e, 0x26, 0x5f,
				0xb2, 0x6b, 0x97, 0x41, 0x16, 0x2c, 0x47, 0x10,
			},
			[]byte{0x42},
		},
	}

	for _, tt := range tests {
		e, err := NewKDF(tt.skey)
		if err != nil {
			t.Errorf("%q. NewKDF() = %s", tt.name, err)
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
			t.Errorf("%q. Secret mismatch, got %v, want %v", tt.name, got, tt.want)
		}
	}
}

// TestAESGCMKDFEncryptorIntegration ensures a key is generated, secret
// encrypted with AESGCM, and decrypted to the same plaintext.
func TestAESGCMKDFEncryptorIntegration(t *testing.T) {
	tests := []struct {
		// Test description.
		name string
		// Parameters.
		want []byte
		skey []byte
	}{
		{
			"Simple string",
			[]byte("i am a secret"),
			[]byte("smallkey!"),
		},
		{
			"Binary",
			[]byte{
				0xb0, 0x75, 0x11, 0x62, 0xa2, 0x3e, 0x5f, 0x2f,
				0xca, 0xa3, 0x00, 0x1d, 0x51, 0x89, 0xc8, 0xe7,
				0xb5, 0x15, 0xb9, 0x5c, 0x9b, 0x3e, 0x26, 0x5f,
				0xb2, 0x6b, 0x97, 0x41, 0x16, 0x2c, 0x47, 0x10,
			},
			[]byte{0x42},
		},
	}

	for _, tt := range tests {
		e, err := NewKDF(tt.skey)
		e.Provider = func(key []byte) (EncryptDecryptor, error) {
			return NewAESGCM(key[:32])
		}

		if err != nil {
			t.Errorf("%q. NewKDF() = %s", tt.name, err)
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
			t.Errorf("%q. Secret mismatch, got %v, want %v", tt.name, got, tt.want)
		}
	}
}

// Ensure errors are passed up to the caller
func TestKDFEncrypt(t *testing.T) {
	tests := []struct {
		// Test description.
		name string
		// Receiver fields.
		rProvider  EncryptionProvider
		rSourceKey []byte
		// Parameters.
		secret []byte
		// Expected results.
		wantErr error
	}{
		{
			"Known good",
			func(key []byte) (EncryptDecryptor, error) {
				return NopEncryptor{}, nil
			},
			[]byte("key"),
			[]byte("secret"),
			nil,
		},
		{
			"Encryptor initalise errors passed up",
			func(key []byte) (EncryptDecryptor, error) {
				return nil, errMarker
			},
			[]byte("key"),
			[]byte("secret"),
			errMarker,
		},
		{
			"Encryptor Encrypt() errors passed up",
			func(key []byte) (EncryptDecryptor, error) {
				return &errEncryptor{errMarker}, nil
			},
			[]byte("key"),
			[]byte("secret"),
			errMarker,
		},
	}
	for _, tt := range tests {
		e := KDF{
			Provider:   tt.rProvider,
			SaltSize:   16,
			Iterations: 32, // small for testing
			SourceKey:  tt.rSourceKey,
		}
		got, err := e.Encrypt(tt.secret)
		if err != tt.wantErr {
			t.Errorf("%q. KDF.Encrypt() error = %v, wantErr %v", tt.name, err, tt.wantErr)
			continue
		}
		if err != nil {
			continue
		}

		if !bytes.Equal(got.Ciphertext, tt.secret) {
			t.Errorf("%q. KDF.Encrypt() = %v, want %v", tt.name, got.Ciphertext, tt.secret)
		}

		if got.Type != Pbkdf2 {
			t.Errorf("%q. KDF.Encrypt() type = %v, want %v", tt.name, got.Type, Pbkdf2)
		}

		if got.Context == nil {
			t.Errorf("%q. KDF.Encrypt() context map = %v", tt.name, got.Context)
			continue
		}

		ctxInt, ok := got.Context["kdf"]
		if !ok {
			t.Errorf("%q. KDF.Encrypt() context = %v", tt.name, nil)
			continue
		}

		ctx, ok := ctxInt.(kdfParameters)
		if !ok {
			t.Errorf("%q. KDF.Encrypt() context = %T", tt.name, ctxInt)
			continue
		}

		if ctx.OrigType != Nop {
			t.Errorf("%q. KDF.Encrypt() OrigType = %v, want %v", tt.name, ctx.OrigType, Nop)
		}

		if ctx.Iterations != 32 {
			t.Errorf("%q. KDF.Encrypt() Iterations = %v, want %v", tt.name, ctx.Iterations, 32)
		}

		if len(ctx.Salt) != 16 {
			t.Errorf("%q. KDF.Encrypt() len(Salt) = %v, want %v", tt.name, len(ctx.Salt), 16)
		}
	}
}

func TestKDFDecrypt(t *testing.T) {
	tests := []struct {
		// Test description.
		name string
		// Receiver fields.
		rProvider  EncryptionProvider
		rSourceKey []byte
		// Parameters.
		data *EncryptedData
		// Expected results.
		want    []byte
		wantErr error
	}{
		{
			"Known good - NOP",
			func(key []byte) (EncryptDecryptor, error) {
				return NopEncryptor{}, nil
			},
			[]byte("key"),
			&EncryptedData{
				Ciphertext: []byte("secret"),
				HMAC:       []byte("--ignored--"),
				Type:       Pbkdf2,
				Context: map[string]interface{}{
					"kdf": kdfParameters{
						Salt: []byte{
							0xbf, 0x19, 0x6d, 0x5e, 0xc6, 0xa0, 0x70, 0x5b,
							0x45, 0xff, 0x36, 0x04, 0xf7, 0xa3, 0x3f, 0xd5,
						},
						Iterations: 32,
						OrigType:   Nop,
					},
				},
			},
			[]byte("secret"),
			nil,
		},
		{
			"Known good - AES",
			func(key []byte) (EncryptDecryptor, error) {
				return NewAES(key[:32], key[32:])
			},
			[]byte("key"),
			&EncryptedData{
				Ciphertext: []byte{
					0x69, 0x6b, 0xb7, 0x4e, 0x41, 0x76, 0x6a, 0x9c, 0x74, 0x54, 0xf4,
					0x2a, 0x89, 0x86, 0x65, 0x91, 0x64, 0x89, 0x5b, 0xb0, 0x16, 0xda,
				},
				HMAC: []byte{
					0x53, 0x3a, 0xd6, 0x8d, 0x87, 0xb2, 0x98, 0xc4, 0x11, 0x2d, 0xde,
					0x39, 0xe5, 0x00, 0xfa, 0xa0, 0x28, 0x91, 0xd4, 0xb0, 0x34, 0xcc,
					0x2d, 0xc6, 0x05, 0xbd, 0xf5, 0x8a, 0xb2, 0x72, 0xb5, 0x55,
				},
				Type: Pbkdf2,
				Context: map[string]interface{}{
					"kdf": kdfParameters{
						Salt: []byte{
							0xbf, 0x19, 0x6d, 0x5e, 0xc6, 0xa0, 0x70, 0x5b,
							0x45, 0xff, 0x36, 0x04, 0xf7, 0xa3, 0x3f, 0xd5,
						},
						Iterations: 32,
						OrigType:   AESCTR,
					},
				},
			},
			[]byte("secret"),
			nil,
		},
		{
			"Encryptor initalise errors passed up",
			func(key []byte) (EncryptDecryptor, error) {
				return nil, errMarker
			},
			[]byte("key"),
			&EncryptedData{
				Ciphertext: []byte("secret"),
				HMAC:       []byte("--ignored--"),
				Type:       Pbkdf2,
				Context: map[string]interface{}{
					"kdf": kdfParameters{
						Salt: []byte{
							0xbf, 0x19, 0x6d, 0x5e, 0xc6, 0xa0, 0x70, 0x5b,
							0x45, 0xff, 0x36, 0x04, 0xf7, 0xa3, 0x3f, 0xd5,
						},
						Iterations: 32,
						OrigType:   Nop,
					},
				},
			},
			[]byte{},
			errMarker,
		},
		{
			"Encryptor Decrypt() errors passed up",
			func(key []byte) (EncryptDecryptor, error) {
				return &errEncryptor{errMarker}, nil
			},
			[]byte("key"),
			&EncryptedData{
				Ciphertext: []byte("secret"),
				HMAC:       []byte("--ignored--"),
				Type:       Pbkdf2,
				Context: map[string]interface{}{
					"kdf": kdfParameters{
						Salt: []byte{
							0xbf, 0x19, 0x6d, 0x5e, 0xc6, 0xa0, 0x70, 0x5b,
							0x45, 0xff, 0x36, 0x04, 0xf7, 0xa3, 0x3f, 0xd5,
						},
						Iterations: 32,
						OrigType:   Nop,
					},
				},
			},
			[]byte{},
			errMarker,
		},
		{
			"Wrong type",
			func(key []byte) (EncryptDecryptor, error) {
				return NopEncryptor{}, nil
			},
			[]byte("key"),
			&EncryptedData{
				Ciphertext: []byte("secret"),
				HMAC:       []byte("--ignored--"),
				Type:       Nop,
				Context: map[string]interface{}{
					"kdf": kdfParameters{
						Salt: []byte{
							0xbf, 0x19, 0x6d, 0x5e, 0xc6, 0xa0, 0x70, 0x5b,
							0x45, 0xff, 0x36, 0x04, 0xf7, 0xa3, 0x3f, 0xd5,
						},
						Iterations: 32,
						OrigType:   Nop,
					},
				},
			},
			[]byte("secret"),
			ErrWrongType,
		},
	}
	for _, tt := range tests {
		e := KDF{
			Provider:   tt.rProvider,
			SaltSize:   16,
			Iterations: 32, // small for testing
			SourceKey:  tt.rSourceKey,
		}
		got, err := e.Decrypt(tt.data)
		if err != tt.wantErr {
			t.Errorf("%q. KDF.Decrypt() error = %v, wantErr %v", tt.name, err, tt.wantErr)
			continue
		}
		if err != nil {
			continue
		}

		if !reflect.DeepEqual(got, tt.want) {
			t.Errorf("%q. KDF.Decrypt() = %v, want %v", tt.name, got, tt.want)
		}
	}
}
