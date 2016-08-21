package encryptor

import (
	"bytes"
	"testing"
)

func TestNopEncryptorIntegration(t *testing.T) {
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
			[]byte{0x42, 0x00, 0xDE, 0xAD, 0xBE, 0xEF},
		},
	}

	for _, tt := range tests {
		e := NopEncryptor{}

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
