// +build awsintegration

package encryptor

import (
	"bytes"
	"os"
	"testing"
)

// TestKMSAWSIntegration performs an encryption and decryption using live KMS
// details, ensuring we get the same output as input.
func TestKMSAWSIntegration(t *testing.T) {
	if os.Getenv("AWS_REGION") == "" {
		t.Skip("no AWS_REGION environment variable set, skipping KMS integration tests")
	}

	if os.Getenv("KMS_KEY_ID") == "" {
		t.Skip("no KMS_KEY_ID environment variable set, skipping KMS integration tests")
	}

	tests := []struct {
		// Test description.
		name string
		// Parameters.
		secret []byte
		// Expected results.
		wantEncryptErr error
		wantDecryptErr error
	}{
		{
			"Known good",
			[]byte("secret"),
			nil,
			nil,
		},
	}

	for _, tt := range tests {
		e := NewKMS(os.Getenv("KMS_KEY_ID"), os.Getenv("AWS_REGION"))

		encd, err := e.Encrypt(tt.secret)
		if err != tt.wantEncryptErr {
			t.Errorf("%q. KMS.Encrypt() error = %v, wantEncryptErr %v", tt.name, err, tt.wantEncryptErr)
			continue
		}
		if err != nil {
			continue
		}

		got, err := e.Decrypt(encd)
		if err != tt.wantDecryptErr {
			t.Errorf("%q. KMS.Decrypt() error = %v, wantDecryptErr %v", tt.name, err, tt.wantDecryptErr)
			continue
		}
		if err != nil {
			continue
		}

		if !bytes.Equal(got, tt.secret) {
			t.Errorf("%q. KMS.Decrypt() = %v, want %v", tt.name, got, tt.secret)
		}
	}
}
