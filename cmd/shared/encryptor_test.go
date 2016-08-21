package shared

import (
	"testing"

	"github.com/domodwyer/cryptic/config"
	"github.com/domodwyer/cryptic/encryptor"
)

func TestGetEncryptor_AES(t *testing.T) {
	tests := []struct {
		// Test description.
		name string
		// Parameters.
		config config.Encryptor
		// Expected results.
		wantErr error
	}{
		{
			"AES",
			mockConfig{
				encryptor:  "aes",
				aesKey:     "1234567890123456",
				aesHmacKey: "HMAC",
			},
			nil,
		},
		{
			"AES key too short",
			mockConfig{
				encryptor:  "aes",
				aesKey:     "1",
				aesHmacKey: "HMAC",
			},
			encryptor.ErrKeyTooShort,
		},
		{
			"HMAC key too short",
			mockConfig{
				encryptor:  "aes",
				aesKey:     "1234567890123456",
				aesHmacKey: "",
			},
			encryptor.ErrHmacKeyTooShort,
		},
	}
	for _, tt := range tests {
		got, err := GetEncryptor(tt.config)
		if err != tt.wantErr {
			t.Errorf("%q. getEncryptor() error = %v, wantErr %v", tt.name, err, tt.wantErr)
			continue
		}
		if err != nil {
			continue
		}

		if _, ok := got.(*encryptor.AESCTREncryptor); !ok {
			t.Errorf("%q. getEncryptor() not correct type", tt.name)
		}
	}
}

func TestGetEncryptor_KMS(t *testing.T) {
	tests := []struct {
		// Test description.
		name string
		// Parameters.
		config config.Encryptor
		// Expected results.
		wantErr bool
	}{
		{
			"KMS",
			mockConfig{
				encryptor: "kms",
				kmsKeyID:  "keyID",
				kmsRegion: "eu-west-1",
			},
			false,
		},
		{
			"KMS no Key ID",
			mockConfig{
				encryptor: "kms",
				kmsKeyID:  "",
				kmsRegion: "eu-west-1",
			},
			true,
		},
	}
	for _, tt := range tests {
		got, err := GetEncryptor(tt.config)
		if (err != nil) != tt.wantErr {
			t.Errorf("%q. getEncryptor() error = %v, wantErr %v", tt.name, err, tt.wantErr)
			continue
		}
		if err != nil {
			continue
		}

		if _, ok := got.(*encryptor.KMS); !ok {
			t.Errorf("%q. getEncryptor() not correct type", tt.name)
		}
	}
}
