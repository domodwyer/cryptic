package encryptor

import (
	"bytes"
	"errors"
	"reflect"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/kms"
)

var (
	errGenerateDataKey = errors.New("GenerateDataKey error")
	errMarker          = errors.New("any error")
)

type mockKms struct {
	keyID string
	err   error
}

func (m *mockKms) GenerateDataKey(input *kms.GenerateDataKeyInput) (*kms.GenerateDataKeyOutput, error) {
	if m.err != nil {
		return nil, m.err
	}

	if m.keyID != *input.KeyId {
		return nil, errGenerateDataKey
	}

	return &kms.GenerateDataKeyOutput{
		CiphertextBlob: []byte("AAAA"),
		KeyId:          aws.String("KEY"),
		Plaintext:      []byte("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY"),
	}, nil
}

func (m *mockKms) Decrypt(input *kms.DecryptInput) (*kms.DecryptOutput, error) {
	if m.err != nil {
		return nil, m.err
	}

	return &kms.DecryptOutput{
		KeyId:     aws.String("KEY"),
		Plaintext: []byte("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY"),
	}, nil
}

type errEncryptor struct {
	err error
}

func (e *errEncryptor) Encrypt(secret []byte) (*EncryptedData, error) {
	return nil, e.err
}

func (e *errEncryptor) Decrypt(data *EncryptedData) ([]byte, error) {
	return nil, e.err
}

func TestKMSEncrypt(t *testing.T) {
	tests := []struct {
		// Test description.
		name string
		// Receiver fields.
		rsvc      kmsInterface
		rkeyID    string
		rProvider EncryptionProvider
		// Parameters.
		secret []byte
		// Expected results.
		want    *EncryptedData
		wantErr error
	}{
		{
			"Known good",
			&mockKms{keyID: "keyId"},
			"keyId",
			// Use NopEncryptor for testing
			func(key []byte) (EncryptDecryptor, error) {
				return NopEncryptor{}, nil
			},
			[]byte("secret"),
			&EncryptedData{
				Ciphertext: []byte("secret"),
				HMAC:       []byte("--ignored--"),
				Type:       KMSWrapped,
				Context: map[string]interface{}{
					"kms_type": Nop,
					"kms_key":  []byte("AAAA"),
				},
			},
			nil,
		},
		{
			"KMS request error",
			&mockKms{keyID: "keyId", err: errMarker},
			"keyId",
			// Use NopEncryptor for testing
			func(key []byte) (EncryptDecryptor, error) {
				return NopEncryptor{}, nil
			},
			[]byte("secret"),
			&EncryptedData{},
			errMarker,
		},
		{
			"Encryptor initalise errors passed up",
			&mockKms{keyID: "keyId"},
			"keyId",
			// Use NopEncryptor for testing
			func(key []byte) (EncryptDecryptor, error) {
				return nil, errMarker
			},
			[]byte("secret"),
			&EncryptedData{},
			errMarker,
		},
		{
			"Encryptor Encrypt() errors passed up",
			&mockKms{keyID: "keyId"},
			"keyId",
			// Use NopEncryptor for testing
			func(key []byte) (EncryptDecryptor, error) {
				return &errEncryptor{errMarker}, nil
			},
			[]byte("secret"),
			&EncryptedData{},
			errMarker,
		},
	}

	for _, tt := range tests {
		e := &KMS{
			svc:      tt.rsvc,
			keyID:    tt.rkeyID,
			KeySize:  64,
			Provider: tt.rProvider,
		}
		got, err := e.Encrypt(tt.secret)

		if err != tt.wantErr {
			t.Errorf("%q. KMS.Encrypt() error = %v, wantErr %v", tt.name, err, tt.wantErr)
			continue
		}

		if err != nil {
			continue
		}

		if !reflect.DeepEqual(got, tt.want) {
			t.Errorf("%q. KMS.Encrypt() = %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestKMSDecrypt(t *testing.T) {
	tests := []struct {
		// Test description.
		name string
		// Receiver fields.
		rsvc      kmsInterface
		rkeyID    string
		rProvider EncryptionProvider
		// Parameters.
		data *EncryptedData
		// Expected results.
		want    []byte
		wantErr error
	}{
		{
			"Decrypt",
			&mockKms{keyID: "keyId"},
			"keyId",
			// Use NopEncryptor for testing
			func(key []byte) (EncryptDecryptor, error) {
				return NopEncryptor{}, nil
			},
			&EncryptedData{
				Ciphertext: []byte("secret"),
				HMAC:       []byte("--ignored--"),
				Type:       KMSWrapped,
				Context: map[string]interface{}{
					"kms_type": Nop,
					"kms_key":  []byte("AAAA"),
				},
			},
			[]byte("secret"),
			nil,
		},
		{
			"KMS request error",
			&mockKms{keyID: "keyId", err: errMarker},
			"keyId",
			// Use NopEncryptor for testing
			func(key []byte) (EncryptDecryptor, error) {
				return NopEncryptor{}, nil
			},
			&EncryptedData{
				Ciphertext: []byte("secret"),
				HMAC:       []byte("--ignored--"),
				Type:       KMSWrapped,
				Context: map[string]interface{}{
					"kms_type": Nop,
					"kms_key":  []byte("AAAA"),
				},
			},
			[]byte("secret"),
			errMarker,
		},
		{
			"Encryptor initalise errors passed up",
			&mockKms{keyID: "keyId"},
			"keyId",
			// Use NopEncryptor for testing
			func(key []byte) (EncryptDecryptor, error) {
				return nil, errMarker
			},
			&EncryptedData{
				Ciphertext: []byte("secret"),
				HMAC:       []byte("--ignored--"),
				Type:       KMSWrapped,
				Context: map[string]interface{}{
					"kms_type": Nop,
					"kms_key":  []byte("AAAA"),
				},
			},
			[]byte("secret"),
			errMarker,
		},
		{
			"Encryptor Decrypt() errors passed up",
			&mockKms{keyID: "keyId"},
			"keyId",
			// Use NopEncryptor for testing
			func(key []byte) (EncryptDecryptor, error) {
				return &errEncryptor{errMarker}, nil
			},
			&EncryptedData{
				Ciphertext: []byte("secret"),
				HMAC:       []byte("--ignored--"),
				Type:       KMSWrapped,
				Context: map[string]interface{}{
					"kms_type": Nop,
					"kms_key":  []byte("AAAA"),
				},
			},
			[]byte("secret"),
			errMarker,
		},
		{
			"Wrong type",
			&mockKms{keyID: "keyId"},
			"keyId",
			// Use NopEncryptor for testing
			func(key []byte) (EncryptDecryptor, error) {
				return NopEncryptor{}, nil
			},
			&EncryptedData{
				Ciphertext: []byte("secret"),
				HMAC:       []byte("--ignored--"),
				Type:       Nop,
				Context: map[string]interface{}{
					"kms_type": Nop,
					"kms_key":  []byte("AAAA"),
				},
			},
			[]byte("secret"),
			ErrWrongType,
		},
		{
			"Missing kms_key",
			&mockKms{keyID: "keyId"},
			"keyId",
			// Use NopEncryptor for testing
			func(key []byte) (EncryptDecryptor, error) {
				return NopEncryptor{}, nil
			},
			&EncryptedData{
				Ciphertext: []byte("secret"),
				HMAC:       []byte("--ignored--"),
				Type:       KMSWrapped,
				Context: map[string]interface{}{
					"kms_type": Nop,
				},
			},
			[]byte("secret"),
			ErrMissingContext,
		},
		{
			"Wrong kms_key type",
			&mockKms{keyID: "keyId"},
			"keyId",
			// Use NopEncryptor for testing
			func(key []byte) (EncryptDecryptor, error) {
				return NopEncryptor{}, nil
			},
			&EncryptedData{
				Ciphertext: []byte("secret"),
				HMAC:       []byte("--ignored--"),
				Type:       KMSWrapped,
				Context: map[string]interface{}{
					"kms_type": Nop,
					"kms_key":  "wrong",
				},
			},
			[]byte("secret"),
			ErrMissingContext,
		},
		{
			"Missing kms_type",
			&mockKms{keyID: "keyId"},
			"keyId",
			// Use NopEncryptor for testing
			func(key []byte) (EncryptDecryptor, error) {
				return NopEncryptor{}, nil
			},
			&EncryptedData{
				Ciphertext: []byte("secret"),
				HMAC:       []byte("--ignored--"),
				Type:       KMSWrapped,
				Context: map[string]interface{}{
					"kms_type": Nop,
				},
			},
			[]byte("secret"),
			ErrMissingContext,
		},
		{
			"Wrong kms_type type",
			&mockKms{keyID: "keyId"},
			"keyId",
			// Use NopEncryptor for testing
			func(key []byte) (EncryptDecryptor, error) {
				return NopEncryptor{}, nil
			},
			&EncryptedData{
				Ciphertext: []byte("secret"),
				HMAC:       []byte("--ignored--"),
				Type:       KMSWrapped,
				Context: map[string]interface{}{
					"kms_type": "wrong",
					"kms_key":  Nop,
				},
			},
			[]byte("secret"),
			ErrMissingContext,
		},
	}
	for _, tt := range tests {
		e := &KMS{
			svc:      tt.rsvc,
			keyID:    tt.rkeyID,
			KeySize:  64,
			Provider: tt.rProvider,
		}
		got, err := e.Decrypt(tt.data)
		if err != tt.wantErr {
			t.Errorf("%q. KMS.Decrypt() error = %v, wantErr %v", tt.name, err, tt.wantErr)
			continue
		}

		if err != nil {
			continue
		}

		if !reflect.DeepEqual(got, tt.want) {
			t.Errorf("%q. KMS.Decrypt() = %v, want %v", tt.name, got, tt.want)
		}

		if tt.data.Type != KMSWrapped {
			t.Errorf("%q. KMS.Decrypt() mutated input, type = %v, want %v", tt.name, tt.data.Type, KMSWrapped)
		}
	}
}

func TestKMSIntegration(t *testing.T) {
	tests := []struct {
		// Test description.
		name string
		// Receiver fields.
		rsvc      kmsInterface
		rkeyID    string
		rProvider EncryptionProvider
		// Parameters.
		secret []byte
		// Expected results.
		wantEncryptErr error
		wantDecryptErr error
	}{
		{
			"Decrypt",
			&mockKms{keyID: "keyId"},
			"keyId",
			func(key []byte) (EncryptDecryptor, error) {
				return NewAES(key[:32], key[32:])
			},
			[]byte("secret"),
			nil,
			nil,
		},
	}
	for _, tt := range tests {
		e := &KMS{
			svc:      tt.rsvc,
			keyID:    tt.rkeyID,
			KeySize:  64,
			Provider: tt.rProvider,
		}

		encd, err := e.Encrypt(tt.secret)
		if err != tt.wantEncryptErr {
			t.Errorf("%q. KMS.Encrypt() error = %v, wantErr %v", tt.name, err, tt.wantEncryptErr)
			continue
		}

		got, err := e.Decrypt(encd)
		if err != tt.wantDecryptErr {
			t.Errorf("%q. KMS.Decrypt() error = %v, wantErr %v", tt.name, err, tt.wantDecryptErr)
			continue
		}

		if !bytes.Equal(got, tt.secret) {
			t.Errorf("%q. KMS.Decrypt() = %v, want %v", tt.name, got, tt.secret)
		}
	}
}
