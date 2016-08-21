package shared

type mockConfig struct {
	store      string
	encryptor  string
	kmsKeyID   string
	kmsRegion  string
	aesKey     string
	aesHmacKey string
}

func (m mockConfig) Store() string {
	return m.store
}

func (m mockConfig) Encryptor() string {
	return m.encryptor
}

func (m mockConfig) KMSKeyID() string {
	return m.kmsKeyID
}

func (m mockConfig) KMSRegion() string {
	return m.kmsRegion
}

func (m mockConfig) AESKey() string {
	return m.aesKey
}

func (m mockConfig) AESHmacKey() string {
	return m.aesHmacKey
}
