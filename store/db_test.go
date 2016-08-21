package store

import (
	"database/sql"
	"reflect"
	"testing"

	"github.com/domodwyer/cryptic/encryptor"
	_ "github.com/mattn/go-sqlite3"
)

const tableSQL = `
	CREATE TABLE secrets(
		id INTEGER NOT NULL PRIMARY KEY,
		name TEXT UNIQUE,
		data BLOB
	);
`

// TestDbPutGet uses an in-memory sqlite DB to verify Get() returns the same as what
// was Put() in.
func TestDbPutGet(t *testing.T) {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Errorf("Failed to set up sqlite db: %s", err)
		return
	}

	if _, err := db.Exec(tableSQL); err != nil {
		t.Errorf("Failed to create db table: %s", err)
		return
	}

	tests := []struct {
		// Test description.
		name string
		// Parameters.
		pname string
		pdata *encryptor.EncryptedData
		// Expected results.
		putErr error
		getErr error
	}{
		{
			"Empty",
			"empty secret",
			&encryptor.EncryptedData{
				Context: map[string]interface{}{},
			},
			nil,
			nil,
		},
		{
			"No secret name",
			"",
			nil,
			ErrInvalidName,
			ErrInvalidName,
		},
		{
			"Simple",
			"simple secret",
			&encryptor.EncryptedData{
				Ciphertext: []byte("ciphertext"),
				HMAC:       []byte("hmac"),
				Type:       encryptor.Nop,
				Context:    map[string]interface{}{},
			},
			nil,
			nil,
		},
		{
			"Simple, binary",
			"binary secret",
			&encryptor.EncryptedData{
				Ciphertext: []byte{0x42, 0x00, 0xDE, 0xAD, 0xBE, 0xEF},
				HMAC:       []byte{0xDE, 0xAD, 0xBA, 0xAD},
				Type:       encryptor.Nop,
				Context:    map[string]interface{}{},
			},
			nil,
			nil,
		},
		{
			"Simple, with context",
			"secret with context",
			&encryptor.EncryptedData{
				Ciphertext: []byte("ciphertext"),
				HMAC:       []byte("hmac"),
				Type:       encryptor.Nop,
				Context: map[string]interface{}{
					"string": "value",
					"int":    42,
				},
			},
			nil,
			nil,
		},
	}

	for _, tt := range tests {
		s, err := NewDB(db, nil)
		if err != nil {
			t.Errorf("%q. NewDB() err = %v", tt.name, err)
			continue
		}

		if err := s.Put(tt.pname, tt.pdata); err != tt.putErr {
			t.Errorf("%q. DB.Put() err = %v, want %v", tt.name, err, tt.putErr)
			continue
		}

		got, err := s.Get(tt.pname)
		if err != tt.getErr {
			t.Errorf("%q. DB.Get() err = %v, want %v", tt.name, err, tt.getErr)
			continue
		}

		if !reflect.DeepEqual(got, tt.pdata) {
			t.Errorf("%q. DB.Get() = %v, want %v", tt.name, got, tt.pdata)
		}
	}
}

// TestDbNotFound ensures calling Get() for a secret that doesn't exist produces
// an error
func TestDbNotFound(t *testing.T) {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Errorf("Failed to set up sqlite db: %s", err)
		return
	}

	if _, err := db.Exec(tableSQL); err != nil {
		t.Errorf("Failed to create db table: %s", err)
		return
	}

	s, err := NewDB(db, nil)
	if err != nil {
		t.Errorf("NotFound. NewDB() err = %v", err)
		return
	}

	got, err := s.Get("nope")
	if err != ErrNotFound {
		t.Errorf("NotFound. DB.Get() err = %v, want %v", err, ErrNotFound)
		return
	}

	if got != nil {
		t.Errorf("NotFound. DB.Get() got = %v, want %v", got, nil)
		return
	}
}

func TestDbParseOpts(t *testing.T) {
	tests := []struct {
		// Test description.
		name string
		// Parameters.
		opts *DBOpts
		// Expected results.
		want  string
		want1 string
		want2 string
	}{
		{
			"Defaults",
			&DBOpts{},
			"secrets",
			"name",
			"data",
		},
		{
			"Nil",
			nil,
			"secrets",
			"name",
			"data",
		},
		{
			"Table",
			&DBOpts{Table: "test"},
			"test",
			"name",
			"data",
		},
		{
			"Key",
			&DBOpts{Key: "test"},
			"secrets",
			"test",
			"data",
		},
		{
			"Value",
			&DBOpts{Value: "test"},
			"secrets",
			"name",
			"test",
		},
	}
	for _, tt := range tests {
		got, got1, got2 := parseOpts(tt.opts)
		if got != tt.want {
			t.Errorf("%q. parseOpts() got = %v, want %v", tt.name, got, tt.want)
		}
		if got1 != tt.want1 {
			t.Errorf("%q. parseOpts() got1 = %v, want %v", tt.name, got1, tt.want1)
		}
		if got2 != tt.want2 {
			t.Errorf("%q. parseOpts() got2 = %v, want %v", tt.name, got2, tt.want2)
		}
	}
}

// TestDbDelete uses an in-memory sqlite DB to verify Delete() returns correct
// errors, and removes things
func TestDbDelete(t *testing.T) {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Errorf("Failed to set up sqlite db: %s", err)
		return
	}

	if _, err := db.Exec(tableSQL); err != nil {
		t.Errorf("Failed to create db table: %s", err)
		return
	}

	existing := "INSERT INTO `secrets` (`name`, `data`) VALUES ('iExist', 'data');"
	if _, err := db.Exec(existing); err != nil {
		t.Errorf("Failed to insert known row: %s", err)
		return
	}

	tests := []struct {
		// Test description.
		name string
		// Parameters.
		pname string
		// Expected results.
		wantErr error
	}{
		{
			"Not found",
			"missing",
			ErrNotFound,
		},
		{
			"OK",
			"iExist",
			nil,
		},
		{
			"Definitely gone",
			"iExist",
			ErrNotFound,
		},
		{
			"No name",
			"",
			ErrInvalidName,
		},
	}
	for _, tt := range tests {
		s, err := NewDB(db, nil)
		if err != nil {
			t.Errorf("NotFound. NewDB() err = %v", err)
			return
		}

		if err := s.Delete(tt.pname); err != tt.wantErr {
			t.Errorf("%q. DB.Delete() error = %v, wantErr %v", tt.name, err, tt.wantErr)
		}
	}
}

func TestDbPut(t *testing.T) {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Errorf("Failed to set up sqlite db: %s", err)
		return
	}

	if _, err := db.Exec(tableSQL); err != nil {
		t.Errorf("Failed to create db table: %s", err)
		return
	}

	tests := []struct {
		// Test description.
		name string
		// Parameters.
		pname string
		// Expected results.
		wantErr bool
	}{
		{
			"Simple",
			"simple",
			false,
		},
		{
			"No overwrite",
			"simple",
			true,
		},
	}
	for _, tt := range tests {
		s, err := NewDB(db, nil)
		if err != nil {
			t.Errorf("NotFound. NewDB() err = %v", err)
			return
		}

		if err := s.Put(tt.pname, &encryptor.EncryptedData{}); (err != nil) != tt.wantErr {
			t.Errorf("%q. DB.Put() error = %v, wantErr %v", tt.name, err, tt.wantErr)
		}
	}
}
