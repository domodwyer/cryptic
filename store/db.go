package store

import (
	"database/sql"
	"fmt"

	"github.com/domodwyer/cryptic/encryptor"
)

// DB stores secrets in a database.
//
// It is expected that the key column has a UNIQUE constraint. Unlike most
// stores, DB does not return ErrAlreadyExists when attempting to Put() a secret
// already in the store, as each database driver returns a different error -
// instead the driver specific error is returned.
type DB struct {
	getStmt *sql.Stmt
	putStmt *sql.Stmt
	delStmt *sql.Stmt
}

// DBOpts allows the user to use a different database schema than the defaults.
//
// It is expected that the DBOpts values are from trusted input (free from SQL
// injection vectors).
type DBOpts struct {
	Table string
	Key   string
	Value string
}

// NewDB returns an initalised DB store
func NewDB(db *sql.DB, opts *DBOpts) (*DB, error) {
	t, k, v := parseOpts(opts)

	getSQL := fmt.Sprintf("SELECT `%s` FROM `%s` WHERE `%s`= ? LIMIT 1", v, t, k)
	get, err := db.Prepare(getSQL)
	if err != nil {
		return nil, err
	}

	putSQL := fmt.Sprintf("INSERT INTO `%s` (`%s`, `%s`) VALUES (?, ?)", t, k, v)
	put, err := db.Prepare(putSQL)
	if err != nil {
		return nil, err
	}

	delSQL := fmt.Sprintf("DELETE FROM `%s` WHERE `%s` = ?", t, k)
	del, err := db.Prepare(delSQL)
	if err != nil {
		return nil, err
	}

	return &DB{get, put, del}, nil
}

// parseOpts sets sensible defaults, and returns any user-set DB config.
func parseOpts(opts *DBOpts) (string, string, string) {
	t := "secrets"
	k := "name"
	v := "data"

	if opts == nil {
		return t, k, v
	}

	if opts.Table != "" {
		t = opts.Table
	}

	if opts.Key != "" {
		k = opts.Key
	}

	if opts.Value != "" {
		v = opts.Value
	}

	return t, k, v
}

// Put encodes data using binary gobs and stores the result in the database
// using name as the key.
func (s *DB) Put(name string, data *encryptor.EncryptedData) error {
	if name == "" {
		return ErrInvalidName
	}

	buf, err := data.MarshalBinary()
	if err != nil {
		return err
	}

	if _, err := s.putStmt.Exec(name, buf); err != nil {
		return err
	}

	return nil
}

// Get fetches the secret stored under name.
func (s *DB) Get(name string) (*encryptor.EncryptedData, error) {
	if name == "" {
		return nil, ErrInvalidName
	}

	data := []byte{}

	// Get the data, translate a ErrNoRows into our ErrNotFound
	err := s.getStmt.QueryRow(name).Scan(&data)

	switch err {
	case nil:
		break

	case sql.ErrNoRows:
		return nil, ErrNotFound

	default:
		return nil, err
	}

	d := encryptor.EncryptedData{}
	if err := d.UnmarshalBinary(data); err != nil {
		return nil, err
	}

	return &d, nil
}

// Delete removes a secret from the database.
func (s *DB) Delete(name string) error {
	if name == "" {
		return ErrInvalidName
	}

	res, err := s.delStmt.Exec(name)
	if err != nil {
		return err
	}

	i, err := res.RowsAffected()
	if err != nil {
		return err
	}

	if i < 1 {
		return ErrNotFound
	}

	return nil
}
