package config

import "github.com/spf13/viper"

// DB defines config getters for the database Store parameters.
type DB interface {
	DBHost() string
	DBName() string
	DBTable() string
	DBUsername() string
	DBPassword() string
	DBKeyColumn() string
	DBValueColumn() string
}

// DBHost returns the configured database host (in the form of ip:port).
func (v viperStore) DBHost() string {
	return viper.GetString("DB.Host")
}

// DBName returns the configured database name.
func (v viperStore) DBName() string {
	return viper.GetString("DB.Name")
}

// DBTable returns the configured database table.
func (v viperStore) DBTable() string {
	return viper.GetString("DB.Table")
}

// DBUsername returns the configured database username.
func (v viperStore) DBUsername() string {
	return viper.GetString("DB.Username")
}

// DBPassword returns the configured database password.
func (v viperStore) DBPassword() string {
	return viper.GetString("DB.Password")
}

// DBKeyColumn returns the configured 'lookup' column name.
func (v viperStore) DBKeyColumn() string {
	return viper.GetString("DB.KeyColumn")
}

// DBValueColumn returns the configured 'value' column name.
func (v viperStore) DBValueColumn() string {
	return viper.GetString("DB.ValueColumn")
}
