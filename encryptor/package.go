// Package encryptor implements various encyption methods for use with cryptic.
//
// Everything in this package implements the EncryptDecryptor interface.
//
// See the KMS implementation for an example of how encryptors can be chained
// together to create layered solutions.
//
// Where suitable, implementors of the EncryptDecryptor interface should return
// the errors defined in this package.
//
// Encryptors must support binary secrets.
package encryptor
