package cryptic

import (
	"fmt"

	"github.com/domodwyer/cryptic/encryptor"
	"github.com/domodwyer/cryptic/store"
)

// Below is an example of how to use the library in your own Go programs.
//
// Note you should definitely be checking the error returns, they're omitted
// here for brevity.
func Example() {
	store := store.NewMemory()

	aesKey := []byte("anAesTestKey1234")
	hmacKey := []byte("superSecretHmacKey")

	// Note the AES key has to be either 16, 24, or 32 bytes
	e, _ := encryptor.NewAES(aesKey, hmacKey)

	// Encrypt the secret and store it
	result, _ := e.Encrypt([]byte("something secret"))
	store.Put("example", result)

	//
	// Time passes...
	//

	// Fetch and decrypt
	data, _ := store.Get("example")
	plain, _ := e.Decrypt(data)

	// Output
	fmt.Printf("%s\n", plain)
	// Output: something secret
}
