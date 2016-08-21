package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/domodwyer/cryptic/cmd/shared"
	"github.com/domodwyer/cryptic/config"
)

var name = flag.String("name", "", "secret name")

func init() {
	flag.Parse()
}

func main() {
	if *name == "" {
		log.Print("required parameter missing")
		flag.PrintDefaults()
		os.Exit(1)
	}

	config := config.New()

	enc, err := shared.GetEncryptor(config)
	if err != nil {
		log.Fatal(err)
	}

	backend, err := shared.GetStore(config)
	if err != nil {
		log.Fatal(err)
	}

	data, err := backend.Get(*name)
	if err != nil {
		log.Fatal(err)
	}

	plain, err := enc.Decrypt(data)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("%s", plain)
}
