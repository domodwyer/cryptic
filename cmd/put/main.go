package main

import (
	"flag"
	"log"
	"os"

	"github.com/domodwyer/cryptic/cmd/shared"
	"github.com/domodwyer/cryptic/config"
)

var name = flag.String("name", "", "secret name")
var data = flag.String("value", "", "secret value")

func init() {
	flag.Parse()
}

func main() {
	if *name == "" || *data == "" {
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

	e, err := enc.Encrypt([]byte(*data))
	if err != nil {
		log.Fatal(err)
	}

	if err := backend.Put(*name, e); err != nil {
		log.Fatal(err)
	}

	log.Print("OK")
}
