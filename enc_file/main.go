package main

import (
	"log"
	"os"

	"github.com/jasonmoo/cryp"
)

func main() {

	key, exists := os.LookupEnv("CRYP_KEY")
	if !exists {
		log.Fatal("CRYP_KEY not set in environment")
	}

	for _, path := range os.Args[1:] {
		if _, err := cryp.EncryptFile(path, []byte(key)); err != nil {
			log.Fatal(err)
		}
	}

}
