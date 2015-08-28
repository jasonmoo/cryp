package main

import (
	"encoding/base64"
	"io/ioutil"
	"log"
	"os"

	"github.com/jasonmoo/cryp"
)

func main() {

	key, exists := os.LookupEnv("CRYP_KEY")
	if !exists {
		log.Fatal("CRYP_KEY not set in environment")
	}

	input, err := ioutil.ReadAll(base64.NewDecoder(base64.StdEncoding, os.Stdin))
	if err != nil {
		log.Fatal(err)
	}

	if len(input) < cryp.SignatureSize {
		log.Fatal("data too short to decrypt")
	}

	// extract sig prefix from input data
	sig := string(input[:cryp.SignatureSize])
	input = input[cryp.SignatureSize:]

	output, err := cryp.Decrypt(input, sig, []byte(key))
	if err != nil {
		log.Fatal(err)
	}

	os.Stdout.Write(output)

}
