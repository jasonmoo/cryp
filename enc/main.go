package main

import (
	"encoding/base64"
	"fmt"
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

	data, err := ioutil.ReadAll(os.Stdin)
	if err != nil {
		log.Fatal(err)
	}

	output, sig, err := cryp.Encrypt(data, []byte(key))
	if err != nil {
		log.Fatal(err)
	}

	// prepend sig to encrypted data before base64 encoding
	buf := make([]byte, 0, len(sig)+len(output))
	buf = append(buf, sig...)
	buf = append(buf, output...)

	fmt.Println(base64.StdEncoding.EncodeToString(buf))

}
