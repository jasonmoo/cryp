package cryp

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/crypto/scrypt"
)

// Common actions are printed to stdout.  These can be silenced
// by setting LogOutput = ioutil.Discard
var LogOutput io.Writer = os.Stdout

// Encrypt takes data and a key and outputs encrypted data, it's HMAC SHA-256 signature
// and any possible errors. The key can be any length or empty (not recommended).
// The data can be any length or empty.  Scrypt for the 32 byte AES-256 key derivation.
// The data is compressed using gzip prior to encryption.  Raw byte output will need
// to be hex/base64 encoded before it is printable.
func Encrypt(data []byte, key []byte) ([]byte, string, error) {

	// generate a 32 byte key from the variable length key supplied
	aes256Key := generate32ByteKey(key)

	block, err := aes.NewCipher(aes256Key)
	if err != nil {
		return nil, "", err
	}

	buf := &bytes.Buffer{}
	w, err := gzip.NewWriterLevel(buf, gzip.BestCompression)
	if err != nil {
		return nil, "", err
	}
	if _, err := w.Write(data); err != nil {
		return nil, "", err
	}
	if err := w.Close(); err != nil {
		return nil, "", err
	}

	ciphertext := make([]byte, aes.BlockSize+buf.Len())

	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, "", err
	}

	cfb := cipher.NewCFBEncrypter(block, iv)
	cfb.XORKeyStream(ciphertext[aes.BlockSize:], buf.Bytes())

	h := hmac.New(sha256.New, key)
	h.Write(ciphertext)
	sig := hex.EncodeToString(h.Sum(nil))

	return ciphertext, sig, nil

}

// EncryptFile writes a file's name, size, mode, mod time, and contents
// in tar format and passes it to Encrypt. A new file is created
// that is named the SHA-256 checksum of the encrypted output.
// It returns the new file path and error if occurred
func EncryptFile(path string, key []byte) (string, error) {

	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}

	// unable to encrypt these files
	// ModeType = ModeDir | ModeSymlink | ModeNamedPipe | ModeSocket | ModeDevice
	if info.Mode()&os.ModeType != 0 {
		return "", errors.New("invalid file type")
	}

	start := time.Now()
	fmt.Fprint(LogOutput, "Encrypting ", path)

	data, err := ioutil.ReadFile(path)
	if err != nil {
		return "", err
	}

	// Create a new tar archive.
	buf := &bytes.Buffer{}
	tw := tar.NewWriter(buf)

	hdr := &tar.Header{
		Name:    info.Name(),        // string    // name of header file entry
		Mode:    int64(info.Mode()), // int64     // permission and mode bits
		Size:    info.Size(),        // int64     // length in bytes
		ModTime: info.ModTime(),     // time.Time // modified time
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return "", err
	}
	if _, err := tw.Write(data); err != nil {
		return "", err
	}
	if err := tw.Close(); err != nil {
		return "", err
	}

	// encrypt tar archive
	encrypted_data, sig, err := Encrypt(buf.Bytes(), key)
	if err != nil {
		return "", err
	}

	// create new file using signature as name
	new_file_path := filepath.Join(filepath.Dir(path), sig)
	new_file, err := os.OpenFile(new_file_path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|os.O_SYNC, 0400)
	if err != nil {
		return "", err
	}
	if n, err := new_file.Write(encrypted_data); err != nil {
		return "", err
	} else if n != len(encrypted_data) {
		return "", io.ErrShortWrite
	}
	if err := new_file.Close(); err != nil {
		return "", err
	}

	fmt.Fprintln(LogOutput, " ...", time.Since(start))

	return new_file_path, nil

}

// EncryptDirFiles takes a directory and a key and searches, recursively,
// for any files to encrypt and passes it to EncryptFile, replacing the
// existing file with the new encrypted version. All directories,
// symlinks, named pipes, sockets, and devices are left as-is.
func EncryptDirFiles(dir string, key []byte) error {

	return filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {

		// Skip these types
		// ModeType = ModeDir | ModeSymlink | ModeNamedPipe | ModeSocket | ModeDevice
		if info.Mode()&os.ModeType != 0 {
			return nil
		}

		if _, err := EncryptFile(path, key); err != nil {
			return err
		}

		if err := os.Remove(path); err != nil {
			return err
		}

		return nil

	})

}

func generate32ByteKey(input []byte) []byte {

	// The recommended parameters for interactive logins as of 2009 are N=16384, r=8, p=1.
	const (
		// N is a CPU/memory cost parameter, which must be a power of two greater than 1.
		N = 16 << 10
		// r and p must satisfy r * p < 2³⁰
		r = 8
		p = 1
		// AES-256 requires 32 byte key
		keyLen = 32
	)

	salt := sha512.Sum512(input)
	key, _ := scrypt.Key(input, salt[:], N, r, p, keyLen)
	return key

}
