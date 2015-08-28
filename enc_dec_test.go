package cryp

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func init() {
	// discard courtesy output during tests
	LogOutput = ioutil.Discard
}

func TestEncDec(t *testing.T) {

	testset := []struct {
		key  string
		data string
	}{
		{key: "", data: "small data"},
		{key: "key", data: ""},
		{key: "utf8 key ∆∆", data: "utf8 data ∆∆"},
		{key: "key", data: strings.Repeat("large_data", 1<<10)},
		{key: strings.Repeat("large key", 1<<10), data: strings.Repeat("large data", 1<<10)},
		{key: strings.Repeat("large key", 1<<10), data: "sml data"},
	}

	for _, test := range testset {
		encdata, err := Encrypt([]byte(test.data), []byte(test.key))
		if err != nil {
			t.Error(err)
		}

		decdata, err := Decrypt(encdata, []byte(test.key))
		if err != nil {
			t.Error(err)
		}

		if !bytes.Equal([]byte(test.data), decdata) {
			t.Errorf("output mismatch")
		}
	}

}

func TestEncDecFile(t *testing.T) {

	var key = []byte("key")

	testset := []struct {
		name string
		data []byte
		mode os.FileMode
	}{
		{
			name: "empty_file.txt",
			data: nil,
			mode: 0644,
		},
		{
			name: "regular file.txt",
			data: []byte("text data"),
			mode: 0644,
		},
		{
			name: "binary",
			data: bytes.Repeat([]byte{0xff, 0xaa, 0x00}, 64<<10),
			mode: 0755,
		},
		{
			name: "read_only.🔒",
			data: bytes.Repeat([]byte(" 🔒 "), 1<<10),
			mode: 0400,
		},
	}

	for _, test := range testset {
		func() {
			file, err := ioutil.TempFile(os.TempDir(), test.name)
			if err != nil {
				t.Error(err)
			}
			if _, err := file.Write(test.data); err != nil {
				t.Error(err)
			}
			if err := file.Close(); err != nil {
				t.Error(err)
			}
			if err := os.Chmod(file.Name(), test.mode); err != nil {
				t.Error(err)
			}

			new_path, err := EncryptFile(file.Name(), key)
			if err != nil {
				t.Error(err)
			}
			defer os.Remove(new_path)

			// check if it exists
			if _, err := os.Stat(new_path); err != nil {
				t.Error(err)
			}

			// remove temp file so we can restore it
			os.Remove(file.Name())

			orig_path, err := DecryptFile(new_path, key)
			if err != nil {
				t.Error(err)
			}
			defer os.Remove(orig_path)

			if file.Name() != orig_path {
				t.Errorf("Expected %q, got %q", file.Name(), orig_path)
			}
			info, err := os.Stat(orig_path)
			if err != nil {
				t.Error(err)
			}
			if info.Mode().Perm() != test.mode {
				t.Errorf("Expected %#o, got %#o", test.mode, info.Mode().Perm())
			}
			data, err := ioutil.ReadFile(orig_path)
			if err != nil {
				t.Error(err)
			}
			if !bytes.Equal(data, test.data) {
				t.Errorf("File contents mismatch")
			}
		}()
	}

}

func TestEncDecDirectory(t *testing.T) {

	const testSubDir = "test_enc_dec_directory"
	dir, err := ioutil.TempDir(os.TempDir(), testSubDir)
	if err != nil {
		t.Fatal(err)
	}

	encryptTheseDir := filepath.Join(dir, "encrypt/these")
	if err := os.MkdirAll(encryptTheseDir, 0777); err != nil {
		t.Fatal(err)
	}

	dontEncryptTheseDir := filepath.Join(dir, "not/these")
	if err := os.MkdirAll(dontEncryptTheseDir, 0777); err != nil {
		t.Fatal(err)
	}

	const TextFile = "normal.txt"
	var TextFileData = bytes.Repeat([]byte("lines of data\n"), 500)
	var TextFileMode os.FileMode = 0644
	for i := 0; i < 10; i++ {
		if err := ioutil.WriteFile(filepath.Join(encryptTheseDir, TextFile+strconv.Itoa(i)), []byte(TextFileData), TextFileMode); err != nil {
			t.Fatal(err)
		}
		if err := ioutil.WriteFile(filepath.Join(dontEncryptTheseDir, TextFile+strconv.Itoa(i)), []byte(TextFileData), TextFileMode); err != nil {
			t.Fatal(err)
		}
	}

	var key = []byte("key")

	if err := EncryptDirFiles(encryptTheseDir, key); err != nil {
		t.Error(err)
	}

	var atLeastOneFileChecked bool

	if err := filepath.Walk(encryptTheseDir, func(path string, info os.FileInfo, err error) error {

		// skip processing directories as files
		if info.IsDir() {
			return nil
		}

		atLeastOneFileChecked = true

		if !sha256HexRegexp.MatchString(filepath.Base(path)) {
			return fmt.Errorf("Expected sha256 hash filename, got %q", filepath.Base(path))
		}

		// ensure we write with user read only perm
		if info.Mode().Perm()&0400 != 0400 {
			return fmt.Errorf("Expected %#o, got %#o", 0400, info.Mode().Perm())
		}

		data, err := ioutil.ReadFile(path)
		if err != nil {
			return err
		}

		h := hmac.New(sha256.New, key)
		h.Write(data)
		data_hash := hex.EncodeToString(h.Sum(nil))

		if data_hash != filepath.Base(path) {
			return fmt.Errorf("Corruption detected in %s", path)
		}

		return nil

	}); err != nil {
		t.Error(err)
	}

	if !atLeastOneFileChecked {
		t.Errorf("Somehow there were no files found in %q", dir)
	}

	// decrypt from top most temp dir and check to see if only encrypted files touched
	if err := DecryptDirFiles(dir, key); err != nil {
		t.Error(err)
	}

	atLeastOneFileChecked = false
	if err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {

		// skip processing directories as files
		if info.IsDir() {
			return nil
		}

		atLeastOneFileChecked = true

		if !strings.HasPrefix(filepath.Base(path), TextFile) {
			return fmt.Errorf("Found unexpected file: %q", path)
		}
		stat, err := os.Stat(path)
		if err != nil {
			return err
		}
		if stat.Mode().Perm() != TextFileMode {
			return fmt.Errorf("Expected decrypted file mode %#o, got %#o", TextFileMode, stat.Mode().Perm())
		}
		data, err := ioutil.ReadFile(path)
		if err != nil {
			return err
		}
		if !bytes.Equal(data, TextFileData) {
			return fmt.Errorf("File data mismatch for %q", path)
		}

		return nil

	}); err != nil {
		t.Error(err)
	}

	if !atLeastOneFileChecked {
		t.Errorf("Somehow there were no files found in %q", dir)
	}

	if err := os.RemoveAll(dir); err != nil {
		t.Error(err)
	}

}
