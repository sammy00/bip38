package ec_test

import (
	"encoding/json"
	"os"
	"path/filepath"
)

type cfrmCodeGoldie struct {
	Flag                       byte
	AddrHash                   []byte
	OwnerEntropy               []byte
	B                          []byte
	DerivedHalf1, DerivedHalf2 []byte
	Passphrase                 string
	ConfirmationCode           string // expected confirmation code
}

type fataler interface {
	Fatal(args ...interface{})
}

func readGolden(f fataler, name string, golden interface{}) {
	fd, err := os.Open(filepath.Join("testdata", name+".golden"))
	if nil != err {
		f.Fatal(err)
	}
	defer fd.Close()

	unmarshaler := json.NewDecoder(fd)
	if err := unmarshaler.Decode(golden); nil != err {
		f.Fatal(err)
	}
}
