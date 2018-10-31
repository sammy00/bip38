package nonec_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type decryptGoldie struct {
	Description string
	Passphrase  string
	Encrypted   string
	WIF         string `json:",omitempty"`
	Unencrypted string `json:",omitempty"`
	Bad         bool
}

func readGolden(t *testing.T, name string, golden interface{}) {
	fd, err := os.Open(filepath.Join("testdata", name+".golden"))
	if nil != err {
		t.Fatal(err)
	}
	defer fd.Close()

	unmarshaler := json.NewDecoder(fd)
	if err := unmarshaler.Decode(golden); nil != err {
		t.Fatal(err)
	}
}
