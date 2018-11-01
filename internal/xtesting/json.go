package xtesting

import (
	"encoding/json"
	"os"
	"path/filepath"
)

func DecodeGoldenJSON(f Logger, name string, golden interface{}) {
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

func EncodeGoldenToJSON(l Logger, name string, goldies interface{}) {
	fd, err := os.OpenFile(filepath.Join("testdata", "Test"+name+".golden"),
		os.O_CREATE|os.O_RDWR, 0644)
	if nil != err {
		l.Fatal(err)
	}
	defer fd.Close()

	marshaler := json.NewEncoder(fd)
	marshaler.SetIndent("", "  ")
	if err := marshaler.Encode(goldies); nil != err {
		l.Fatal(err)
	}
}
