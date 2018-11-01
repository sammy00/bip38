package nonec_test

/*
type fataler interface {
	Fatal(args ...interface{})
}
*/

type decryptExpect struct {
	Unencrypted string `json:",omitempty"`
	Bad         bool
}

type decryptGoldie struct {
	Description string
	Passphrase  string
	Encrypted   string
	WIF         string `json:",omitempty"`
	//Unencrypted string `json:",omitempty"`
	//Bad         bool
	Expect decryptExpect
}

type encryptGoldie struct {
	Decription  string
	Unencrypted string // unencrypted key in hex
	Passphrase  string
	Compressed  bool
	Encrypted   string // this is the expected value after encryption
}

/*
func readGolden(f xtesting.Logger, name string, golden interface{}) {
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
*/
