package ec_test

type cfrmCodeGoldie struct {
	Flag                       byte
	AddrHash                   []byte
	OwnerEntropy               []byte
	B                          []byte
	DerivedHalf1, DerivedHalf2 []byte
	Passphrase                 string
	ConfirmationCode           string // expected confirmation code
}

type decryptExpect struct {
	Decrypted string `json:",omitempty"` // in hex
	Bad       bool
}

type decryptGoldie struct {
	Description string
	Encrypted   string
	Passphrase  string
	Expect      decryptExpect
}

type encryptExpect struct {
	PrivKey          string `json:",omitempty"`
	ConfirmationCode string `json:",omitempty"`
	Bad              bool   // true if the provided inputs is malformed
}

type encryptGoldie struct {
	Description    string
	Entropy        []byte
	PassphraseCode string
	Compressed     bool
	Expect         encryptExpect
}

type encryptPassphraseExpect struct {
	PassphraseCode string `json:",omitempty"`
	Bad            bool   // indicate whether the inputs are malformed
}

type encryptPassphraseGoldie struct {
	Description string
	Entropy     []byte
	Passphrase  string
	Expect      encryptPassphraseExpect
}

type encryptPassphraseXGoldie struct {
	Description   string
	Entropy       []byte
	Passphrase    string
	Lot, Sequence uint32
	Expect        encryptPassphraseExpect
}

type recoverAddressExpect struct {
	Address string `json:",omitempty"` // expected bitcoin address
	Bad     bool   // whether the address is malformed
}

type recoverAddressGoldie struct {
	Description      string
	Passphrase       string
	ConfirmationCode string
	Expect           recoverAddressExpect
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
