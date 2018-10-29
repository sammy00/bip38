package ec_test

import (
	"io"
	"testing"

	"github.com/sammy00/bip38/ec"
)

func TestEncryptPassphrase(t *testing.T) {
	testCases := []struct {
		rand       io.Reader
		passphrase string
		expect     string
	}{
		{
			&EntropyReader{
				Stream: []byte{0xa5, 0x0d, 0xba, 0x67, 0x72, 0xcb, 0x93, 0x83},
			},
			"TestingOneTwoThree",
			"passphrasepxFy57B9v8HtUsszJYKReoNDV6VHjUSGt8EVJmux9n1J3Ltf1gRxyDGXqnf9qm",
		},
		{
			&EntropyReader{
				Stream: []byte{0x67, 0x01, 0x0a, 0x95, 0x73, 0x41, 0x89, 0x06},
			},
			"Satoshi",
			"passphraseoRDGAXTWzbp72eVbtUDdn1rwpgPUGjNZEc6CGBo8i5EC1FPW8wcnLdq4ThKzAS",
		},
	}

	for i, c := range testCases {
		passphraseCode, err := ec.EncryptPassphrase(c.rand, c.passphrase)
		if nil != err {
			t.Fatalf("#%d unexpected error: %v", i, err)
		}

		if passphraseCode != c.expect {
			t.Fatalf("#%d invalid passphrase code: got %s, expect %s", i,
				passphraseCode, c.expect)
		}
	}
}

func TestEncryptPassphraseX(t *testing.T) {
	testCases := []struct {
		rand          io.Reader
		passphrase    string
		lot, sequence uint32
		expect        string
	}{
		{
			&EntropyReader{Stream: []byte{0x4f, 0xca, 0x5a, 0x97}},
			"MOLON LABE",
			263183, 1,
			"passphraseaB8feaLQDENqCgr4gKZpmf4VoaT6qdjJNJiv7fsKvjqavcJxvuR1hy25aTu5sX",
		},
		{
			&EntropyReader{Stream: []byte{0xc4, 0x0e, 0xa7, 0x6f}},
			"ΜΟΛΩΝ ΛΑΒΕ",
			806938, 1,
			"passphrased3z9rQJHSyBkNBwTRPkUGNVEVrUAcfAXDyRU1V28ie6hNFbqDwbFBvsTK7yWVK",
		},
	}

	for i, c := range testCases {
		passphraseCode, err := ec.EncryptPassphraseX(c.rand, c.passphrase,
			c.lot, c.sequence)
		if nil != err {
			t.Fatalf("#%d unexpected error: %v", i, err)
		}

		if passphraseCode != c.expect {
			t.Fatalf("#%d invalid passphrase code: got %s, expect %s", i,
				passphraseCode, c.expect)
		}
	}
}
