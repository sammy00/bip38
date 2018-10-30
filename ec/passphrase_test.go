package ec_test

import (
	"io"
	"testing"

	"github.com/sammy00/bip38/ec"
)

func TestEncryptPassphrase(t *testing.T) {
	type expect struct {
		passphraseCode string
		hasErr         bool
	}

	testCases := []struct {
		rand       io.Reader
		passphrase string
		expect     expect
	}{
		{
			&EntropyReader{
				Stream: []byte{0xa5, 0x0d, 0xba, 0x67, 0x72, 0xcb, 0x93, 0x83},
			},
			"TestingOneTwoThree",
			expect{
				"passphrasepxFy57B9v8HtUsszJYKReoNDV6VHjUSGt8EVJmux9n1J3Ltf1gRxyDGXqnf9qm",
				false,
			},
		},
		{
			&EntropyReader{
				Stream: []byte{0x67, 0x01, 0x0a, 0x95, 0x73, 0x41, 0x89, 0x06},
			},
			"Satoshi",
			expect{
				"passphraseoRDGAXTWzbp72eVbtUDdn1rwpgPUGjNZEc6CGBo8i5EC1FPW8wcnLdq4ThKzAS",
				false,
			},
		},
		{ // not enough entropy
			&EntropyReader{
				Stream: []byte{0xa5, 0x0d, 0xba, 0x67, 0x72, 0xcb, 0x93},
			},
			"TestingOneTwoThree",
			expect{"", true},
		},
	}

	for i, c := range testCases {
		passphraseCode, err := ec.EncryptPassphrase(c.rand, c.passphrase)

		if c.expect.hasErr && nil == err {
			t.Fatalf("#%d failed: expect error but got none", i)
		} else if !c.expect.hasErr && nil != err {
			t.Fatalf("#%d unexpected error: %v", i, err)
		}

		if passphraseCode != c.expect.passphraseCode {
			t.Fatalf("#%d invalid passphrase code: got %s, expect %s", i,
				passphraseCode, c.expect.passphraseCode)
		}
	}
}

func TestEncryptPassphraseX(t *testing.T) {
	type expect struct {
		passphraseCode string
		hasErr         bool
	}

	testCases := []struct {
		rand          io.Reader
		passphrase    string
		lot, sequence uint32
		expect        expect
	}{
		{
			&EntropyReader{Stream: []byte{0x4f, 0xca, 0x5a, 0x97}},
			"MOLON LABE",
			263183, 1,
			expect{
				"passphraseaB8feaLQDENqCgr4gKZpmf4VoaT6qdjJNJiv7fsKvjqavcJxvuR1hy25aTu5sX",
				false,
			},
		},
		{
			&EntropyReader{Stream: []byte{0xc4, 0x0e, 0xa7, 0x6f}},
			"ΜΟΛΩΝ ΛΑΒΕ",
			806938, 1,
			expect{

				"passphrased3z9rQJHSyBkNBwTRPkUGNVEVrUAcfAXDyRU1V28ie6hNFbqDwbFBvsTK7yWVK",
				false,
			},
		},
		{ // not enough entropy
			&EntropyReader{Stream: []byte{0x4f, 0xca, 0x5a}},
			"MOLON LABE",
			263183, 1,
			expect{"", true},
		},
	}

	for i, c := range testCases {
		passphraseCode, err := ec.EncryptPassphraseX(c.rand, c.passphrase,
			c.lot, c.sequence)

		if c.expect.hasErr && nil == err {
			t.Fatalf("#%d failed: expect error but got none", i)
		} else if !c.expect.hasErr && nil != err {
			t.Fatalf("#%d unexpected error: %v", i, err)
		}

		if passphraseCode != c.expect.passphraseCode {
			t.Fatalf("#%d invalid passphrase code: got %s, expect %s", i,
				passphraseCode, c.expect.passphraseCode)
		}
	}
}
