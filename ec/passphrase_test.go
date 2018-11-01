package ec_test

import (
	"testing"

	"github.com/sammy00/bip38/ec"
)

func TestEncryptPassphrase(t *testing.T) {
	var testCases []encryptPassphraseGoldie
	readGolden(t, t.Name(), &testCases)

	for _, c := range testCases {
		c := c

		t.Run(c.Description, func(st *testing.T) {
			st.Parallel()

			entropy := &EntropyReader{Stream: c.Entropy}

			passphraseCode, err := ec.EncryptPassphrase(entropy, c.Passphrase)

			if c.Expect.Bad && nil == err {
				st.Fatalf("expect error but got none")
			} else if !c.Expect.Bad && nil != err {
				st.Fatalf("unexpected error: %v", err)
			}

			if !c.Expect.Bad && passphraseCode != c.Expect.PassphraseCode {
				st.Fatalf("invalid passphrase code: got %s, expect %s",
					passphraseCode, c.Expect.PassphraseCode)
			}
		})
	}
}

func TestEncryptPassphraseX(t *testing.T) {
	var testCases []encryptPassphraseXGoldie
	readGolden(t, t.Name(), &testCases)

	/*
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
	*/

	for _, c := range testCases {
		c := c

		t.Run(c.Description, func(st *testing.T) {
			st.Parallel()

			entropy := &EntropyReader{Stream: c.Entropy}

			passphraseCode, err := ec.EncryptPassphraseX(entropy, c.Passphrase,
				c.Lot, c.Sequence)

			if c.Expect.Bad && nil == err {
				st.Fatalf("expect error but got none")
			} else if !c.Expect.Bad && nil != err {
				st.Fatalf("unexpected error: %v", err)
			}

			if !c.Expect.Bad && passphraseCode != c.Expect.PassphraseCode {
				st.Fatalf("invalid passphrase code: got %s, expect %s",
					passphraseCode, c.Expect.PassphraseCode)
			}
		})
	}
}
