package ec_test

import (
	"testing"

	"github.com/sammy00/bip38/internal/xtesting"

	"github.com/sammy00/bip38/ec"
)

func TestEncryptPassphrase(t *testing.T) {
	var testCases []encryptPassphraseGoldie
	xtesting.DecodeGoldenJSON(t, t.Name(), &testCases)

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
	xtesting.DecodeGoldenJSON(t, t.Name(), &testCases)

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
