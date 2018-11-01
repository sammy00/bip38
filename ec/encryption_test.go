package ec_test

import (
	"testing"

	"github.com/sammy00/bip38/ec"
)

func TestEncrypt(t *testing.T) {
	var testCases []encryptGoldie
	readGolden(t, t.Name(), &testCases)

	for _, c := range testCases {
		c := c

		t.Run(c.Description, func(st *testing.T) {
			entropy := &EntropyReader{Stream: c.Entropy}

			encrypted, code, err := ec.Encrypt(entropy, c.PassphraseCode,
				c.Compressed)

			if c.Expect.Bad && nil == err {
				st.Fatalf("expect error but got none")
			} else if !c.Expect.Bad && nil != err {
				t.Fatalf("unexpected error: %v", err)
			}

			if !c.Expect.Bad && encrypted != c.Expect.PrivKey {
				st.Fatalf("invalid private key: got %s, expect %s", encrypted,
					c.Expect.PrivKey)
			}

			if !c.Expect.Bad && code != c.Expect.ConfirmationCode {
				st.Fatalf("invalid confirmation code: got %s, expect %s", code,
					c.Expect.ConfirmationCode)
			}
		})
	}
}
