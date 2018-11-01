package ec_test

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/sammy00/bip38/ec"
)

func TestDecrypt(t *testing.T) {
	var testCases []decryptGoldie
	readGolden(t, t.Name(), &testCases)

	for _, c := range testCases {
		c := c

		t.Run(c.Description, func(st *testing.T) {
			st.Parallel()

			decrypted, err := ec.Decrypt(c.Encrypted, c.Passphrase)

			if c.Expect.Bad && nil == err {
				st.Fatalf("expect error but got none")
			} else if !c.Expect.Bad && nil != err {
				st.Fatalf("unexpected error: %v", err)
			}

			if c.Expect.Bad {
				return
			}

			if decryptedHex := hex.EncodeToString([]byte(decrypted)); !strings.EqualFold(decryptedHex, c.Expect.Decrypted) {
				t.Fatalf("invalid decrypted private key: got %s, expect %s",
					decryptedHex, c.Expect.Decrypted)
			}
		})
	}
}
