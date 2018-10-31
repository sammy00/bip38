package nonec_test

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/sammy00/bip38/nonec"
)

func TestDecrypt(t *testing.T) {
	var testCases []decryptGoldie
	readGolden(t, t.Name(), &testCases)

	for _, c := range testCases {
		c := c

		t.Run(c.Description, func(st *testing.T) {
			st.Parallel()

			unencrypted, err := nonec.Decrypt(c.Encrypted, c.Passphrase)

			if c.Bad && nil == err {
				st.Fatalf("expect error but got none")
			} else if !c.Bad && nil != err {
				st.Fatalf("unexpected error %v", err)
			}

			if rawInHex := hex.EncodeToString(unencrypted); !c.Bad &&
				!strings.EqualFold(rawInHex, c.Unencrypted) {
				st.Fatalf("invalid unencrypted: got %s, expect %s",
					rawInHex, c.Unencrypted)
			}
		})
	}
}
