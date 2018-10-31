package nonec_test

import (
	"encoding/hex"
	"testing"

	"github.com/sammy00/bip38/nonec"
)

func TestEncrypt(t *testing.T) {
	var testCases []encryptGoldie
	readGolden(t, t.Name(), &testCases)

	for _, c := range testCases {
		c := c

		t.Run(c.Decription, func(st *testing.T) {
			st.Parallel()

			raw, _ := hex.DecodeString(c.Unencrypted)

			encrypted, err := nonec.Encrypt(raw, c.Passphrase, c.Compressed)

			if nil != err {
				st.Fatalf("unexpected error %v", err)
			}

			if encrypted != c.Encrypted {
				st.Fatalf("invalid encrypted key: got %s, expect %s",
					encrypted, c.Encrypted)
			}
		})
	}
}
