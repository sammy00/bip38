package ec_test

import (
	"encoding/hex"
	"io"
	"strings"
	"testing"

	"github.com/sammy00/bip38/ec"
)

func TestDecrypt(t *testing.T) {
	testCases := []struct {
		passphrase     string
		passphraseCode string
		encrypted      string
		unencryptedHex string
		rand           io.Reader
	}{
		{

			"TestingOneTwoThree",
			"passphrasepxFy57B9v8HtUsszJYKReoNDV6VHjUSGt8EVJmux9n1J3Ltf1gRxyDGXqnf9qm",
			"6PfQu77ygVyJLZjfvMLyhLMQbYnu5uguoJJ4kMCLqWwPEdfpwANVS76gTX",
			"A43A940577F4E97F5C4D39EB14FF083A98187C64EA7C99EF7CE460833959A519",
			&EntropyReader{
				Stream: []byte{0xa5, 0x0d, 0xba, 0x67, 0x72, 0xcb, 0x93, 0x83},
			},
		},
		{

			"Satoshi",
			"passphraseoRDGAXTWzbp72eVbtUDdn1rwpgPUGjNZEc6CGBo8i5EC1FPW8wcnLdq4ThKzAS",
			"6PfLGnQs6VZnrNpmVKfjotbnQuaJK4KZoPFrAjx1JMJUa1Ft8gnf5WxfKd",
			"C2C8036DF268F498099350718C4A3EF3984D2BE84618C2650F5171DCC5EB660A",
			&EntropyReader{
				Stream: []byte{0x67, 0x01, 0x0a, 0x95, 0x73, 0x41, 0x89, 0x06},
			},
		},
		{
			"MOLON LABE",
			"passphraseaB8feaLQDENqCgr4gKZpmf4VoaT6qdjJNJiv7fsKvjqavcJxvuR1hy25aTu5sX",
			"6PgNBNNzDkKdhkT6uJntUXwwzQV8Rr2tZcbkDcuC9DZRsS6AtHts4Ypo1j",
			"44EA95AFBF138356A05EA32110DFD627232D0F2991AD221187BE356F19FA8190",
			nil,
		},
	}

	for i, c := range testCases {
		/*
			passphraseCode, err := ec.EncryptPassphrase(c.rand, c.passphrase)
			if nil != err {
				t.Fatalf("#%d unexpected error: %v", i, err)
			}

			if passphraseCode != c.passphraseCode {
				t.Fatalf("#%d invalid passphrase code: got %s, expect %s", i,
					passphraseCode, c.passphraseCode)
			}
		*/
		decrypted, err := ec.Decrypt(c.encrypted, c.passphrase)
		if nil != err {
			t.Fatalf("#%d unexpected error: %v", i, err)
		}

		if decryptedHex := hex.EncodeToString(
			[]byte(decrypted)); !strings.EqualFold(decryptedHex, c.unencryptedHex) {
			t.Fatalf("#%d failed: got %s, expect %s", i, decryptedHex,
				c.unencryptedHex)
		}
	}
}
