package ec_test

import (
	"encoding/hex"
	"io"
	"testing"

	"github.com/sammy00/bip38/ec"
)

func TestEncrypt(t *testing.T) {
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
				Stream: []byte{
					0x99, 0x24, 0x1d, 0x58, 0x24, 0x5c, 0x88, 0x38,
					0x96, 0xf8, 0x08, 0x43, 0xd2, 0x84, 0x66, 0x72,
					0xd7, 0x31, 0x2e, 0x61, 0x95, 0xca, 0x1a, 0x6c,
				},
			},
		},
		{
			"Satoshi",
			"passphraseoRDGAXTWzbp72eVbtUDdn1rwpgPUGjNZEc6CGBo8i5EC1FPW8wcnLdq4ThKzAS",
			"6PfLGnQs6VZnrNpmVKfjotbnQuaJK4KZoPFrAjx1JMJUa1Ft8gnf5WxfKd",
			"C2C8036DF268F498099350718C4A3EF3984D2BE84618C2650F5171DCC5EB660A",
			&EntropyReader{
				Stream: []byte{
					0x49, 0x11, 0x1e, 0x30, 0x1d, 0x94, 0xea, 0xb3,
					0x39, 0xff, 0x9f, 0x68, 0x22, 0xee, 0x99, 0xd9,
					0xf4, 0x96, 0x06, 0xdb, 0x3b, 0x47, 0xa4, 0x97,
				},
			},
		},
	}

	for i, c := range testCases {
		unencrypted, _ := hex.DecodeString(c.unencryptedHex)

		encrypted, err := ec.Encrypt(c.rand, unencrypted, c.passphraseCode, false)
		if nil != err {
			t.Fatalf("#%d unexpected error: %v", i, err)
		}

		if encrypted != c.encrypted {
			t.Fatalf("#%d failed: got %s, expect %s", i, encrypted, c.encrypted)
		}
	}
}
