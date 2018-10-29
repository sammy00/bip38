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
		{
			"MOLON LABE",
			"passphraseaB8feaLQDENqCgr4gKZpmf4VoaT6qdjJNJiv7fsKvjqavcJxvuR1hy25aTu5sX",
			"6PgNBNNzDkKdhkT6uJntUXwwzQV8Rr2tZcbkDcuC9DZRsS6AtHts4Ypo1j",
			"44EA95AFBF138356A05EA32110DFD627232D0F2991AD221187BE356F19FA8190",
			&EntropyReader{
				Stream: []byte{
					0x87, 0xa1, 0x3b, 0x07, 0x85, 0x8f, 0xa7, 0x53,
					0xcd, 0x3a, 0xb3, 0xf1, 0xc5, 0xea, 0xfb, 0x5f,
					0x12, 0x57, 0x9b, 0x6c, 0x33, 0xc9, 0xa5, 0x3f,
				},
			},
		},
		{
			"ΜΟΛΩΝ ΛΑΒΕ",
			"passphrased3z9rQJHSyBkNBwTRPkUGNVEVrUAcfAXDyRU1V28ie6hNFbqDwbFBvsTK7yWVK",
			"6PgGWtx25kUg8QWvwuJAgorN6k9FbE25rv5dMRwu5SKMnfpfVe5mar2ngH",
			"CA2759AA4ADB0F96C414F36ABEB8DB59342985BE9FA50FAAC228C8E7D90E3006",
			&EntropyReader{
				Stream: []byte{
					0x03, 0xb0, 0x6a, 0x1e, 0xa7, 0xf9, 0x21, 0x9a,
					0xe3, 0x64, 0x56, 0x0d, 0x7b, 0x98, 0x5a, 0xb1,
					0xfa, 0x27, 0x02, 0x5a, 0xaa, 0x7e, 0x42, 0x7a,
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
