package ec_test

import (
	"io"
	"testing"

	"github.com/sammy00/bip38/ec"
)

func TestEncrypt(t *testing.T) {
	testCases := []struct {
		rand           io.Reader
		passphraseCode string
		expectPrivKey  string
		expectCode     string // expected confirmation code
	}{
		{
			&EntropyReader{
				Stream: []byte{
					0x99, 0x24, 0x1d, 0x58, 0x24, 0x5c, 0x88, 0x38,
					0x96, 0xf8, 0x08, 0x43, 0xd2, 0x84, 0x66, 0x72,
					0xd7, 0x31, 0x2e, 0x61, 0x95, 0xca, 0x1a, 0x6c,
				},
			},
			"passphrasepxFy57B9v8HtUsszJYKReoNDV6VHjUSGt8EVJmux9n1J3Ltf1gRxyDGXqnf9qm",
			"6PfQu77ygVyJLZjfvMLyhLMQbYnu5uguoJJ4kMCLqWwPEdfpwANVS76gTX",
			"cfrm38V5UPS5Aik2Z91tWbgNUTDmL4uKyUF4CX7wATVikgxRfg9tjCT7Mdon16uVeWCJqjnFGts",
		},
		{
			&EntropyReader{
				Stream: []byte{
					0x49, 0x11, 0x1e, 0x30, 0x1d, 0x94, 0xea, 0xb3,
					0x39, 0xff, 0x9f, 0x68, 0x22, 0xee, 0x99, 0xd9,
					0xf4, 0x96, 0x06, 0xdb, 0x3b, 0x47, 0xa4, 0x97,
				},
			},
			"passphraseoRDGAXTWzbp72eVbtUDdn1rwpgPUGjNZEc6CGBo8i5EC1FPW8wcnLdq4ThKzAS",
			"6PfLGnQs6VZnrNpmVKfjotbnQuaJK4KZoPFrAjx1JMJUa1Ft8gnf5WxfKd",
			"cfrm38V5DK6HEHLdYfLRsiJmSAMdPypxESZ4rPcWWo3Jx6rvBNSL79ZbwbGDh2KNvniTEM1ib3v",
		},
		{
			&EntropyReader{
				Stream: []byte{
					0x87, 0xa1, 0x3b, 0x07, 0x85, 0x8f, 0xa7, 0x53,
					0xcd, 0x3a, 0xb3, 0xf1, 0xc5, 0xea, 0xfb, 0x5f,
					0x12, 0x57, 0x9b, 0x6c, 0x33, 0xc9, 0xa5, 0x3f,
				},
			},
			"passphraseaB8feaLQDENqCgr4gKZpmf4VoaT6qdjJNJiv7fsKvjqavcJxvuR1hy25aTu5sX",
			"6PgNBNNzDkKdhkT6uJntUXwwzQV8Rr2tZcbkDcuC9DZRsS6AtHts4Ypo1j",
			"cfrm38V8aXBn7JWA1ESmFMUn6erxeBGZGAxJPY4e36S9QWkzZKtaVqLNMgnifETYw7BPwWC9aPD",
		},
		{
			&EntropyReader{
				Stream: []byte{
					0x03, 0xb0, 0x6a, 0x1e, 0xa7, 0xf9, 0x21, 0x9a,
					0xe3, 0x64, 0x56, 0x0d, 0x7b, 0x98, 0x5a, 0xb1,
					0xfa, 0x27, 0x02, 0x5a, 0xaa, 0x7e, 0x42, 0x7a,
				},
			},
			"passphrased3z9rQJHSyBkNBwTRPkUGNVEVrUAcfAXDyRU1V28ie6hNFbqDwbFBvsTK7yWVK",
			"6PgGWtx25kUg8QWvwuJAgorN6k9FbE25rv5dMRwu5SKMnfpfVe5mar2ngH",
			"cfrm38V8G4qq2ywYEFfWLD5Cc6msj9UwsG2Mj4Z6QdGJAFQpdatZLavkgRd1i4iBMdRngDqDs51",
		},
	}

	for i, c := range testCases {
		encrypted, code, err := ec.Encrypt(c.rand, c.passphraseCode, false)
		if nil != err {
			t.Fatalf("#%d unexpected error: %v", i, err)
		}

		if encrypted != c.expectPrivKey {
			t.Fatalf("#%d failed: got %s, expect %s", i, encrypted, c.expectPrivKey)
		}

		if code != c.expectCode {
			t.Fatalf("#%d invalid confirmation code: got %s, expect %s", i, code,
				c.expectCode)
		}
	}
}
