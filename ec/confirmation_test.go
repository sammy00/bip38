package ec_test

import (
	"testing"

	"github.com/sammy00/bip38/ec"
)

func TestGenerateConfirmationCode(t *testing.T) {
	testCases := []struct {
		flag                       byte
		addrHash                   []byte
		ownerEntropy               []byte
		b                          []byte
		derivedHalf1, derivedHalf2 []byte
		passphrase                 string
		expect                     string // expected confirmation code
	}{
		{
			0x00,
			[]byte{0x62, 0xb5, 0xb7, 0x22},
			[]byte{0xa5, 0x0d, 0xba, 0x67, 0x72, 0xcb, 0x93, 0x83},
			[]byte{
				0x3c, 0xcd, 0x8e, 0xb8, 0x0d, 0x80, 0x21, 0xaf,
				0x67, 0xb0, 0xe0, 0x66, 0xaf, 0x94, 0x34, 0xd5,
				0xce, 0x21, 0x0c, 0xc7, 0x78, 0x56, 0xb0, 0xcb,
				0x12, 0x5a, 0x09, 0xb3, 0xe2, 0x6f, 0x5a, 0x78,
			},
			[]byte{
				0xda, 0x2d, 0x32, 0x0e, 0x2c, 0xa0, 0x88, 0x57,
				0x53, 0x69, 0x60, 0x1e, 0x94, 0xdd, 0x71, 0xf2,
				0x10, 0xfc, 0x69, 0xc0, 0x47, 0xa3, 0xd0, 0xf4,
				0x8b, 0xdb, 0xaa, 0xb5, 0x95, 0x91, 0x6d, 0xc7,
			},
			[]byte{
				0xb8, 0xd0, 0x83, 0xea, 0x26, 0x78, 0xb5, 0xa7,
				0x15, 0x58, 0xc0, 0xfb, 0x0e, 0xfa, 0x58, 0xb5,
				0x65, 0x22, 0x7d, 0x05, 0xad, 0xf0, 0xc2, 0x5f,
				0xa0, 0xb9, 0xa7, 0x47, 0x55, 0x47, 0x78, 0x27,
			},
			"TestingOneTwoThree",
			"cfrm38V5UPS5Aik2Z91tWbgNUTDmL4uKyUF4CX7wATVikgxRfg9tjCT7Mdon16uVeWCJqjnFGts",
		},
		{
			0x00,
			[]byte{0x05, 0x9a, 0x54, 0x81},
			[]byte{0x67, 0x01, 0x0a, 0x95, 0x73, 0x41, 0x89, 0x06},
			[]byte{
				0x0f, 0xb3, 0xec, 0x31, 0x0f, 0x94, 0x1d, 0xca,
				0xd1, 0xe7, 0xa0, 0xab, 0xd3, 0x5d, 0x4f, 0x86,
				0x53, 0x14, 0x1a, 0x32, 0xbc, 0xea, 0x60, 0x91,
				0x37, 0x6a, 0x06, 0x72, 0x04, 0xc8, 0x58, 0xf0,
			},
			[]byte{
				0xdc, 0x7d, 0x94, 0x2e, 0xa3, 0xc6, 0xc8, 0x95,
				0x3b, 0x30, 0xee, 0x01, 0x0c, 0x14, 0x7a, 0x32,
				0x22, 0xf6, 0xf5, 0xc5, 0x29, 0x23, 0xe2, 0x81,
				0x85, 0x83, 0x2f, 0x64, 0xd8, 0x67, 0x81, 0xbc,
			},
			[]byte{
				0x51, 0x20, 0xc4, 0x2e, 0x25, 0x50, 0x94, 0x60,
				0x89, 0x2a, 0xc9, 0xfe, 0xc4, 0x5e, 0x1b, 0xc5,
				0x26, 0x13, 0x23, 0x8e, 0x1b, 0x5c, 0x1e, 0xad,
				0x9d, 0x41, 0xbd, 0xee, 0xa8, 0x89, 0x2c, 0x5c,
			},
			"Satoshi",
			"cfrm38V5DK6HEHLdYfLRsiJmSAMdPypxESZ4rPcWWo3Jx6rvBNSL79ZbwbGDh2KNvniTEM1ib3v",
		},
		{
			0x04,
			[]byte{0xbb, 0x45, 0x8c, 0xef},
			[]byte{0x4f, 0xca, 0x5a, 0x97, 0x40, 0x40, 0xf0, 0x01},
			[]byte{
				0x70, 0xd8, 0x7a, 0xbd, 0xc2, 0xe2, 0x52, 0x22,
				0x2e, 0x0e, 0x57, 0x3e, 0xd7, 0xb8, 0x39, 0x71,
				0x65, 0x9c, 0xd3, 0x38, 0xda, 0xf5, 0xc8, 0x81,
				0xda, 0x8b, 0xf3, 0xed, 0x5d, 0xcd, 0xf2, 0x1f,
			},
			[]byte{
				0xa8, 0xbc, 0x4a, 0xd3, 0x5f, 0xb6, 0x9c, 0xc3,
				0x7f, 0x12, 0x9a, 0xbb, 0x45, 0x82, 0x45, 0xe4,
				0x52, 0x3c, 0x97, 0x13, 0x3b, 0x22, 0xa5, 0xca,
				0xd8, 0x80, 0x35, 0xf9, 0x9d, 0x0b, 0x1d, 0x50,
			},
			[]byte{
				0xff, 0xc8, 0x31, 0x7a, 0x1e, 0xae, 0xa3, 0x30,
				0xe1, 0xe1, 0x73, 0x05, 0x53, 0x9e, 0xc5, 0xc5,
				0xce, 0x36, 0x16, 0x8a, 0x35, 0xd6, 0xd1, 0x3f,
				0xef, 0xa2, 0x1d, 0x5e, 0x2c, 0xb1, 0xc1, 0xe9,
			},
			"MOLON LABE",
			"cfrm38V8aXBn7JWA1ESmFMUn6erxeBGZGAxJPY4e36S9QWkzZKtaVqLNMgnifETYw7BPwWC9aPD",
		},
		{
			0x04,
			[]byte{0x49, 0x4a, 0xf1, 0x36},
			[]byte{0xc4, 0x0e, 0xa7, 0x6f, 0xc5, 0x01, 0xa0, 0x01},
			[]byte{
				0x68, 0xae, 0x89, 0xd2, 0xe2, 0xf5, 0x67, 0xb4,
				0xce, 0x31, 0x4e, 0x07, 0x5e, 0x04, 0x64, 0x00,
				0x88, 0xf2, 0x2c, 0xdc, 0x80, 0x5e, 0x7c, 0xe9,
				0x22, 0x82, 0xbe, 0x75, 0x76, 0xe2, 0xee, 0x62,
			},
			[]byte{
				0x14, 0x71, 0xd2, 0x4b, 0x21, 0xc2, 0x1e, 0x16,
				0x4f, 0x48, 0x23, 0x7e, 0x9a, 0x5f, 0x09, 0x26,
				0x49, 0x3b, 0xf6, 0x11, 0x83, 0x73, 0xa0, 0xd2,
				0xe1, 0x83, 0x87, 0xa7, 0xc3, 0x45, 0x64, 0x6d,
			},
			[]byte{
				0x68, 0x89, 0xd2, 0xc3, 0x0b, 0xe9, 0x72, 0x18,
				0x74, 0xf1, 0x08, 0x44, 0xfb, 0x98, 0x79, 0x4d,
				0xe1, 0xca, 0xba, 0x62, 0xbb, 0x65, 0x9a, 0x51,
				0x49, 0x2d, 0x4f, 0x33, 0xca, 0x32, 0x37, 0xd7,
			},
			"ΜΟΛΩΝ ΛΑΒΕ",
			"cfrm38V8G4qq2ywYEFfWLD5Cc6msj9UwsG2Mj4Z6QdGJAFQpdatZLavkgRd1i4iBMdRngDqDs51",
		},
	}

	for i, c := range testCases {
		got, _ := ec.GenerateConfirmationCode(c.flag, c.addrHash, c.ownerEntropy,
			c.b, c.derivedHalf1, c.derivedHalf2)
		if got != c.expect {
			t.Fatalf("#%d failed: got %s, expect %s", i, got, c.expect)
		}
	}
}

func TestRecoverAddress(t *testing.T) {
	testCases := []struct {
		passphrase       string
		confirmationCode string
		expectAddress    string // expected bitcoin address
		expectErr        bool
	}{
		{
			"TestingOneTwoThree",
			"cfrm38V5UPS5Aik2Z91tWbgNUTDmL4uKyUF4CX7wATVikgxRfg9tjCT7Mdon16uVeWCJqjnFGts",
			"1PE6TQi6HTVNz5DLwB1LcpMBALubfuN2z2",
			false,
		},
		{
			"Satoshi",
			"cfrm38V5DK6HEHLdYfLRsiJmSAMdPypxESZ4rPcWWo3Jx6rvBNSL79ZbwbGDh2KNvniTEM1ib3v",
			"1CqzrtZC6mXSAhoxtFwVjz8LtwLJjDYU3V",
			false,
		},
		{
			"MOLON LABE",
			"cfrm38V8aXBn7JWA1ESmFMUn6erxeBGZGAxJPY4e36S9QWkzZKtaVqLNMgnifETYw7BPwWC9aPD",
			"1Jscj8ALrYu2y9TD8NrpvDBugPedmbj4Yh",
			false,
		},
		{
			"ΜΟΛΩΝ ΛΑΒΕ",
			"cfrm38V8G4qq2ywYEFfWLD5Cc6msj9UwsG2Mj4Z6QdGJAFQpdatZLavkgRd1i4iBMdRngDqDs51",
			"1Lurmih3KruL4xDB5FmHof38yawNtP9oGf",
			false,
		},
		{ // invalid base58 checksum
			"TestingOneTwoThree",
			"cfrm38V5UPS5Aik2Z91tWbgNUTDmL4uKyUF4CX7wATVikgxRfg9tjCT7Mdon16uVeWCJqjnFGtt",
			"",
			true,
		},
		{ // invalid code length
			"TestingOneTwoThree",
			"passphrasepxFy57B9v8HtUsszJYKReoNDV6VHjUSGt8EVJmux9n1J3Ltf1gRxyDGXqnf9qm",
			"",
			true,
		},
		{ // invalid pointprefix
			"TestingOneTwoThree",
			"cfrm38V5UPS5Aik2Z91tWbgNUMPXoNZERCDNo4NpSiditjA6vLJjn5vUzibTGeqofYB9MsZmCz9",
			"",
			true,
		},
		{ // invalid address hash
			"TestingOneTwoThree",
			"cfrm38V5UPS5Aik2Z91tWbgNURH29qTJ83Zq4hYEFssioNMekZYB5VcEZzjfkxDberBvM5pPV7A",
			"",
			true,
		},
	}

	for i, c := range testCases {
		got, err := ec.RecoverAddress(c.passphrase, c.confirmationCode)

		if !c.expectErr && nil != err {
			t.Fatalf("#%d unexpected error: %v", i, err)
		} else if c.expectErr && nil == err {
			t.Fatalf("#%d failed: expect an error", i)
		}

		if got != c.expectAddress {
			t.Fatalf("#%d invalid address: got %s, expect %s", i, got,
				c.expectAddress)
		}
	}
}
