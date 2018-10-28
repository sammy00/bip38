package ec_test

import (
	"testing"

	"github.com/sammy00/bip38/ec"
)

func TestConfirmation(t *testing.T) {
	testCases := []struct {
		flag         byte
		addrHash     []byte
		ownerEntropy []byte
		b            []byte
		derivedHalf1 []byte
		derivedHalf2 []byte
		passphrase   string
		expect       bool // expected bitcoin address
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
			false,
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
			false,
		},
	}

	for i, c := range testCases {
		confirmationCode, _ := ec.Confirm(c.flag, c.addrHash, c.ownerEntropy, c.b,
			c.derivedHalf1, c.derivedHalf2)

		got := ec.CheckConfirmationCode(c.passphrase, confirmationCode)

		if !c.expect && nil != got {
			t.Fatalf("#%d unexpected error: %v", i, got)
		} else if c.expect && nil == got {
			t.Fatalf("#%d failed: expect an error", i)
		}
	}
}