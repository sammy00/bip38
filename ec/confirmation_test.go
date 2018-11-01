package ec_test

import (
	"testing"

	"github.com/sammy00/bip38/ec"
)

func TestGenerateConfirmationCode(t *testing.T) {
	var testCases []cfrmCodeGoldie
	readGolden(t, t.Name(), &testCases)

	for i, c := range testCases {
		got, _ := ec.GenerateConfirmationCode(c.Flag, c.AddrHash, c.OwnerEntropy,
			c.B, c.DerivedHalf1, c.DerivedHalf2)
		if got != c.ConfirmationCode {
			t.Fatalf("#%d failed: got %s, expect %s", i, got, c.ConfirmationCode)
		}
	}
}

func TestRecoverAddress(t *testing.T) {
	/*
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
			{ // compressed form
				"TestingOneTwoThree",
				"cfrm38VUCLt2TQxAbVcZKYcZWx8cg4A8LjL9Fx1mL6zn7jJnAfeUYiJGrLsmU1pci4M3QEeeGc3",
				"1AtJUNDEkPfgiAY88vRaZAs9ZCTmoX5UMh",
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
	*/

	var testCases []recoverAddressGoldie
	readGolden(t, t.Name(), &testCases)

	for _, c := range testCases {
		c := c

		t.Run(c.Description, func(st *testing.T) {
			st.Parallel()

			got, err := ec.RecoverAddress(c.Passphrase, c.ConfirmationCode)

			if !c.Expect.Bad && nil != err {
				st.Fatalf("unexpected error: %v", err)
			} else if c.Expect.Bad && nil == err {
				st.Fatalf("expect an error")
			}

			if !c.Expect.Bad && got != c.Expect.Address {
				st.Fatalf("invalid address: got %s, expect %s", got,
					c.Expect.Address)
			}
		})
	}
}
