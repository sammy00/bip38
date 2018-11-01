package ec_test

import (
	"testing"

	"github.com/sammy00/bip38/internal/xtesting"

	"github.com/sammy00/bip38/ec"
)

func TestGenerateConfirmationCode(t *testing.T) {
	var testCases []cfrmCodeGoldie
	xtesting.DecodeGoldenJSON(t, t.Name(), &testCases)

	for i, c := range testCases {
		got, _ := ec.GenerateConfirmationCode(c.Flag, c.AddrHash, c.OwnerEntropy,
			c.B, c.DerivedHalf1, c.DerivedHalf2)
		if got != c.ConfirmationCode {
			t.Fatalf("#%d failed: got %s, expect %s", i, got, c.ConfirmationCode)
		}
	}
}

func TestRecoverAddress(t *testing.T) {
	var testCases []recoverAddressGoldie
	xtesting.DecodeGoldenJSON(t, t.Name(), &testCases)

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
