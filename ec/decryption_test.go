package ec_test

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/sammy00/bip38/ec"
)

func TestDecrypt(t *testing.T) {
	type expect struct {
		decrypted string
		hasErr    bool
	}

	testCases := []struct {
		encrypted  string
		passphrase string
		expect     expect
	}{
		{
			"6PfQu77ygVyJLZjfvMLyhLMQbYnu5uguoJJ4kMCLqWwPEdfpwANVS76gTX",
			"TestingOneTwoThree",
			expect{
				"A43A940577F4E97F5C4D39EB14FF083A98187C64EA7C99EF7CE460833959A519",
				false,
			},
		},
		{
			"6PfLGnQs6VZnrNpmVKfjotbnQuaJK4KZoPFrAjx1JMJUa1Ft8gnf5WxfKd",
			"Satoshi",
			expect{
				"C2C8036DF268F498099350718C4A3EF3984D2BE84618C2650F5171DCC5EB660A",
				false,
			},
		},
		{
			"6PgNBNNzDkKdhkT6uJntUXwwzQV8Rr2tZcbkDcuC9DZRsS6AtHts4Ypo1j",
			"MOLON LABE",
			expect{
				"44EA95AFBF138356A05EA32110DFD627232D0F2991AD221187BE356F19FA8190",
				false,
			},
		},
		{
			"6PgGWtx25kUg8QWvwuJAgorN6k9FbE25rv5dMRwu5SKMnfpfVe5mar2ngH",
			"ΜΟΛΩΝ ΛΑΒΕ",
			expect{
				"CA2759AA4ADB0F96C414F36ABEB8DB59342985BE9FA50FAAC228C8E7D90E3006",
				false,
			},
		},
		{ // corrupted encrypted part1
			"6PfQu77ygVyJLZjfvMLyC6yJ5ZL5YxH55rpxFNvDEQ42qgGRFAH2CqYosc",
			"TestingOneTwoThree",
			expect{"", true},
		},
		{ // invalid base58 checksum
			"6PfQu77ygVyJLZjfvMLyhLMQbYnu5uguoJJ4kMCLqWwPEdfpwANVS76gTY",
			"TestingOneTwoThree",
			expect{"", true},
		},
	}

	/*
		passphrase := "TestingOneTwoThree"
		encrypted := "6PfQu77ygVyJLZjfvMLyhLMQbYnu5uguoJJ4kMCLqWwPEdfpwANVS76gTX"
		_, payload, _ := encoding.CheckDecode(encrypted, ec.VersionLen)
		for i := byte(0); i < 1; i++ {
			payload[13] = i
			corrupted := encoding.CheckEncode(ec.Version, payload)

			if _, err := ec.Decrypt(corrupted, passphrase); nil != err {
				t.Log(i, err)
				t.Log(corrupted)
			}
		}*/

	for i, c := range testCases {
		decrypted, err := ec.Decrypt(c.encrypted, c.passphrase)

		if c.expect.hasErr && nil == err {
			t.Fatalf("#%d failed: expect error but got none", i)
		} else if !c.expect.hasErr && nil != err {
			t.Fatalf("#%d unexpected error: %v", i, err)
		}

		if decryptedHex := hex.EncodeToString(
			[]byte(decrypted)); !strings.EqualFold(decryptedHex, c.expect.decrypted) {
			t.Fatalf("#%d failed: got %s, expect %s", i, decryptedHex,
				c.expect.decrypted)
		}
	}
}
