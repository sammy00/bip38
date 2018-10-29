package ec_test

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/sammy00/bip38/ec"
)

func TestDecrypt(t *testing.T) {
	testCases := []struct {
		encrypted  string
		passphrase string
		expect     string
	}{
		{
			"6PfQu77ygVyJLZjfvMLyhLMQbYnu5uguoJJ4kMCLqWwPEdfpwANVS76gTX",
			"TestingOneTwoThree",
			"A43A940577F4E97F5C4D39EB14FF083A98187C64EA7C99EF7CE460833959A519",
		},
		{
			"6PfLGnQs6VZnrNpmVKfjotbnQuaJK4KZoPFrAjx1JMJUa1Ft8gnf5WxfKd",
			"Satoshi",
			"C2C8036DF268F498099350718C4A3EF3984D2BE84618C2650F5171DCC5EB660A",
		},
		{
			"6PgNBNNzDkKdhkT6uJntUXwwzQV8Rr2tZcbkDcuC9DZRsS6AtHts4Ypo1j",
			"MOLON LABE",
			"44EA95AFBF138356A05EA32110DFD627232D0F2991AD221187BE356F19FA8190",
		},
		{
			"6PgGWtx25kUg8QWvwuJAgorN6k9FbE25rv5dMRwu5SKMnfpfVe5mar2ngH",
			"ΜΟΛΩΝ ΛΑΒΕ",
			"CA2759AA4ADB0F96C414F36ABEB8DB59342985BE9FA50FAAC228C8E7D90E3006",
		},
	}

	for i, c := range testCases {
		decrypted, err := ec.Decrypt(c.encrypted, c.passphrase)
		if nil != err {
			t.Fatalf("#%d unexpected error: %v", i, err)
		}

		if decryptedHex := hex.EncodeToString(
			[]byte(decrypted)); !strings.EqualFold(decryptedHex, c.expect) {
			t.Fatalf("#%d failed: got %s, expect %s", i, decryptedHex,
				c.expect)
		}
	}
}
