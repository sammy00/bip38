package hash_test

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/sammy00/bip38/hash"
)

func TestAddressChecksum(t *testing.T) {
	testCases := []struct {
		priv       string
		compressed bool
		expect     []byte
	}{
		{
			"A43A940577F4E97F5C4D39EB14FF083A98187C64EA7C99EF7CE460833959A519",
			false,
			[]byte{0x62, 0xb5, 0xb7, 0x22},
		},
		{
			"A43A940577F4E97F5C4D39EB14FF083A98187C64EA7C99EF7CE460833959A519",
			true,
			[]byte{0x2e, 0xd1, 0x46, 0x9a},
		},
		{
			"C2C8036DF268F498099350718C4A3EF3984D2BE84618C2650F5171DCC5EB660A",
			false,
			[]byte{0x05, 0x9a, 0x54, 0x81},
		},
		{
			"C2C8036DF268F498099350718C4A3EF3984D2BE84618C2650F5171DCC5EB660A",
			true,
			[]byte{0xb6, 0x46, 0xa1, 0x57},
		},
		{
			"44EA95AFBF138356A05EA32110DFD627232D0F2991AD221187BE356F19FA8190",
			false,
			[]byte{0xbb, 0x45, 0x8c, 0xef},
		},
		{
			"44EA95AFBF138356A05EA32110DFD627232D0F2991AD221187BE356F19FA8190",
			true,
			[]byte{0xe5, 0xdd, 0x42, 0xe5},
		},
		{
			"CA2759AA4ADB0F96C414F36ABEB8DB59342985BE9FA50FAAC228C8E7D90E3006",
			false,
			[]byte{0x49, 0x4a, 0xf1, 0x36},
		},
		{
			"CA2759AA4ADB0F96C414F36ABEB8DB59342985BE9FA50FAAC228C8E7D90E3006",
			true,
			[]byte{0x03, 0xb9, 0x35, 0x14},
		},
	}

	for i, c := range testCases {
		priv, _ := hex.DecodeString(c.priv)
		if got := hash.AddressChecksum(priv,
			c.compressed); !bytes.Equal(got, c.expect) {
			t.Logf("% 02x", got)
			t.Fatalf("#%d failed: got %x, expect %x", i, got, c.expect)
		}
	}
}
