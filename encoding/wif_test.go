package encoding_test

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/sammy00/base58"

	"github.com/sammy00/bip38/encoding"
)

func TestPrivateKeyToWIF(t *testing.T) {
	testCases := []struct {
		priv   string
		expect string
	}{
		{
			"CBF4B9F70470856BB4F40F80B87EDB90865997FFEE6DF315AB166D713AF433A5",
			"5KN7MzqK5wt2TP1fQCYyHBtDrXdJuXbUzm4A9rKAteGu3Qi5CVR",
		},
		{
			"09C2686880095B1A4C249EE3AC4EEA8A014F11E6F986D0B5025AC1F39AFBD9AE",
			"5HtasZ6ofTHP6HCwTqTkLDuLQisYPah7aUnSKfC7h4hMUVw2gi5",
		},
	}

	for i, c := range testCases {
		priv, _ := hex.DecodeString(c.priv)
		if got := encoding.PrivateKeyToWIF(priv); got != c.expect {
			t.Fatalf("#%d failed: got %s, expect %s", i, got, c.expect)
		}
	}
}

func TestPrivateKeyToWIFCompressed(t *testing.T) {
	testCases := []struct {
		priv   string
		expect string
	}{
		{
			"CBF4B9F70470856BB4F40F80B87EDB90865997FFEE6DF315AB166D713AF433A5",
			"L44B5gGEpqEDRS9vVPz7QT35jcBG2r3CZwSwQ4fCewXAhAhqGVpP",
		},
		{
			"09C2686880095B1A4C249EE3AC4EEA8A014F11E6F986D0B5025AC1F39AFBD9AE",
			"KwYgW8gcxj1JWJXhPSu4Fqwzfhp5Yfi42mdYmMa4XqK7NJxXUSK7",
		},
	}

	for i, c := range testCases {
		priv, _ := hex.DecodeString(c.priv)
		if got := encoding.PrivateKeyToWIFCompressed(priv); got != c.expect {
			t.Fatalf("#%d failed: got %s, expect %s", i, got, c.expect)
		}
	}
}

func TestWIFToPrivateKey(t *testing.T) {
	type expect struct {
		priv string
		err  error
	}

	testCases := []struct {
		wif    string
		expect expect
	}{
		{
			"5KN7MzqK5wt2TP1fQCYyHBtDrXdJuXbUzm4A9rKAteGu3Qi5CVR",
			expect{
				"CBF4B9F70470856BB4F40F80B87EDB90865997FFEE6DF315AB166D713AF433A5",
				nil,
			},
		},
		{
			"5HtasZ6ofTHP6HCwTqTkLDuLQisYPah7aUnSKfC7h4hMUVw2gi5",
			expect{
				"09C2686880095B1A4C249EE3AC4EEA8A014F11E6F986D0B5025AC1F39AFBD9AE",
				nil,
			},
		},
		{
			"L44B5gGEpqEDRS9vVPz7QT35jcBG2r3CZwSwQ4fCewXAhAhqGVpP",
			expect{
				"CBF4B9F70470856BB4F40F80B87EDB90865997FFEE6DF315AB166D713AF433A501",
				nil,
			},
		},
		{
			"KwYgW8gcxj1JWJXhPSu4Fqwzfhp5Yfi42mdYmMa4XqK7NJxXUSK7",
			expect{
				// note the 0x01 suffix to signal compression
				"09C2686880095B1A4C249EE3AC4EEA8A014F11E6F986D0B5025AC1F39AFBD9AE01",
				nil,
			},
		},
		{
			// mutate 7->8 to corrupt the checksum
			"KwYgW8gcxj1JWJXhPSu4Fqwzfhp5Yfi42mdYmMa4XqK7NJxXUSK8",
			expect{"", base58.ErrChecksum},
		},
	}

	for i, c := range testCases {
		priv, err := encoding.WIFToPrivateKey(c.wif)

		if privHex := hex.EncodeToString(
			priv); !strings.EqualFold(privHex, c.expect.priv) {
			t.Fatalf("#%d invalid private key: got %s, expect %s", i, privHex,
				c.expect.priv)
		}

		if err != c.expect.err {
			t.Fatalf("#%d unexpected error: got %v, expect %v", i, err, c.expect.err)
		}
	}
}
