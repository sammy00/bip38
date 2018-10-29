package nonec_test

import (
	"encoding/hex"
	"testing"

	"github.com/sammy00/bip38/encoding"
	"github.com/sammy00/bip38/nonec"
)

func Test_Encrypt(t *testing.T) {
	testCases := []struct {
		passphrase     string
		encrypted      string
		unencryptedWIF string
		unencryptedHex string
		mode           nonec.EncryptionMode
	}{
		{
			"TestingOneTwoThree",
			"6PRVWUbkzzsbcVac2qwfssoUJAN1Xhrg6bNk8J7Nzm5H7kxEbn2Nh2ZoGg",
			"5KN7MzqK5wt2TP1fQCYyHBtDrXdJuXbUzm4A9rKAteGu3Qi5CVR",
			"CBF4B9F70470856BB4F40F80B87EDB90865997FFEE6DF315AB166D713AF433A5",
			nonec.UncompressedNoECMultiply,
		},
		{
			"Satoshi",
			"6PRNFFkZc2NZ6dJqFfhRoFNMR9Lnyj7dYGrzdgXXVMXcxoKTePPX1dWByq",
			"5HtasZ6ofTHP6HCwTqTkLDuLQisYPah7aUnSKfC7h4hMUVw2gi5",
			"09C2686880095B1A4C249EE3AC4EEA8A014F11E6F986D0B5025AC1F39AFBD9AE",
			nonec.UncompressedNoECMultiply,
		},
		{
			"\u03D2\u0301\u0000\U00010400\U0001F4A9",
			"6PRW5o9FLp4gJDDVqJQKJFTpMvdsSGJxMYHtHaQBF3ooa8mwD69bapcDQn",
			//"16ktGzmfrurhbhi6JGqsMWf7TyqK9HNAeF"
			"5Jajm8eQ22H3pGWLEVCXyvND8dQZhiQhoLJNKjYXk9roUFTMSZ4",
			"64eeab5f9be2a01a8365a579511eb3373c87c40da6d2a25f05bda68fe077b66e",
			nonec.UncompressedNoECMultiply,
		},
		{
			"TestingOneTwoThree",
			"6PYNKZ1EAgYgmQfmNVamxyXVWHzK5s6DGhwP4J5o44cvXdoY7sRzhtpUeo",
			"L44B5gGEpqEDRS9vVPz7QT35jcBG2r3CZwSwQ4fCewXAhAhqGVpP",
			"CBF4B9F70470856BB4F40F80B87EDB90865997FFEE6DF315AB166D713AF433A5",
			nonec.CompressedNoECMultiply,
		},
		{
			"Satoshi",
			"6PYLtMnXvfG3oJde97zRyLYFZCYizPU5T3LwgdYJz1fRhh16bU7u6PPmY7",
			"KwYgW8gcxj1JWJXhPSu4Fqwzfhp5Yfi42mdYmMa4XqK7NJxXUSK7",
			"09C2686880095B1A4C249EE3AC4EEA8A014F11E6F986D0B5025AC1F39AFBD9AE",
			nonec.CompressedNoECMultiply,
		},
	}

	for i, c := range testCases {
		raw, _ := hex.DecodeString(c.unencryptedHex)

		switch c.mode {
		case nonec.UncompressedNoECMultiply:
			if wif := encoding.PrivateKeyToWIF(raw); wif != c.unencryptedWIF {
				t.Fatalf("#%d invalid wif: got %s, expect %s", i, wif, c.unencryptedWIF)
			}
		case nonec.CompressedNoECMultiply:
			if wif := encoding.PrivateKeyToWIFCompressed(
				raw); wif != c.unencryptedWIF {
				t.Fatalf("#%d invalid wif-compressed: got %s, expect %s", i, wif,
					c.unencryptedWIF)
			}
		}

		cipher, err := nonec.Encrypt(raw, c.passphrase, c.mode)
		if nil != err {
			t.Fatalf("#%d failed: unexpected error %v", i, err)
		}
		if cipher != c.encrypted {
			t.Fatalf("#%d invalid cipher text: got %s, expect %s", i,
				cipher, c.encrypted)
		}
	}
}
