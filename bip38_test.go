package bip38_test

import (
	"encoding/hex"
	"testing"

	"github.com/sammy00/bip38"
	"github.com/sammy00/bip38/encoding"
)

func Test_Encrypt(t *testing.T) {
	testCases := []struct {
		passphrase     string
		encrypted      string
		unencryptedWIF string
		unencryptedHex string
	}{
		{
			"TestingOneTwoThree",
			"6PRVWUbkzzsbcVac2qwfssoUJAN1Xhrg6bNk8J7Nzm5H7kxEbn2Nh2ZoGg",
			"5KN7MzqK5wt2TP1fQCYyHBtDrXdJuXbUzm4A9rKAteGu3Qi5CVR",
			"CBF4B9F70470856BB4F40F80B87EDB90865997FFEE6DF315AB166D713AF433A5",
		},
		{
			"Satoshi",
			"6PRNFFkZc2NZ6dJqFfhRoFNMR9Lnyj7dYGrzdgXXVMXcxoKTePPX1dWByq",
			"5HtasZ6ofTHP6HCwTqTkLDuLQisYPah7aUnSKfC7h4hMUVw2gi5",
			"09C2686880095B1A4C249EE3AC4EEA8A014F11E6F986D0B5025AC1F39AFBD9AE",
		},
		{
			"\u03D2\u0301\u0000\U00010400\U0001F4A9",
			"6PRW5o9FLp4gJDDVqJQKJFTpMvdsSGJxMYHtHaQBF3ooa8mwD69bapcDQn",
			//"16ktGzmfrurhbhi6JGqsMWf7TyqK9HNAeF"
			"5Jajm8eQ22H3pGWLEVCXyvND8dQZhiQhoLJNKjYXk9roUFTMSZ4",
			"64eeab5f9be2a01a8365a579511eb3373c87c40da6d2a25f05bda68fe077b66e",
		},
	}

	for i, c := range testCases {
		raw, _ := hex.DecodeString(c.unencryptedHex)

		if wif := encoding.PrivateKeyToWIF(raw); wif != c.unencryptedWIF {
			t.Fatalf("#%d failed: got %s, expect %s", i, wif, c.unencryptedWIF)
		}

		cipher, err := bip38.Encrypt(raw, c.passphrase)
		if nil != err {
			t.Fatalf("#%d failed: unexpected error %v", i, err)
		}
		if cipher != c.encrypted {
			t.Fatalf("#%d invalid cipher text: got %s, expect %s", i,
				cipher, c.encrypted)
		}
	}
}
