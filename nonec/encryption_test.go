package nonec_test

import (
	"encoding/hex"
	"testing"

	"github.com/sammy00/bip38/nonec"
)

func Test_Encrypt(t *testing.T) {
	testCases := []struct {
		unencryptedHex string
		passphrase     string
		compressed     bool
		expect         string // the expected encrypted private key
	}{
		{
			"CBF4B9F70470856BB4F40F80B87EDB90865997FFEE6DF315AB166D713AF433A5",
			"TestingOneTwoThree",
			false,
			"6PRVWUbkzzsbcVac2qwfssoUJAN1Xhrg6bNk8J7Nzm5H7kxEbn2Nh2ZoGg",
		},
		{
			"09C2686880095B1A4C249EE3AC4EEA8A014F11E6F986D0B5025AC1F39AFBD9AE",
			"Satoshi",
			false,
			"6PRNFFkZc2NZ6dJqFfhRoFNMR9Lnyj7dYGrzdgXXVMXcxoKTePPX1dWByq",
		},
		{
			"64eeab5f9be2a01a8365a579511eb3373c87c40da6d2a25f05bda68fe077b66e",
			"\u03D2\u0301\u0000\U00010400\U0001F4A9",
			false,
			"6PRW5o9FLp4gJDDVqJQKJFTpMvdsSGJxMYHtHaQBF3ooa8mwD69bapcDQn",
		},
		{
			"CBF4B9F70470856BB4F40F80B87EDB90865997FFEE6DF315AB166D713AF433A5",
			"TestingOneTwoThree",
			true,
			"6PYNKZ1EAgYgmQfmNVamxyXVWHzK5s6DGhwP4J5o44cvXdoY7sRzhtpUeo",
		},
		{
			"09C2686880095B1A4C249EE3AC4EEA8A014F11E6F986D0B5025AC1F39AFBD9AE",
			"Satoshi",
			true,
			"6PYLtMnXvfG3oJde97zRyLYFZCYizPU5T3LwgdYJz1fRhh16bU7u6PPmY7",
		},
	}

	for i, c := range testCases {
		raw, _ := hex.DecodeString(c.unencryptedHex)

		encrypted, err := nonec.Encrypt(raw, c.passphrase, c.compressed)
		if nil != err {
			t.Fatalf("#%d failed: unexpected error %v", i, err)
		}
		if encrypted != c.expect {
			t.Fatalf("#%d invalid encrypted key: got %s, expect %s", i,
				encrypted, c.expect)
		}
	}
}