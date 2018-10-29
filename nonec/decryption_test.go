package nonec_test

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/sammy00/bip38/nonec"
)

func Test_Decrypt(t *testing.T) {
	testCases := []struct {
		passphrase string
		encrypted  string
		expect     string // the expected unencrypted key
	}{
		{
			"TestingOneTwoThree",
			"6PRVWUbkzzsbcVac2qwfssoUJAN1Xhrg6bNk8J7Nzm5H7kxEbn2Nh2ZoGg",
			"CBF4B9F70470856BB4F40F80B87EDB90865997FFEE6DF315AB166D713AF433A5",
		},
		{
			"Satoshi",
			"6PRNFFkZc2NZ6dJqFfhRoFNMR9Lnyj7dYGrzdgXXVMXcxoKTePPX1dWByq",
			"09C2686880095B1A4C249EE3AC4EEA8A014F11E6F986D0B5025AC1F39AFBD9AE",
		},
		{
			"\u03D2\u0301\u0000\U00010400\U0001F4A9",
			"6PRW5o9FLp4gJDDVqJQKJFTpMvdsSGJxMYHtHaQBF3ooa8mwD69bapcDQn",
			"64eeab5f9be2a01a8365a579511eb3373c87c40da6d2a25f05bda68fe077b66e",
		},
		{
			"TestingOneTwoThree",
			"6PYNKZ1EAgYgmQfmNVamxyXVWHzK5s6DGhwP4J5o44cvXdoY7sRzhtpUeo",
			"CBF4B9F70470856BB4F40F80B87EDB90865997FFEE6DF315AB166D713AF433A5",
		},
		{
			"Satoshi",
			"6PYLtMnXvfG3oJde97zRyLYFZCYizPU5T3LwgdYJz1fRhh16bU7u6PPmY7",
			"09C2686880095B1A4C249EE3AC4EEA8A014F11E6F986D0B5025AC1F39AFBD9AE",
		},
	}

	for i, c := range testCases {
		unencrypted, err := nonec.Decrypt(c.encrypted, c.passphrase)
		if nil != err {
			t.Fatalf("#%d failed: unexpected error %v", i, err)
		}

		if rawInHex := hex.EncodeToString(
			unencrypted); !strings.EqualFold(rawInHex, c.expect) {
			t.Fatalf("#%d invalid unencrypted: got %s, expect %s", i,
				rawInHex, c.expect)
		}
	}
}
