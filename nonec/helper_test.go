// +build golden

package nonec_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestUpdateDecryptGolden(t *testing.T) {
	goldies := []decryptGoldie{
		{
			"uncompressed",
			"TestingOneTwoThree",
			"6PRVWUbkzzsbcVac2qwfssoUJAN1Xhrg6bNk8J7Nzm5H7kxEbn2Nh2ZoGg",
			"5KN7MzqK5wt2TP1fQCYyHBtDrXdJuXbUzm4A9rKAteGu3Qi5CVR",
			"CBF4B9F70470856BB4F40F80B87EDB90865997FFEE6DF315AB166D713AF433A5",
			false,
		},
		{
			"uncompressed",
			"Satoshi",
			"6PRNFFkZc2NZ6dJqFfhRoFNMR9Lnyj7dYGrzdgXXVMXcxoKTePPX1dWByq",
			"5HtasZ6ofTHP6HCwTqTkLDuLQisYPah7aUnSKfC7h4hMUVw2gi5",
			"09C2686880095B1A4C249EE3AC4EEA8A014F11E6F986D0B5025AC1F39AFBD9AE",
			false,
		},
		{
			"uncompressed",
			"\u03D2\u0301\u0000\U00010400\U0001F4A9",
			"6PRW5o9FLp4gJDDVqJQKJFTpMvdsSGJxMYHtHaQBF3ooa8mwD69bapcDQn",
			"5Jajm8eQ22H3pGWLEVCXyvND8dQZhiQhoLJNKjYXk9roUFTMSZ4",
			"64eeab5f9be2a01a8365a579511eb3373c87c40da6d2a25f05bda68fe077b66e",
			false,
		},
		{
			"compressed",
			"TestingOneTwoThree",
			"6PYNKZ1EAgYgmQfmNVamxyXVWHzK5s6DGhwP4J5o44cvXdoY7sRzhtpUeo",
			"L44B5gGEpqEDRS9vVPz7QT35jcBG2r3CZwSwQ4fCewXAhAhqGVpP",
			"CBF4B9F70470856BB4F40F80B87EDB90865997FFEE6DF315AB166D713AF433A5",
			false,
		},
		{
			"compressed",
			"Satoshi",
			"6PYLtMnXvfG3oJde97zRyLYFZCYizPU5T3LwgdYJz1fRhh16bU7u6PPmY7",
			"KwYgW8gcxj1JWJXhPSu4Fqwzfhp5Yfi42mdYmMa4XqK7NJxXUSK7",
			"09C2686880095B1A4C249EE3AC4EEA8A014F11E6F986D0B5025AC1F39AFBD9AE",
			false,
		},
		{
			"invalid flag 0xff",
			"TestingOneTwoThree",
			"6PfJsLhdYx7zGWKeFUNxYxbqdTmN7N3WSkYXpaTQ9X7Bj7kYMHu72yHNm7",
			"", "",
			true,
		},
		{
			"invalid address hash for uncompressed key",
			"TestingOneTwoThree",
			"6PRVWUbkyjKok2rceBDLxQbxyrYTkGTGKitSZ5iDccjM2YX9qj41oAARm4",
			"", "",
			true,
		},
		{
			"invalid address hash for compressed key",
			"TestingOneTwoThree",
			"6PYNKZ1EAvCYGE12C7bgo71L1jsWYMmdpzx7useE4hbQycHowHwuUvv6WE",
			"", "",
			true,
		},
		{
			"invalid length",
			"TestingOneTwoThree",
			"QnVT6tG17jYrX1U6qsA5U4VapHyxpU61AKh2MYQAGWyZGDSQMKbKq9pGF3T",
			"", "",
			true,
		},
		{
			"invalid base58 checksum",
			"TestingOneTwoThree",
			"6PRVWUbkzzsbcVac2qwfssoUJAN1Xhrg6bNk8J7Nzm5H7kxEbn2Nh2ZoGh",
			"", "",
			true,
		},
	}

	const golden = "TestDecrypt.golden"
	fd, err := os.OpenFile(filepath.Join("testdata", golden),
		os.O_CREATE|os.O_RDWR, 0644)
	if nil != err {
		t.Fatal(err)
	}
	defer fd.Close()

	marshaler := json.NewEncoder(fd)
	marshaler.SetIndent("", "  ")
	if err := marshaler.Encode(goldies); nil != err {
		t.Fatal(err)
	}
}
