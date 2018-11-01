// +build golden

package nonec_test

import (
	"testing"

	"github.com/sammy00/bip38/internal/xtesting"
)

func TestUpdateDecryptGolden(t *testing.T) {
	goldies := []decryptGoldie{
		{
			"uncompressed",
			"TestingOneTwoThree",
			"6PRVWUbkzzsbcVac2qwfssoUJAN1Xhrg6bNk8J7Nzm5H7kxEbn2Nh2ZoGg",
			"5KN7MzqK5wt2TP1fQCYyHBtDrXdJuXbUzm4A9rKAteGu3Qi5CVR",
			decryptExpect{

				"CBF4B9F70470856BB4F40F80B87EDB90865997FFEE6DF315AB166D713AF433A5",
				false,
			},
		},
		{
			"uncompressed",
			"Satoshi",
			"6PRNFFkZc2NZ6dJqFfhRoFNMR9Lnyj7dYGrzdgXXVMXcxoKTePPX1dWByq",
			"5HtasZ6ofTHP6HCwTqTkLDuLQisYPah7aUnSKfC7h4hMUVw2gi5",
			decryptExpect{
				"09C2686880095B1A4C249EE3AC4EEA8A014F11E6F986D0B5025AC1F39AFBD9AE",
				false,
			},
		},
		{
			"uncompressed",
			"\u03D2\u0301\u0000\U00010400\U0001F4A9",
			"6PRW5o9FLp4gJDDVqJQKJFTpMvdsSGJxMYHtHaQBF3ooa8mwD69bapcDQn",
			"5Jajm8eQ22H3pGWLEVCXyvND8dQZhiQhoLJNKjYXk9roUFTMSZ4",
			decryptExpect{
				"64eeab5f9be2a01a8365a579511eb3373c87c40da6d2a25f05bda68fe077b66e",
				false,
			},
		},
		{
			"compressed",
			"TestingOneTwoThree",
			"6PYNKZ1EAgYgmQfmNVamxyXVWHzK5s6DGhwP4J5o44cvXdoY7sRzhtpUeo",
			"L44B5gGEpqEDRS9vVPz7QT35jcBG2r3CZwSwQ4fCewXAhAhqGVpP",
			decryptExpect{
				"CBF4B9F70470856BB4F40F80B87EDB90865997FFEE6DF315AB166D713AF433A5",
				false,
			},
		},
		{
			"compressed",
			"Satoshi",
			"6PYLtMnXvfG3oJde97zRyLYFZCYizPU5T3LwgdYJz1fRhh16bU7u6PPmY7",
			"KwYgW8gcxj1JWJXhPSu4Fqwzfhp5Yfi42mdYmMa4XqK7NJxXUSK7",
			decryptExpect{
				"09C2686880095B1A4C249EE3AC4EEA8A014F11E6F986D0B5025AC1F39AFBD9AE",
				false,
			},
		},
		{
			"invalid flag 0xff",
			"TestingOneTwoThree",
			"6PfJsLhdYx7zGWKeFUNxYxbqdTmN7N3WSkYXpaTQ9X7Bj7kYMHu72yHNm7",
			"",
			decryptExpect{
				"",
				true,
			},
		},
		{
			"invalid address hash for uncompressed key",
			"TestingOneTwoThree",
			"6PRVWUbkyjKok2rceBDLxQbxyrYTkGTGKitSZ5iDccjM2YX9qj41oAARm4",
			"",
			decryptExpect{
				"",
				true,
			},
		},
		{
			"invalid address hash for compressed key",
			"TestingOneTwoThree",
			"6PYNKZ1EAvCYGE12C7bgo71L1jsWYMmdpzx7useE4hbQycHowHwuUvv6WE",
			"",
			decryptExpect{
				"",
				true,
			},
		},
		{
			"invalid length",
			"TestingOneTwoThree",
			"QnVT6tG17jYrX1U6qsA5U4VapHyxpU61AKh2MYQAGWyZGDSQMKbKq9pGF3T",
			"",
			decryptExpect{
				"",
				true,
			},
		},
		{
			"invalid base58 checksum",
			"TestingOneTwoThree",
			"6PRVWUbkzzsbcVac2qwfssoUJAN1Xhrg6bNk8J7Nzm5H7kxEbn2Nh2ZoGh",
			"",
			decryptExpect{
				"",
				true,
			},
		},
	}

	/*
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
	*/
	xtesting.EncodeGoldenToJSON(t, "Decrypt", goldies)
}

func TestUpdateEncryptGolden(t *testing.T) {
	goldies := []encryptGoldie{
		{
			"uncompressed",
			"CBF4B9F70470856BB4F40F80B87EDB90865997FFEE6DF315AB166D713AF433A5",
			"TestingOneTwoThree",
			false,
			"6PRVWUbkzzsbcVac2qwfssoUJAN1Xhrg6bNk8J7Nzm5H7kxEbn2Nh2ZoGg",
		},
		{
			"uncompressed",
			"09C2686880095B1A4C249EE3AC4EEA8A014F11E6F986D0B5025AC1F39AFBD9AE",
			"Satoshi",
			false,
			"6PRNFFkZc2NZ6dJqFfhRoFNMR9Lnyj7dYGrzdgXXVMXcxoKTePPX1dWByq",
		},
		{
			"uncompressed",
			"64eeab5f9be2a01a8365a579511eb3373c87c40da6d2a25f05bda68fe077b66e",
			"\u03D2\u0301\u0000\U00010400\U0001F4A9",
			false,
			"6PRW5o9FLp4gJDDVqJQKJFTpMvdsSGJxMYHtHaQBF3ooa8mwD69bapcDQn",
		},
		{
			"uncompressed",
			"CBF4B9F70470856BB4F40F80B87EDB90865997FFEE6DF315AB166D713AF433A5",
			"TestingOneTwoThree",
			true,
			"6PYNKZ1EAgYgmQfmNVamxyXVWHzK5s6DGhwP4J5o44cvXdoY7sRzhtpUeo",
		},
		{
			"uncompressed",
			"09C2686880095B1A4C249EE3AC4EEA8A014F11E6F986D0B5025AC1F39AFBD9AE",
			"Satoshi",
			true,
			"6PYLtMnXvfG3oJde97zRyLYFZCYizPU5T3LwgdYJz1fRhh16bU7u6PPmY7",
		},
	}

	/*
		const golden = "TestEncrypt.golden"
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
	*/

	xtesting.EncodeGoldenToJSON(t, "Encrypt", goldies)
}
