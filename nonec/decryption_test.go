package nonec_test

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/sammy00/bip38/encoding"
	"github.com/sammy00/bip38/nonec"
)

func Test_Decrypt(t *testing.T) {
	type expect struct {
		decrypted string
		hasErr    bool
	}

	testCases := []struct {
		passphrase string
		encrypted  string
		expect     expect
	}{
		{ // uncompressed
			"TestingOneTwoThree",
			"6PRVWUbkzzsbcVac2qwfssoUJAN1Xhrg6bNk8J7Nzm5H7kxEbn2Nh2ZoGg",
			expect{
				"CBF4B9F70470856BB4F40F80B87EDB90865997FFEE6DF315AB166D713AF433A5",
				false,
			},
		},
		{ // uncompressed
			"Satoshi",
			"6PRNFFkZc2NZ6dJqFfhRoFNMR9Lnyj7dYGrzdgXXVMXcxoKTePPX1dWByq",
			expect{
				"09C2686880095B1A4C249EE3AC4EEA8A014F11E6F986D0B5025AC1F39AFBD9AE",
				false,
			},
		},
		{ // uncompressed
			"\u03D2\u0301\u0000\U00010400\U0001F4A9",
			"6PRW5o9FLp4gJDDVqJQKJFTpMvdsSGJxMYHtHaQBF3ooa8mwD69bapcDQn",
			expect{
				"64eeab5f9be2a01a8365a579511eb3373c87c40da6d2a25f05bda68fe077b66e",
				false,
			},
		},
		{ // compressed
			"TestingOneTwoThree",
			"6PYNKZ1EAgYgmQfmNVamxyXVWHzK5s6DGhwP4J5o44cvXdoY7sRzhtpUeo",
			expect{
				"CBF4B9F70470856BB4F40F80B87EDB90865997FFEE6DF315AB166D713AF433A5",
				false,
			},
		},
		{ // compressed
			"Satoshi",
			"6PYLtMnXvfG3oJde97zRyLYFZCYizPU5T3LwgdYJz1fRhh16bU7u6PPmY7",
			expect{
				"09C2686880095B1A4C249EE3AC4EEA8A014F11E6F986D0B5025AC1F39AFBD9AE",
				false,
			},
		},
		{ // invalid flag 0xff
			"TestingOneTwoThree",
			"6PfJsLhdYx7zGWKeFUNxYxbqdTmN7N3WSkYXpaTQ9X7Bj7kYMHu72yHNm7",
			expect{"", true},
		},
		{ // invalid address hash for uncompressed key
			"TestingOneTwoThree",
			"6PRVWUbkyjKok2rceBDLxQbxyrYTkGTGKitSZ5iDccjM2YX9qj41oAARm4",
			expect{"", true},
		},
		{ // invalid address hash for compressed key
			"TestingOneTwoThree",
			"6PYNKZ1EAvCYGE12C7bgo71L1jsWYMmdpzx7useE4hbQycHowHwuUvv6WE",
			expect{"", true},
		},
		{ // invalid length
			"TestingOneTwoThree",
			"QnVT6tG17jYrX1U6qsA5U4VapHyxpU61AKh2MYQAGWyZGDSQMKbKq9pGF3T",
			expect{"", true},
		},
		{ // invalid base58 checksum
			"TestingOneTwoThree",
			"6PRVWUbkzzsbcVac2qwfssoUJAN1Xhrg6bNk8J7Nzm5H7kxEbn2Nh2ZoGh",
			expect{"", true},
		},
	}

	//encrypted := "6PRVWUbkzzsbcVac2qwfssoUJAN1Xhrg6bNk8J7Nzm5H7kxEbn2Nh2ZoGg"
	encrypted := "6PYNKZ1EAgYgmQfmNVamxyXVWHzK5s6DGhwP4J5o44cvXdoY7sRzhtpUeo"
	version, payload, _ := encoding.CheckDecode(encrypted, nonec.VersionLen)
	t.Logf("%02x", payload)
	//payload[5] ^= 0xff
	payload = append(payload, 0xff)
	t.Log(encoding.CheckEncode(version, payload))

	for i, c := range testCases {
		unencrypted, err := nonec.Decrypt(c.encrypted, c.passphrase)

		if c.expect.hasErr && nil == err {
			t.Fatalf("#%d expect error but got none", i)
		} else if !c.expect.hasErr && nil != err {
			t.Fatalf("#%d failed: unexpected error %v", i, err)
		}

		if rawInHex := hex.EncodeToString(unencrypted); !c.expect.hasErr &&
			!strings.EqualFold(rawInHex, c.expect.decrypted) {
			t.Fatalf("#%d invalid unencrypted: got %s, expect %s", i,
				rawInHex, c.expect.decrypted)
		}
	}
}
