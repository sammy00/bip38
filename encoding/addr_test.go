package encoding_test

import (
	"encoding/hex"
	"testing"

	"github.com/sammy00/bip38/encoding"
)

func TestPublicKeyToAddress(t *testing.T) {
	testCases := []struct {
		pub    string // in hex
		expect string
	}{
		{ // 1st input from tx 40d9589620c4f3b98c14f9a4899290bb6a80ad4f940ad27b6175914783600a80
			"0310a579f303588a1b537bbd6f994a50091d578a8e472dc5b1b81019baddf90e91",
			"1LJUysBLbJ3BCycP8KiFhUhwzDVqRChZBM",
		},
		{ // 2nd input from tx 40d9589620c4f3b98c14f9a4899290bb6a80ad4f940ad27b6175914783600a80
			"030a66c66da4b4aa9bfbca8f042465166866fdb55718009e9adec061f90d0960f2",
			"18UhXJZvGJrSrocWPg8jeUJruDJYJy5F9Y",
		},
		{ // from example-4-6 in mastering-bitcoin-2ed
			"045c0de3b9c8ab18dd04e3511243ec2952002dbfadc864b9628910169d9b9b00ec243bcefdd4347074d44bd7356d6a53c495737dd96295e2a9374bf5f02ebfc176",
			"1thMirt546nngXqyPEz532S8fLwbozud8",
		},
		{ // 1st input from tx 7e3ab0ea65b60f7d1ff4b231016fc958bc0766a46770410caa0a1855459b6e41
			"047146f0e0fcb3139947cf0beb870fe251930ca10d4545793d31033e801b5219abf56c11a3cf3406ca590e4c14b0dab749d20862b3adc4709153c280c2a78be10c",
			"17A16QmavnUfCW11DAApiJxp7ARnxN5pGX",
		},
	}

	for i, c := range testCases {
		data, _ := hex.DecodeString(c.pub)

		if got := encoding.PublicKeyToAddress(data); got != c.expect {
			t.Fatalf("#%d invalid address: got %s, expect %s", i, got, c.expect)
		}
	}
}
