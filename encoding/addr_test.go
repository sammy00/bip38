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
	}

	for i, c := range testCases {
		data, _ := hex.DecodeString(c.pub)

		if got := encoding.PublicKeyToAddress(data); got != c.expect {
			t.Fatalf("#%d invalid address: got %s, expect %s", i, got, c.expect)
		}
	}
}
