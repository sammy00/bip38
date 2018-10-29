package encoding_test

import (
	"testing"

	"github.com/sammy00/bip38/encoding"
)

func TestPublicKeyToAddress(t *testing.T) {
	testCases := []struct {
		pub    []byte
		expect string
	}{}

	for i, c := range testCases {
		if got := encoding.PublicKeyToAddress(c.pub); got != c.expect {
			t.Fatalf("#%d invalid address: got %s, expect %s", i, got, c.expect)
		}
	}
}
