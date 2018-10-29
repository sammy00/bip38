package bytes_test

import (
	gobytes "bytes"
	"testing"

	"github.com/sammy00/bip38/bytes"
)

func TestXOR(t *testing.T) {
	testCases := []struct {
		x, y []byte
		z    []byte
	}{
		{
			[]byte{0x12, 0x34, 0x56, 0x78},
			[]byte{0x10, 0x30, 0x50, 0x70},
			[]byte{0x02, 0x04, 0x06, 0x08},
		},
	}

	for i, c := range testCases {
		z := make([]byte, len(c.z))
		bytes.XOR(z, c.x, c.y)

		if !gobytes.Equal(z, c.z) {
			t.Fatalf("#%d invalid z: got %x, expect %x", i, z, c.z)
		}
	}
}
