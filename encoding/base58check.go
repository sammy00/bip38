package encoding

import (
	"bytes"

	"github.com/sammy00/base58"
)

// CheckDecode decodes the version and payload out of the input base58 string
func CheckDecode(input string, versionLen int) ([]byte, []byte, error) {
	decoded := base58.Decode(input)

	if len(decoded) < 4+versionLen {
		return nil, nil, base58.ErrInvalidFormat
	}

	if cksum := base58.Checksum(decoded[:len(decoded)-4]); !bytes.Equal(
		cksum[:], decoded[len(decoded)-4:]) {
		return nil, nil, base58.ErrChecksum
	}

	version := decoded[:versionLen]
	payload := decoded[versionLen : len(decoded)-4]

	return version, payload, nil
}

// CheckEncode encodes the input data bytes prepended by the given version
// prefix bound to the given mode into a base58 string
func CheckEncode(version, input []byte) string {
	b := make([]byte, 0, len(version)+len(input)+4)
	b = append(b, version...)
	b = append(b, input...)

	cksum := base58.Checksum(b)
	b = append(b, cksum[:]...)

	return base58.Encode(b)
}
