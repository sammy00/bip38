package bip38

import "github.com/sammy00/base58"

// CheckDecode decodes payload and version prefix out of the input base58 string
func CheckDecode(input string) ([]byte, [versionLen]byte, error) {
	decoded := base58.Decode(input)

	var version [versionLen]byte
	if len(decoded) < 7 {
		return nil, version, base58.ErrInvalidFormat
	}

	copy(version[:], decoded[:versionLen])

	var cksum [4]byte
	copy(cksum[:], decoded[len(decoded)-4:])
	if base58.Checksum(decoded[:len(decoded)-4]) != cksum {
		return nil, version, base58.ErrChecksum
	}

	payload := decoded[versionLen : len(decoded)-4]

	return payload, version, nil
}

// CheckEncode encodes the input data bytes prepended by the given version
// into a base58 string
func CheckEncode(input []byte, version [versionLen]byte) string {
	b := make([]byte, 0, versionLen+len(input)+4)
	b = append(b, version[:]...)
	b = append(b, input[:]...)

	cksum := base58.Checksum(b)
	b = append(b, cksum[:]...)

	return base58.Encode(b)
}
