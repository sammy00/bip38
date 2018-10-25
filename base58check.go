package bip38

import "github.com/sammy00/base58"

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
	//result = append(result, payload...)

	return payload, version, nil
}

func CheckEncode(input []byte, version [versionLen]byte) string {
	b := make([]byte, 0, versionLen+len(input)+4)
	b = append(b, version[:]...)
	b = append(b, input[:]...)

	cksum := base58.Checksum(b)
	b = append(b, cksum[:]...)

	return base58.Encode(b)
}
