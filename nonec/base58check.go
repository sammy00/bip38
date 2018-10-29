package nonec

import (
	"bytes"
	"errors"

	"github.com/sammy00/base58"
)

// CheckDecode decodes payload and version prefix out of the input base58 string
func CheckDecode(input string) ([]byte, EncryptionMode, error) {
	decoded := base58.Decode(input)

	if len(decoded) < 4+versionLen {
		return nil, Reserved, base58.ErrInvalidFormat
	}

	var mode EncryptionMode
	switch {
	case bytes.Equal(decoded[:versionLen], versions[UncompressedNoECMultiply][:]):
		mode = UncompressedNoECMultiply
	case bytes.Equal(decoded[:versionLen], versions[CompressedNoECMultiply][:]):
		mode = CompressedNoECMultiply
	case bytes.Equal(decoded[:versionLen], versions[UncompressedECMultiply][:]):
		mode = UncompressedECMultiply
	case bytes.Equal(decoded[:versionLen], versions[CompressedECMultiply][:]):
		mode = CompressedECMultiply
	default:
		return nil, Reserved, errors.New("invalid encryption mode")
	}

	if cksum := base58.Checksum(decoded[:len(decoded)-4]); !bytes.Equal(
		cksum[:], decoded[len(decoded)-4:]) {
		return nil, Reserved, base58.ErrChecksum
	}

	//var cksum [4]byte
	//copy(cksum[:], decoded[len(decoded)-4:])
	//if base58.Checksum(decoded[:len(decoded)-4]) != cksum {
	//	return nil, Reserved, base58.ErrChecksum
	//}

	payload := decoded[versionLen : len(decoded)-4]

	return payload, mode, nil
}

// CheckEncode encodes the input data bytes prepended by the given version
// prefix bound to the given mode into a base58 string
func CheckEncode(input []byte, mode EncryptionMode) string {
	b := make([]byte, 0, versionLen+len(input)+4)
	b = append(b, versions[mode][:]...)
	b = append(b, input[:]...)

	cksum := base58.Checksum(b)
	b = append(b, cksum[:]...)

	return base58.Encode(b)
}
