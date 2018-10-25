package hash

import (
	"crypto/sha256"
)

// DoubleSum calculates SHA256(SHA256(data))
func DoubleSum(data []byte) []byte {
	digest := sha256.Sum256(data)
	digest = sha256.Sum256(digest[:])

	return digest[:]
}
