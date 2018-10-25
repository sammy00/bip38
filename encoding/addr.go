package encoding

import (
	"crypto/sha256"

	"github.com/sammy00/base58"
	"golang.org/x/crypto/ripemd160"
)

func PublicKeyToAddress(pub []byte) string {
	data := sha256.Sum256(pub)

	ripemd := ripemd160.New()
	ripemd.Write(data[:])

	payload := ripemd.Sum(nil)

	return base58.CheckEncode(payload[:], 0x00)
	//return payload[:]
}
