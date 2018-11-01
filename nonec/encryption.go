package nonec

import (
	"crypto/aes"

	"github.com/sammy00/bip38/bytes"
	"github.com/sammy00/bip38/encoding"
	"github.com/sammy00/bip38/hash"
	"golang.org/x/text/unicode/norm"

	"golang.org/x/crypto/scrypt"
)

// Encrypt encrypts the given private key (32 bytes) byte sequence
// with the given passphrase
func Encrypt(data []byte, passphrase string, compressed bool) (
	string, error) {

	var addrHash []byte
	if compressed {
		addrHash = hash.AddressChecksum(data, true)
	} else {
		addrHash = hash.AddressChecksum(data, false)
	}

	dk, _ := scrypt.Key(norm.NFC.Bytes([]byte(passphrase)),
		addrHash, N, R, P, KeyLen)

	var payload [37]byte
	if compressed {
		payload[0] = Compressed
	} else {
		payload[0] = Uncompressed
	}
	copy(payload[1:], addrHash) // append salt

	C, _ := aes.NewCipher(dk[32:])

	var block [32]byte
	bytes.XOR(block[:], data, dk[:32])
	C.Encrypt(payload[5:], block[:16])
	C.Encrypt(payload[21:], block[16:])

	return encoding.CheckEncode(Version, payload[:]), nil
}
