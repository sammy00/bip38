package nonec

import (
	"crypto/aes"
	"errors"

	"github.com/sammy00/bip38/bytes"
	"github.com/sammy00/bip38/encoding"
	"github.com/sammy00/bip38/hash"
	"golang.org/x/text/unicode/norm"

	"golang.org/x/crypto/scrypt"
)

// Encrypt encrypts the given private key byte sequence
// with the given passphrase
func Encrypt(data []byte, passphrase string, mode EncryptionMode) (
	string, error) {

	var addrHash []byte
	switch mode {
	case UncompressedNoECMultiply:
		addrHash = hash.AddressChecksum(data, false)
	case CompressedNoECMultiply:
		addrHash = hash.AddressChecksum(data, true)
	case UncompressedECMultiply:
		panic("not implemented")
	case CompressedECMultiply:
		panic("not implemented")
	default:
		return "", errors.New("not implemented")
	}

	dk, err := scrypt.Key(norm.NFC.Bytes([]byte(passphrase)),
		addrHash, n, r, p, keyLen)
	if nil != err {
		return "", err
	}

	var payload [37]byte
	//var flag [1]byte
	if UncompressedNoECMultiply == mode {
		payload[0] = Uncompressed
	} else {
		payload[0] = Compressed
	}
	copy(payload[1:], addrHash) // append salt

	C, err := aes.NewCipher(dk[32:])
	if nil != err {
		return "", err
	}

	var block [32]byte
	//block := xor(data, dk[:32])
	bytes.XOR(block[:], data, dk[:32])
	C.Encrypt(payload[5:], block[:16])
	C.Encrypt(payload[21:], block[16:])

	return encoding.CheckEncode(Version, payload[:]), nil
}

/*
// xor calculates the (x[0]^y[0], x[1]^y[1],..., x[32]^y[32])
func xor(x, y []byte) []byte {
	var out [32]byte
	for i := range out {
		out[i] = x[i] ^ y[i]
	}

	return out[:]
}

*/
