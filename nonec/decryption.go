package nonec

import (
	"bytes"
	"crypto/aes"
	"errors"

	"github.com/sammy00/bip38/hash"
	"golang.org/x/crypto/scrypt"
	"golang.org/x/text/unicode/norm"
)

func Decrypt(encrypted string, passphrase string) ([]byte, error) {
	// TODO: distinguish decoding routine based on version
	payload, mode, err := CheckDecode(encrypted)
	if nil != err {
		return nil, err
	}

	dk, err := scrypt.Key(norm.NFC.Bytes([]byte(passphrase)),
		payload[:4], n, r, p, keyLen)
	if nil != err {
		return nil, err
	}

	C, err := aes.NewCipher(dk[32:])
	if nil != err {
		return nil, err
	}

	var plain [32]byte
	C.Decrypt(plain[:16], payload[4:20])
	C.Decrypt(plain[16:], payload[20:])

	priv := xor(plain[:], dk[:32])

	switch mode {
	case UncompressedNoECMultiply, UncompressedECMultiply:
		if !bytes.Equal(payload[:4], hash.AddressChecksum(priv, false)) {
			err = errors.New("invalid address hash")
		}
	case CompressedNoECMultiply, CompressedECMultiply:
		if !bytes.Equal(payload[:4], hash.AddressChecksum(priv, true)) {
			err = errors.New("invalid address hash")
		}
	default:
	}

	return priv, nil
}
