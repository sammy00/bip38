package nonec

import (
	gobytes "bytes"
	"crypto/aes"

	"github.com/pkg/errors"

	"github.com/sammy00/bip38/bytes"
	"github.com/sammy00/bip38/encoding"
	"github.com/sammy00/bip38/hash"
	"golang.org/x/crypto/scrypt"
	"golang.org/x/text/unicode/norm"
)

// Decrypt decodes the encrypted private key out of the encrypted cipher text
// with the help of passphrase provided by owner.
func Decrypt(encrypted string, passphrase string) ([]byte, error) {
	_, payload, err := encoding.CheckDecode(encrypted, VersionLen)
	if nil != err {
		return nil, err
	} else if len(payload) != RawEncryptedKeyLen {
		return nil, errors.Errorf("invalid encrypted key length: %d", len(payload))
	}

	// decompose payload into different parts
	flag, addrHash := payload[0], payload[1:5]
	encryptedHalf1, encryptedHalf2 := payload[5:21], payload[21:]

	dk, _ := scrypt.Key(norm.NFC.Bytes([]byte(passphrase)),
		addrHash, N, R, P, KeyLen)

	C, _ := aes.NewCipher(dk[32:])

	var priv [32]byte
	C.Decrypt(priv[:16], encryptedHalf1)
	C.Decrypt(priv[16:], encryptedHalf2)
	bytes.XOR(priv[:], priv[:], dk[:32])

	switch flag {
	case Compressed:
		if !gobytes.Equal(addrHash, hash.AddressChecksum(priv[:], true)) {
			err = errors.New("invalid address hash")
		}
	case Uncompressed:
		if !gobytes.Equal(addrHash, hash.AddressChecksum(priv[:], false)) {
			err = errors.New("invalid address hash")
		}
	default:
		err = errors.New("invalid flag")
	}

	return priv[:], err
}
