package bip38

import (
	"crypto/aes"

	"golang.org/x/text/unicode/norm"

	"github.com/btcsuite/btcd/btcec"
	"github.com/sammy00/bip38/encoding"
	"github.com/sammy00/bip38/hash"
	"golang.org/x/crypto/scrypt"
)

func Encrypt(data []byte, passphrase string) (string, error) {
	priv, _ := btcec.PrivKeyFromBytes(btcec.S256(), data)

	pub := priv.PubKey().SerializeUncompressed()
	addr := encoding.PublicKeyToAddress(pub)
	addrHash := hash.DoubleSum([]byte(addr))

	dk, err := scrypt.Key(norm.NFC.Bytes([]byte(passphrase)),
		addrHash[:4], n, r, p, keyLen)
	if nil != err {
		return "", err
	}

	var payload [36]byte
	copy(payload[:], addrHash[:4]) // append salt

	C, err := aes.NewCipher(dk[32:])
	if nil != err {
		return "", err
	}

	block := xor(data, dk[:32])
	C.Encrypt(payload[4:], block[:16])
	C.Encrypt(payload[20:], block[16:])

	return CheckEncode(payload[:], [3]byte{0x01, 0x42, 0xc0}), nil
}

func xor(priv, derivedHash []byte) []byte {
	var out [32]byte
	for i := range out {
		out[i] = priv[i] ^ derivedHash[i]
	}

	return out[:]
}
