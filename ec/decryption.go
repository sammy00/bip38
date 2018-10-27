package ec

import (
	gobytes "bytes"
	"crypto/aes"
	"errors"
	"math/big"

	"github.com/sammy00/bip38"

	"golang.org/x/crypto/scrypt"
	"golang.org/x/text/unicode/norm"

	"github.com/SHDMT/btcec"
	"github.com/sammy00/bip38/bytes"
	"github.com/sammy00/bip38/encoding"
	"github.com/sammy00/bip38/hash"
)

func Decrypt(encrypted string, passphrase string) ([]byte, error) {
	_, payload, err := encoding.CheckDecode(encrypted, VersionLen)
	if nil != err {
		return nil, err
	}
	//fmt.Printf("%x\n", version)
	//fmt.Printf("%x\n", payload)
	//fmt.Println(len(payload))

	addrHash, ownerEntropy := payload[:4], payload[4:12]

	pass, err := scrypt.Key(norm.NFC.Bytes([]byte(passphrase)), ownerEntropy,
		n1, r1, p1, keyLen1)
	if nil != err {
		return nil, err
	}

	_, pub := btcec.PrivKeyFromBytes(btcec.S256(), pass)
	passPoint := pub.SerializeCompressed()

	salt := append(addrHash, ownerEntropy...)
	dk, err := scrypt.Key(passPoint, salt, n2, r2, p2, keyLen2)
	if nil != err {
		return nil, err
	}

	decryptor, err := aes.NewCipher(dk[32:])
	if nil != err {
		return nil, err
	}

	var out [16]byte

	encryptedPart2 := payload[20:]
	decryptor.Decrypt(out[:], encryptedPart2)
	bytes.XOR(out[:], out[:], dk[16:32])

	var seedb [24]byte
	copy(seedb[16:], out[8:])

	encryptedPart1 := append(payload[12:20], out[:8]...)
	decryptor.Decrypt(out[:], encryptedPart1)
	bytes.XOR(seedb[:16], out[:], dk[:16])

	b := hash.DoubleSum(seedb[:])

	x, y := new(big.Int).SetBytes(pass), new(big.Int).SetBytes(b)
	z := new(big.Int).Mul(x, y)
	z.Mod(z, btcec.S256().N)

	addrHash2 := bip38.AddressHash(z.Bytes(), false)
	if !gobytes.Equal(addrHash, addrHash2) {
		return nil, errors.New("invalid address hash")
	}

	return z.Bytes(), nil
}
