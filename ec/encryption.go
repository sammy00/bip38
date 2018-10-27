package ec

import (
	"crypto/aes"
	"io"

	"github.com/btcsuite/btcd/btcec"

	"golang.org/x/crypto/scrypt"

	"github.com/sammy00/bip38/bytes"
	"github.com/sammy00/bip38/encoding"
	"github.com/sammy00/bip38/hash"
)

func Encrypt(rand io.Reader, data []byte, passphraseEx string,
	compressed bool) (string, error) {

	var seedb [24]byte
	if _, err := rand.Read(seedb[:]); nil != err {
		return "", err
	}

	b := hash.DoubleSum(seedb[:])

	_, payload, err := encoding.CheckDecode(passphraseEx, MagicLen)
	if nil != err {
		return "", err
	}

	//btcec.PublicKey
	curve := btcec.S256()
	pubKey, err := btcec.ParsePubKey(payload[8:], curve)
	if nil != err {
		return "", err
	}
	pubKey.X, pubKey.Y = curve.ScalarMult(pubKey.X, pubKey.Y, b)

	var pub []byte
	if compressed {
		pub = pubKey.SerializeCompressed()
	} else {
		pub = pubKey.SerializeUncompressed()
	}
	addr := encoding.PublicKeyToAddress(pub)
	checksum := hash.DoubleSum([]byte(addr))

	addrHash := checksum[:4]

	// ownerEntropy=payload[:8]
	// passPoint=payload[8:]
	salt := append(addrHash, payload[:8]...)
	dk, err := scrypt.Key(payload[8:], salt, n2, r2, p2, keyLen2)
	if nil != err {
		return "", err
	}

	encryptor, err := aes.NewCipher(dk[32:])
	if nil != err {
		return "", err
	}

	var block, encryptedPart1, encryptedPart2 [16]byte

	bytes.XOR(block[:], seedb[:16], dk[:16])
	encryptor.Encrypt(encryptedPart1[:], block[:])

	copy(block[:8], encryptedPart1[8:])
	copy(block[8:], seedb[16:])
	bytes.XOR(block[:], block[:], dk[16:32])
	encryptor.Encrypt(encryptedPart2[:], block[:])

	var version []byte
	if compressed {
		version = CompressedNoLotSequence[:]
	} else {
		version = UncompressedNoLotSequence[:]
	}

	out := make([]byte, 0, 39-VersionLen)
	out = append(out, addrHash...)
	out = append(out, payload[:8]...)
	out = append(out, encryptedPart1[:8]...)
	out = append(out, encryptedPart2[:]...)

	return encoding.CheckEncode(version, out), nil
}
