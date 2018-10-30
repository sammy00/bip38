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

// Encrypt derives an encrypted private key from the given passphrase code and
// return the resultant encrypted private key and confirmation code
func Encrypt(rand io.Reader, passphraseEx string,
	compressed bool) (string, string, error) {

	var seedb [24]byte
	if _, err := rand.Read(seedb[:]); nil != err {
		return "", "", err
	}

	b := hash.DoubleSum(seedb[:])

	magic, payload, err := encoding.CheckDecode(passphraseEx, MagicLen)
	if nil != err {
		return "", "", err
	}

	curve := btcec.S256()
	pubKey, err := btcec.ParsePubKey(payload[8:], curve)
	if nil != err {
		return "", "", err
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
	dk, err := scrypt.Key(payload[8:], salt, N2, R2, P2, KeyLen2)
	if nil != err {
		return "", "", err
	}

	encryptor, err := aes.NewCipher(dk[32:])
	if nil != err {
		return "", "", err
	}

	var block, encryptedPart1, encryptedPart2 [16]byte

	bytes.XOR(block[:], seedb[:16], dk[:16])
	encryptor.Encrypt(encryptedPart1[:], block[:])

	copy(block[:8], encryptedPart1[8:])
	copy(block[8:], seedb[16:])
	bytes.XOR(block[:], block[:], dk[16:32])
	encryptor.Encrypt(encryptedPart2[:], block[:])

	var flag byte
	if compressed {
		flag |= Compressed
	} else {
		flag |= Uncompressed
	}
	if 0x51 == magic[MagicLen-1] {
		flag |= WithLotSequence
	} else {
		flag |= NoLotSequence
	}

	out := make([]byte, 0, 39-VersionLen)
	out = append(out, flag)
	out = append(out, addrHash...)
	out = append(out, payload[:8]...)
	out = append(out, encryptedPart1[:8]...)
	out = append(out, encryptedPart2[:]...)

	code, err := GenerateConfirmationCode(flag, addrHash, payload[:8], b,
		dk[:32], dk[32:])
	if nil != err {
		return "", "", err
	}

	return encoding.CheckEncode(Version, out), code, nil
}
