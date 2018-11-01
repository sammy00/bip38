package ec

import (
	gobytes "bytes"
	"crypto/aes"

	"github.com/pkg/errors"

	"github.com/btcsuite/btcd/btcec"
	"github.com/sammy00/bip38/bytes"
	"github.com/sammy00/bip38/encoding"
	"github.com/sammy00/bip38/hash"
	"golang.org/x/crypto/scrypt"
	"golang.org/x/text/unicode/norm"
)

// GenerateConfirmationCode derives the corresponding confirmation code
// based on the intermediate information during private key encryption.
// Especially, both derivedHalf1 and derivedHalf2 should be of exact length
// as 32 bytes. Otherwise, the program would behave unexpectedly.
func GenerateConfirmationCode(flag byte, addrHash, ownerEntropy, b,
	derivedHalf1, derivedHalf2 []byte) string {
	curve := btcec.S256()
	Bx, By := curve.ScalarBaseMult(b)
	pubKey := &btcec.PublicKey{X: Bx, Y: By}
	B := pubKey.SerializeCompressed()

	var encrypted [33]byte
	encrypted[0] = B[0] ^ (derivedHalf2[31] & 0x01)

	encryptor, _ := aes.NewCipher(derivedHalf2)
	//if nil != err {
	//	return "", err
	//}

	bytes.XOR(B[1:], B[1:], derivedHalf1)
	encryptor.Encrypt(encrypted[1:17], B[1:17])
	encryptor.Encrypt(encrypted[17:], B[17:])

	payload := make([]byte, 1+4+8+33)
	payload[0] = flag
	copy(payload[1:], addrHash)
	copy(payload[5:], ownerEntropy)
	copy(payload[13:], encrypted[:])

	return encoding.CheckEncode(ConfirmationMagicCode, payload)
}

// RecoverAddress recovers the generated address out of the given confirmation
// code based on the given passphrase. If applicable, the corresponding lot and
// sequence number can be recovered from this passphrase code using
// LotSequenceFromConfirmationCode function.
func RecoverAddress(passphrase, code string) (string, error) {
	_, rawCode, err := encoding.CheckDecode(code, ConfirmationMagicLen)
	if nil != err {
		return "", err
	} else if len(rawCode) != RawConfirmationCodeLen {
		return "", errors.Errorf("invalid code length: %d", len(rawCode))
	}

	// rawCode=flag(1)|addressHash(4)|ownerEntropy(8)|encryptedB(33)
	flag, addrHash, ownerEntropy := rawCode[0], rawCode[1:5], rawCode[5:13]
	encryptedB := rawCode[13:]

	var ownerSalt []byte
	if 0 != flag&0x04 {
		// 0x04 bit on indicates the inclusion of lot-sequence,
		// which will make the first 4 bytes as salt for 1st round scrypt
		ownerSalt = ownerEntropy[:4]
	} else {
		ownerSalt = ownerEntropy
	}

	pass, _ := scrypt.Key(norm.NFC.Bytes([]byte(passphrase)), ownerSalt,
		N1, R1, P1, KeyLen1)
	//if nil != err {
	//	return "", err
	//}

	if 0 != flag&0x04 { // lot-sequence being included
		pass = hash.DoubleSum(append(pass, ownerEntropy[:]...))
	}

	curve := btcec.S256()
	var pubKey *btcec.PublicKey
	_, pubKey = btcec.PrivKeyFromBytes(curve, pass)
	passPoint := pubKey.SerializeCompressed()

	// addrHash|ownerEntropy=rawCode[1:13]
	dk, _ := scrypt.Key(passPoint, rawCode[1:13], N2, R2, P2, KeyLen2)
	//if nil != err {
	//	return "", err
	//}

	decryptor, _ := aes.NewCipher(dk[32:])
	//if nil != err {
	//	return "", err
	//}

	var B [33]byte

	B[0] = encryptedB[0] ^ (dk[63] & 0x01)
	decryptor.Decrypt(B[1:17], encryptedB[1:17])
	decryptor.Decrypt(B[17:], encryptedB[17:])
	bytes.XOR(B[1:], B[1:], dk[:32])

	pubKey, err = btcec.ParsePubKey(B[:], curve)
	if nil != err {
		return "", err
	}

	pubKey.X, pubKey.Y = curve.ScalarMult(pubKey.X, pubKey.Y, pass)
	var pub []byte
	if 0 != flag&0x20 {
		pub = pubKey.SerializeCompressed()
	} else {
		pub = pubKey.SerializeUncompressed()
	}
	addr := encoding.PublicKeyToAddress(pub)
	checksum := hash.DoubleSum([]byte(addr))

	if !gobytes.Equal(checksum[:4], addrHash) {
		return "", errors.New("invalid confirmation code")
	}

	return addr, nil
}
