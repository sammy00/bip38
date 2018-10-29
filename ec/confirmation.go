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

// RecoverAddress recovers the generated address out of the given confirmation
// code based on the given passphrase
func RecoverAddress(passphrase, code string) (string, error) {
	_, rawCode, err := encoding.CheckDecode(code, ConfirmationMagicLen)
	if nil != err {
		return "", err
	} else if len(rawCode) != RawConfirmationCodeLen {
		return "", errors.Errorf("invalid code length: %d", len(rawCode))
	}

	flag, ownerEntropy := rawCode[0], rawCode[5:13]

	var ownerSalt []byte
	if 0 != flag&0x04 {
		ownerSalt = ownerEntropy[:4]
	} else {
		ownerSalt = ownerEntropy
	}

	pass, err := scrypt.Key(norm.NFC.Bytes([]byte(passphrase)), ownerSalt,
		N1, R1, P1, KeyLen1)
	if nil != err {
		return "", err
	}

	if 0 != flag&0x04 { // lot-sequence being included
		pass = hash.DoubleSum(append(pass, ownerEntropy[:]...))
	}

	//fmt.Println("2")
	//fmt.Printf("pass=%x\n", pass)
	var pubKey *btcec.PublicKey
	_, pubKey = btcec.PrivKeyFromBytes(btcec.S256(), pass)
	passPoint := pubKey.SerializeCompressed()
	//fmt.Printf("pass=%x\n", pass)

	// addrHash|ownerEntropy=rawCode[1:13]
	dk, err := scrypt.Key(passPoint, rawCode[1:13], N2, R2, P2, KeyLen2)
	if nil != err {
		return "", err
	}
	//fmt.Printf("salt=%x\n", rawCode[1:13])
	//fmt.Printf("dk1=%x\n", dk[:32])
	//fmt.Printf("dk2=%x\n", dk[32:])
	//fmt.Println("3")

	decryptor, err := aes.NewCipher(dk[32:])
	if nil != err {
		return "", err
	}
	//fmt.Println("4")

	var B [33]byte

	offset := 13
	B[0] = rawCode[offset] ^ (dk[63] & 0x01)

	offset++
	decryptor.Decrypt(B[1:17], rawCode[offset:offset+16])

	offset += 16
	decryptor.Decrypt(B[17:], rawCode[offset:])
	bytes.XOR(B[1:], B[1:], dk[:32])

	//fmt.Printf("B1=%x\n", B)
	//fmt.Printf("e1=%x\n", rawCode[13])

	curve := btcec.S256()
	pubKey, err = btcec.ParsePubKey(B[:], curve)
	if nil != err {
		return "", err
	}
	//fmt.Println("5")

	pubKey.X, pubKey.Y = curve.ScalarMult(pubKey.X, pubKey.Y, pass)
	var pub []byte
	if 0 != rawCode[0]&0x20 {
		pub = pubKey.SerializeCompressed()
	} else {
		pub = pubKey.SerializeUncompressed()
	}
	addr := encoding.PublicKeyToAddress(pub)
	checksum := hash.DoubleSum([]byte(addr))

	if !gobytes.Equal(checksum[:4], rawCode[1:5]) {
		return "", errors.New("invalid confirmation code")
	}

	//fmt.Printf("hello world")

	return addr, nil
}

//func Confirm(flag byte, addrHash, ownerEntropy, b, derivedHalf1,
func GenerateConfirmationCode(flag byte, addrHash, ownerEntropy, b,
	derivedHalf1, derivedHalf2 []byte) (string, error) {
	curve := btcec.S256()
	Bx, By := curve.ScalarBaseMult(b)
	pubKey := &btcec.PublicKey{X: Bx, Y: By}
	B := pubKey.SerializeCompressed()

	/*fmt.Printf("ownerEntropy=%x\n", ownerEntropy)
	fmt.Printf("dk1=%x\n", derivedHalf1)
	fmt.Printf("dk2=%x\n", derivedHalf2)
	fmt.Printf("B0=%x\n", B)
	*/

	//fmt.Printf("pub %x\n", pub)
	var encrypted [33]byte
	encrypted[0] = B[0] ^ (derivedHalf2[31] & 0x01)
	//fmt.Printf("e0=%x\n", encrypted[0])

	encryptor, err := aes.NewCipher(derivedHalf2)
	if nil != err {
		return "", err
	}

	bytes.XOR(B[1:], B[1:], derivedHalf1)
	encryptor.Encrypt(encrypted[1:17], B[1:17])
	encryptor.Encrypt(encrypted[17:], B[17:])

	payload := make([]byte, 1+4+8+33)
	payload[0] = flag
	copy(payload[1:], addrHash)
	copy(payload[5:], ownerEntropy)
	copy(payload[13:], encrypted[:])
	//fmt.Printf("salt=%x%x\n", addrHash, ownerEntropy)

	return encoding.CheckEncode(ConfirmationMagicCode, payload), nil
}
