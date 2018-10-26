package encoding

import (
	"crypto/sha256"

	"github.com/SHDMT/btcec"
	"github.com/sammy00/base58"
	"golang.org/x/crypto/ripemd160"
)

func PublicKeyToAddress(pub []byte) string {
	data := sha256.Sum256(pub)

	ripemd := ripemd160.New()
	ripemd.Write(data[:])

	payload := ripemd.Sum(nil)

	return base58.CheckEncode(payload[:], 0x00)
}

func AddressFromPrivateKey(data []byte, compressed bool) string {
	priv, _ := btcec.PrivKeyFromBytes(btcec.S256(), data)

	var pub []byte
	if compressed {
		pub = priv.PubKey().SerializeCompressed()
	} else {
		pub = priv.PubKey().SerializeUncompressed()
	}

	return PublicKeyToAddress(pub)
}
