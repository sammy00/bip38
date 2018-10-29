package hash

import (
	"github.com/SHDMT/btcec"
	"github.com/sammy00/bip38/encoding"
)

func AddressChecksum(priv []byte, compressed bool) []byte {
	privKey, _ := btcec.PrivKeyFromBytes(btcec.S256(), priv)

	var pub []byte
	if compressed {
		pub = privKey.PubKey().SerializeCompressed()
	} else {
		pub = privKey.PubKey().SerializeUncompressed()
	}

	addr := encoding.PublicKeyToAddress(pub)
	checksum := DoubleSum([]byte(addr))

	return checksum[:4]
}
