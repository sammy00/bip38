package hash

import (
	"github.com/btcsuite/btcd/btcec"
	"github.com/sammy00/bip38/encoding"
)

// AddressChecksum estimates a checksum for the address derived from the
// public key bound the given private key. The checksum is the first 4 bytes
// of SHA256(SHA256(address))
func AddressChecksum(priv []byte, compressed bool) []byte {
	_, pubKey := btcec.PrivKeyFromBytes(btcec.S256(), priv)

	var pub []byte
	if compressed {
		pub = pubKey.SerializeCompressed()
	} else {
		pub = pubKey.SerializeUncompressed()
	}

	addr := encoding.PublicKeyToAddress(pub)
	checksum := DoubleSum([]byte(addr))

	return checksum[:4]
}
