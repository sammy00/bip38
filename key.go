package bip38

import (
	"github.com/btcsuite/btcd/btcec"
	"github.com/sammy00/bip38/encoding"
	"github.com/sammy00/bip38/hash"
)

func AddressHash(priv []byte, compressed bool) []byte {
	privKey, _ := btcec.PrivKeyFromBytes(btcec.S256(), priv)

	pub := privKey.PubKey().SerializeUncompressed()
	addr := encoding.PublicKeyToAddress(pub)
	checksum := hash.DoubleSum([]byte(addr))

	return checksum[:4]
}
