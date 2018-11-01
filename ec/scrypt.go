package ec

import (
	"golang.org/x/crypto/scrypt"
)

func init() {

	// dynamic checking of the proposed configuration for SCRYPT
	// so as to remove the redundant error checking later
	if _, err := scrypt.Key([]byte("bip38"), []byte("hello world"),
		N1, R1, P1, KeyLen1); nil != err {
		panic(err)
	}
	if _, err := scrypt.Key([]byte("bip38"), []byte("hello world"),
		N2, R2, P2, KeyLen2); nil != err {
		panic(err)
	}
}
