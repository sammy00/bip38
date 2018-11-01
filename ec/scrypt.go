package ec

import (
	"github.com/sammy00/bip38/internal/errz"
	"golang.org/x/crypto/scrypt"
)

func init() {

	// dynamic checking of the proposed configuration for SCRYPT
	// so as to remove the redundant error checking later
	_, err := scrypt.Key([]byte("bip38"), []byte("hello world"),
		N1, R1, P1, KeyLen1)
	errz.Fatal(err)

	_, err = scrypt.Key([]byte("bip38"), []byte("hello world"),
		N2, R2, P2, KeyLen2)
	errz.Fatal(err)
}
