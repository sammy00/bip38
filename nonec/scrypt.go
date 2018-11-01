package nonec

import (
	"github.com/sammy00/bip38/internal/errz"
	"golang.org/x/crypto/scrypt"
)

func init() {
	// dynamic checking of the proposed configuration for SCRYPT
	// so as to remove the redundant error checking later
	_, err := scrypt.Key([]byte("bip38"), []byte("hello world"), N, R, P, KeyLen)
	errz.Fatal(err)
}
