package nonec

import "golang.org/x/crypto/scrypt"

// dynamic checking of the proposed configuration for SCRYPT
// so as to remove the redundant error checking later
var _, _ = scrypt.Key([]byte("bip38"), []byte("hello world"), N, R, P, KeyLen)
