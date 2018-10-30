package encoding

import (
	"github.com/sammy00/base58"
)

// PrivateKeyToWIF encodes the given **uncompressed** private key byte sequence
// into wif format
func PrivateKeyToWIF(priv []byte) string {
	return base58.CheckEncode(priv, 128)
}

// PrivateKeyToWIFCompressed encodes the given **compressed** private key
// byte sequence into wif format
func PrivateKeyToWIFCompressed(priv []byte) string {
	return base58.CheckEncode(append(priv, 0x01), 128)
}

// WIFToPrivateKey just reverses the processing done by
// @PrivateKeyToWIF/@ PrivateKeyToWIFCompressed
func WIFToPrivateKey(wif string) ([]byte, error) {
	priv, _, err := base58.CheckDecode(wif)

	return priv, err
}
