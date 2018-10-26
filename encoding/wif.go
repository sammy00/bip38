package encoding

import (
	"github.com/sammy00/base58"
)

func PrivateKeyToWIF(priv []byte) string {
	return base58.CheckEncode(priv, 128)
}

func PrivateKeyToWIFCompressed(priv []byte) string {
	return base58.CheckEncode(append(priv, 0x01), 128)
}

func WIFToPrivateKey(wif string) ([]byte, error) {
	priv, _, err := base58.CheckDecode(wif)

	return priv, err
}
