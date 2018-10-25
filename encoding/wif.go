package encoding

import (
	"github.com/sammy00/base58"
)

func PrivateKeyToWIF(priv []byte) string {
	return base58.CheckEncode(priv, 128)
}

func WIFToPrivateKey(wif string) ([]byte, error) {
	priv, _, err := base58.CheckDecode(wif)

	return priv, err
}
