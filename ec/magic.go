package ec

// MagicLen is the length of magic bytes to encode the intermediate
// passphrase string
const MagicLen = 8

// magic bytes as prefix for encrypting passphrase to make specific
// human-readable prefix to ease distinguishing
var (
	withLotSequence = [MagicLen]byte{
		0x2C, 0xE9, 0xB3, 0xE1, 0xFF, 0x39, 0xE2, 0x51,
	}
	noLotSequence = [MagicLen]byte{
		0x2C, 0xE9, 0xB3, 0xE1, 0xFF, 0x39, 0xE2, 0x53,
	}
)
