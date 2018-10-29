package ec

// ConfirmationMagicLen is the length of magic bytes to encode the confirmation
// returning to owner from the generator
const ConfirmationMagicLen = 5

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

// ConfirmationMagicCode prepend to the raw confirmation code to
// make up the "cfrm38" prefix in the final base58-encoding string
var ConfirmationMagicCode = []byte{0x64, 0x3B, 0xF6, 0xA8, 0x9A}
