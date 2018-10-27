package ec

// params for SCRYPT
const (
	n1, n2           = 16384, 1024
	r1, r2           = 8, 1
	p1, p2           = 8, 1
	keyLen1, keyLen2 = 32, 64
)

// MagicLen is the length of magic bytes to encode the intermediate
// passphrase string
const MagicLen = 8

var (
	withLotSequence = [8]byte{0x2C, 0xE9, 0xB3, 0xE1, 0xFF, 0x39, 0xE2, 0x51}
	noLotSequence   = [8]byte{0x2C, 0xE9, 0xB3, 0xE1, 0xFF, 0x39, 0xE2, 0x53}
)

// VersionLen is the length of version prefix prepended to the payload
const VersionLen = 3

var (
	CompressedNoLotSequence     = [VersionLen]byte{0x01, 0x43, 0x20}
	CompressedWithLotSequence   = [VersionLen]byte{0x01, 0x43, 0x24}
	UncompressedNoLotSequence   = [VersionLen]byte{0x01, 0x43, 0x00}
	UncompressedWithLotSequence = [VersionLen]byte{0x01, 0x43, 0x04}
)
