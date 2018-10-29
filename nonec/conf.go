package nonec

// EncryptionMode denotes a mode to encrypting private key
type EncryptionMode uint8

// enumerations of encryption modes
const (
	Reserved EncryptionMode = iota
	UncompressedNoECMultiply
	CompressedNoECMultiply
	UncompressedECMultiply
	CompressedECMultiply
)

const versionLen = 3

// versions specifies the set of version prefix to employ for
// different encryption mode
var versions [][versionLen]byte

const VersionLen = 2

var Version = []byte{0x01, 0x42}

const (
	Compressed   = 0xe0
	Uncompressed = 0xc0
)

func init() {
	versions = [][versionLen]byte{
		{}, // reserved
		{0x01, 0x42, 0xc0},
		{0x01, 0x42, 0xe0},
		{0x01, 0x43, 0x00},
		{0x01, 0x43, 0x20},
	}
}
