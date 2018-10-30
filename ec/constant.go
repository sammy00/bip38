package ec

// Parameters configuration for SCRYPT
const (
	N1      = 16384
	N2      = 1024
	R1      = 8
	R2      = 1
	P1      = 8
	P2      = 1
	KeyLen1 = 32
	KeyLen2 = 64
)

// flag bits
const (
	// Compressed denotes the public key is in compressed form
	Compressed = 0x20
	// Uncompressed denotes the public key is in uncompressed form
	Uncompressed = 0x00
	// NoLotSequence is employed when no lot number or sequence number is included
	NoLotSequence = 0x00
	// WithLotSequence is the opposite to NoLotSequence
	WithLotSequence = 0x04
)

// RawConfirmationCodeLen is the length of confirmation code without encoding
// and the magic prefix
const RawConfirmationCodeLen = 1 + 4 + 8 + 33

// RawEncryptedKeyLen is the length of encrypted private key without base58
// encoding and trimming out the version prefix
const RawEncryptedKeyLen = 1 + 4 + 8 + 8 + 16

// VersionLen is length of version prefix for encrypting private key
// according to EC-Multiply mode
const VersionLen = 2

// Version is the object identifier prefix for EC-Multiply encryption mode
var Version = []byte{0x01, 0x43}
