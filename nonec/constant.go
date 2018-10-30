package nonec

// Parameters configuration for SCRYPT
const (
	N      = 16384
	R      = 8
	P      = 8
	KeyLen = 64
)

// flag byte indicating encoding format of private/public key
const (
	Compressed   = 0xe0
	Uncompressed = 0xc0
)

// RawEncryptedKeyLen is the length of encrypted key as byte sequence without
// version prefix
const RawEncryptedKeyLen = 37
