package nonec

// Parameters configuration for SCRYPT
const (
	N      = 16384
	R      = 8
	P      = 8
	KeyLen = 64
)

const (
	Compressed   = 0xe0
	Uncompressed = 0xc0
)

const RawEncryptedKeyLen = 37
