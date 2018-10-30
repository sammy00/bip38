package nonec

// VersionLen is the length in bytes of object identification prefix employed
// for base58 encoding the encrypted private key
const VersionLen = 2

// Version is the  object identification prefix employed for base58 encoding
// the encrypted private key
var Version = []byte{0x01, 0x42}
