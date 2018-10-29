package nonec

const VersionLen = 2

var Version = []byte{0x01, 0x42}

const (
	Compressed   = 0xe0
	Uncompressed = 0xc0
)
