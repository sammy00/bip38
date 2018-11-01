package xtesting

// Logger serves as logger report fatal message
type Logger interface {
	Fatal(args ...interface{})
}
