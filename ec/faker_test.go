package ec_test

import "errors"

type EntropyReader struct {
	Stream []byte
}

func (rd *EntropyReader) Read(p []byte) (n int, err error) {
	copy(p, rd.Stream)

	if len(p) > len(rd.Stream) {
		return len(rd.Stream), errors.New("not enough entropy")
	}

	return len(p), nil
}
