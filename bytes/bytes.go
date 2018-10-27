package bytes

func XOR(z, x, y []byte) {
	for i := range z {
		z[i] = x[i] ^ y[i]
	}
}
