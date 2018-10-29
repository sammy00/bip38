package bytes

// XOR calculates z[i]=x[i]^y[i], where i=0,1,...,len(z)
// assuming len(z)<=x and len(z)<=y
func XOR(z, x, y []byte) {
	for i := range z {
		z[i] = x[i] ^ y[i]
	}
}
