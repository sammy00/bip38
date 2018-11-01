package nonec_test

import (
	"testing"

	"github.com/sammy00/bip38/nonec"
)

func BenchmarkDecrypt(b *testing.B) {
	var benchmarkCases []decryptGoldie
	readGolden(b, "TestDecrypt", &benchmarkCases)

	var okCases []decryptGoldie
	for _, v := range benchmarkCases {
		if !v.Expect.Bad {
			okCases = append(okCases, v)
		}
	}

	for _, c := range okCases {
		c := c
		b.Run(c.Description, func(sb *testing.B) {
			sb.ResetTimer()
			sb.ReportAllocs()
			for i := 0; i < sb.N; i++ {
				nonec.Decrypt(c.Encrypted, c.Passphrase)
			}
		})
	}
}
