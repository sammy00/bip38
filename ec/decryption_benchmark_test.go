package ec_test

import (
	"strings"
	"testing"

	"github.com/sammy00/bip38/ec"
)

func BenchmarkDecrypt(b *testing.B) {
	var allCases []decryptGoldie
	readGolden(b, strings.Replace(b.Name(), "Benchmark", "Test", 1),
		&allCases)

	var benchmarkCases []decryptGoldie
	for _, v := range allCases {
		if !v.Expect.Bad {
			benchmarkCases = append(benchmarkCases, v)
		}
	}

	for _, c := range benchmarkCases {
		c := c

		b.Run(c.Description, func(sb *testing.B) {
			sb.ReportAllocs()

			for i := 0; i < sb.N; i++ {
				ec.Decrypt(c.Encrypted, c.Passphrase)
			}
		})
	}
}
