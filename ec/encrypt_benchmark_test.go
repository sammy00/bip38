package ec_test

import (
	"strings"
	"testing"

	"github.com/sammy00/bip38/ec"
)

func BenchmarkEncrypt(b *testing.B) {
	var allCases []encryptGoldie
	readGolden(b, strings.Replace(b.Name(), "Benchmark", "Test", 1),
		&allCases)

	var benchmarkCases []encryptGoldie
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
				entropy := &EntropyReader{Stream: c.Entropy}
				ec.Encrypt(entropy, c.PassphraseCode, c.Compressed)
			}
		})
	}
}
