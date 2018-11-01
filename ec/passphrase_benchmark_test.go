package ec_test

import (
	"strings"
	"testing"

	"github.com/sammy00/bip38/internal/xtesting"

	"github.com/sammy00/bip38/ec"
)

func BenchmarkEncryptPassphrase(b *testing.B) {
	var allCases []encryptPassphraseGoldie
	xtesting.DecodeGoldenJSON(b,
		strings.Replace(b.Name(), "Benchmark", "Test", 1), &allCases)

	var benchmarkCases []encryptPassphraseGoldie
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

				ec.EncryptPassphrase(entropy, c.Passphrase)
			}
		})
	}
}

func BenchmarkEncryptPassphraseX(b *testing.B) {
	var allCases []encryptPassphraseXGoldie
	xtesting.DecodeGoldenJSON(b,
		strings.Replace(b.Name(), "Benchmark", "Test", 1), &allCases)

	var benchmarkCases []encryptPassphraseXGoldie
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

				ec.EncryptPassphraseX(entropy, c.Passphrase, c.Lot, c.Sequence)
			}
		})
	}
}
