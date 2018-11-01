package ec_test

import (
	"strings"
	"testing"

	"github.com/sammy00/bip38/ec"
)

func BenchmarkGenerateConfirmationCode(b *testing.B) {
	var benchmarkCases []cfrmCodeGoldie
	readGolden(b, strings.Replace(b.Name(), "Benchmark", "Test", 1),
		&benchmarkCases)

	for _, c := range benchmarkCases {
		c := c

		b.Run("", func(sb *testing.B) {
			sb.ReportAllocs()

			for i := 0; i < sb.N; i++ {
				ec.GenerateConfirmationCode(c.Flag, c.AddrHash, c.OwnerEntropy, c.B,
					c.DerivedHalf1, c.DerivedHalf2)
			}
		})
	}
}

func BenchmarkRecoverAddress(b *testing.B) {
	var benchmarkCases []recoverAddressGoldie
	readGolden(b, strings.Replace(b.Name(), "Benchmark", "Test", 1),
		&benchmarkCases)

	var okCases []recoverAddressGoldie
	for _, v := range benchmarkCases {
		if !v.Expect.Bad {
			okCases = append(okCases, v)
		}
	}

	for _, c := range okCases {
		c := c

		b.Run(c.Description, func(sb *testing.B) {
			sb.ReportAllocs()

			for i := 0; i < sb.N; i++ {
				ec.RecoverAddress(c.Passphrase, c.ConfirmationCode)
			}
		})
	}
}
