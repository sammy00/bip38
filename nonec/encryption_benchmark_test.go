package nonec_test

import (
	"encoding/hex"
	"testing"

	"github.com/sammy00/bip38/internal/xtesting"
	"github.com/sammy00/bip38/nonec"
)

func BenchmarkEncrypt(b *testing.B) {
	var benchmarkCases []encryptGoldie
	xtesting.DecodeGoldenJSON(b, "TestEncrypt", &benchmarkCases)

	for _, bc := range benchmarkCases {
		bc := bc
		b.Run("", func(sb *testing.B) {
			unencrypted, _ := hex.DecodeString(bc.Unencrypted)

			sb.ResetTimer()
			sb.ReportAllocs()
			for i := 0; i < sb.N; i++ {
				nonec.Encrypt(unencrypted, bc.Passphrase, bc.Compressed)
			}
		})
	}
}

/*

func hexlify(data []byte, comment ...string) {
	fmt.Printf("[]byte{")
	if len(comment) > 0 {
		fmt.Println("//", comment[0])
	}

	for i, v := range data {
		if i%8 == 0 {
			fmt.Println()
		}
		fmt.Printf("0x%02x,", v)
	}
	fmt.Println("\n},")
}
*/
