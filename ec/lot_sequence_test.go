package ec_test

import (
	"bytes"
	"testing"

	"github.com/sammy00/bip38/ec"
)

func TestDecodeLotSequence(t *testing.T) {
	type expect struct {
		lot      uint32
		sequence uint32
	}

	testCases := []struct {
		lotSeq [4]byte
		expect expect
	}{
		{[4]byte{0x40, 0x40, 0xf0, 0x01}, expect{263183, 1}},
		{[4]byte{0xc5, 0x01, 0xa0, 0x01}, expect{806938, 1}},
	}

	for i, c := range testCases {
		lot, seq := ec.DecodeLotSequence(c.lotSeq[:])

		if lot != c.expect.lot {
			t.Fatalf("#%d invalid lot number: got %d, expect %d", i, lot,
				c.expect.lot)
		}

		if seq != c.expect.sequence {
			t.Fatalf("#%d invalid sequence number: got %d, expect %d", i, seq,
				c.expect.sequence)
		}
	}
}

func TestEncodeLotSequence(t *testing.T) {
	testCases := []struct {
		lot, sequence uint32
		expect        []byte
	}{
		{263183, 1, []byte{0x40, 0x40, 0xf0, 0x01}},
		{806938, 1, []byte{0xc5, 0x01, 0xa0, 0x01}},
	}

	for i, c := range testCases {
		var got [4]byte
		ec.EncodeLotSequence(got[:], c.lot, c.sequence)

		if !bytes.Equal(got[:], c.expect) {
			t.Fatalf("#%d failed: got %x, expect %x", i, got, c.expect)
		}
	}
}

func TestLotSequenceFromConfirmationCode(t *testing.T) {
	type expect struct {
		lot      uint32
		sequence uint32
		hasErr   bool
	}

	testCases := []struct {
		code   string
		expect expect
	}{
		{
			"cfrm38V8aXBn7JWA1ESmFMUn6erxeBGZGAxJPY4e36S9QWkzZKtaVqLNMgnifETYw7BPwWC9aPD",
			expect{263183, 1, false},
		},
		{
			"cfrm38V8G4qq2ywYEFfWLD5Cc6msj9UwsG2Mj4Z6QdGJAFQpdatZLavkgRd1i4iBMdRngDqDs51",
			expect{806938, 1, false},
		},
		{ // no lot/sequence
			"cfrm38V5UPS5Aik2Z91tWbgNUTDmL4uKyUF4CX7wATVikgxRfg9tjCT7Mdon16uVeWCJqjnFGts",
			expect{0, 0, true},
		},
		{ // no lot/sequence
			"cfrm38V5DK6HEHLdYfLRsiJmSAMdPypxESZ4rPcWWo3Jx6rvBNSL79ZbwbGDh2KNvniTEM1ib3v",
			expect{0, 0, true},
		},
		{ // invalid code length
			"355Q13gxUDEtfGESaJu4nxuGoNMMitvB",
			expect{0, 0, true},
		},
		{ // invalid base58 checksum
			"cfrm38V8aXBn7JWA1ESmFMUn6erxeBGZGAxJPY4e36S9QWkzZKtaVqLNMgnifETYw7BPwWC9aPE",
			expect{0, 0, true},
		},
	}

	/*
		cfrm := "cfrm38V8aXBn7JWA1ESmFMUn6erxeBGZGAxJPY4e36S9QWkzZKtaVqLNMgnifETYw7BPwWC9aPD"
		magic, payload, _ := encoding.CheckDecode(cfrm, ec.ConfirmationMagicLen)
		//for i := 0; i < 32; i++ {
		//payload = append(payload, 0xff)
		payload = payload[1:]
		payload = payload[1:]
		t.Log(encoding.CheckEncode(magic, payload))
		//}
	*/

	for i, c := range testCases {
		lot, seq, err := ec.LotSequenceFromConfirmationCode(c.code)

		if c.expect.hasErr && nil == err {
			t.Fatalf("#%d expect error but got none", i)
		} else if !c.expect.hasErr && nil != err {
			t.Fatalf("#%d unexpected error: %v", i, err)
		}

		if lot != c.expect.lot {
			t.Fatalf("#%d invalid lot number: got %d, expect %d", i, lot,
				c.expect.lot)
		}

		if seq != c.expect.sequence {
			t.Fatalf("#%d invalid sequence number: got %d, expect %d", i, seq,
				c.expect.sequence)
		}
	}
}

func TestLotSequenceFromEncryptedKey(t *testing.T) {
	type expect struct {
		lot      uint32
		sequence uint32
		hasErr   bool
	}

	testCases := []struct {
		encrypted string
		expect    expect
	}{
		{
			"6PgNBNNzDkKdhkT6uJntUXwwzQV8Rr2tZcbkDcuC9DZRsS6AtHts4Ypo1j",
			expect{263183, 1, false},
		},
		{
			"6PgGWtx25kUg8QWvwuJAgorN6k9FbE25rv5dMRwu5SKMnfpfVe5mar2ngH",
			expect{806938, 1, false},
		},
		{ // no lot/sequence
			"6PfQu77ygVyJLZjfvMLyhLMQbYnu5uguoJJ4kMCLqWwPEdfpwANVS76gTX",
			expect{0, 0, true},
		},
		{ // no lot/sequence
			"6PfLGnQs6VZnrNpmVKfjotbnQuaJK4KZoPFrAjx1JMJUa1Ft8gnf5WxfKd",
			expect{0, 0, true},
		},
		{ // invalid code length
			"2Dzs6F8PLUw32GzuJ6FF83x9ZEsUUi9GVBajcH2MjTc9NUVBda8hrz9aA",
			expect{0, 0, true},
		},
		{ // invalid base58 checksum
			"6PgNBNNzDkKdhkT6uJntUXwwzQV8Rr2tZcbkDcuC9DZRsS6AtHts4Ypo1k",
			expect{0, 0, true},
		},
	}

	for i, c := range testCases {
		lot, seq, err := ec.LotSequenceFromEncryptedKey(c.encrypted)

		if c.expect.hasErr && nil == err {
			t.Fatalf("#%d expect error but got none", i)
		} else if !c.expect.hasErr && nil != err {
			t.Fatalf("#%d unexpected error: %v", i, err)
		}

		if lot != c.expect.lot {
			t.Fatalf("#%d invalid lot number: got %d, expect %d", i, lot,
				c.expect.lot)
		}

		if seq != c.expect.sequence {
			t.Fatalf("#%d invalid sequence number: got %d, expect %d", i, seq,
				c.expect.sequence)
		}
	}
}
