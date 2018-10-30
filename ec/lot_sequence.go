package ec

import (
	"github.com/pkg/errors"
	"github.com/sammy00/bip38/encoding"
)

func DecodeLotSequence(lotSequence []byte) (uint32, uint32) {
	lot := uint32(lotSequence[0]) << 12
	lot |= uint32(lotSequence[1]) << 4
	lot |= uint32(lotSequence[2]) >> 4

	sequence := uint32(lotSequence[2]&0x0f) << 4
	sequence |= uint32(lotSequence[3])

	return lot, sequence
}

func EncodeLotSequence(lotSequence []byte, lot, sequence uint32) {
	lotSequence[0] = byte(lot >> 12 & 0xff)
	lotSequence[1] = byte(lot >> 4 & 0xff)
	lotSequence[2] = byte((lot << 4 & 0xf0) | (sequence >> 8 & 0x0f))
	lotSequence[3] = byte(sequence & 0xff)
}

func LotSequenceFromConfirmationCode(code string) (uint32, uint32, error) {
	_, rawCode, err := encoding.CheckDecode(code, ConfirmationMagicLen)
	// TODO: ??magic bytes checking
	switch {
	case nil != err:
		return 0, 0, err
	case len(rawCode) != RawConfirmationCodeLen:
		return 0, 0, errors.Errorf("invalid code length: %d", len(rawCode))
	case 0 == rawCode[0]&0x04:
		return 0, 0, errors.New("no lot/sequence")
	}

	lot, seq := DecodeLotSequence(rawCode[9:13])

	return lot, seq, nil
}

func LotSequenceFromEncryptedKey(encrypted string) (uint32, uint32, error) {
	_, priv, err := encoding.CheckDecode(encrypted, VersionLen)
	// TODO: ??magic bytes checking
	switch {
	case nil != err:
		return 0, 0, err
	case len(priv) != RawEncryptedKeyLen:
		return 0, 0, errors.Errorf("invalid encrypted key length: %d", len(priv))
	case 0 == priv[0]&0x04: // check flag setting
		return 0, 0, errors.New("no lot/sequence")
	}

	lot, seq := DecodeLotSequence(priv[9:13])

	return lot, seq, nil
}
