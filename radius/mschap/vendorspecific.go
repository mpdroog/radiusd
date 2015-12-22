package mschap

import (
	"encoding/binary"
)

type ChallengeAttr struct {
	VendorId uint32
	VendorType uint8
	VendorLength uint8
	Value []byte
}

type ResponseAttr struct {
	VendorId uint32
	VendorType uint8
	VendorLength uint8
	Ident uint8
	Flags uint8
	LMResponse []byte //24bytes
	NTResponse []byte //24bytes
}

func DecodeResponse(b []byte) ResponseAttr {
	return ResponseAttr{
		VendorId: binary.BigEndian.Uint32(b[0:4]),
		VendorType: b[4],
		VendorLength: b[5],
		Ident: b[6],
		Flags: b[7],
		LMResponse: b[8:32],
		NTResponse: b[32:],
	}
}

func DecodeChallenge(b []byte) ChallengeAttr {
	return ChallengeAttr{
		VendorId: binary.BigEndian.Uint32(b[0:4]),
		VendorType: b[4],
		VendorLength: b[5],
		Value: b[6:],
	}
}
