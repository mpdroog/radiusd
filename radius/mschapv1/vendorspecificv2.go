package mschapv1

import (
	"encoding/binary"
)

type Response2Attr struct {
	VendorId uint32
	VendorType uint8
	VendorLength uint8
	Ident uint8
	Flags uint8
	PeerChallenge []byte //16bytes
	// 8bytes zero
	Response []byte //24bytes
}

func DecodeResponse2(b []byte) Response2Attr {
	return Response2Attr{
		VendorId: binary.BigEndian.Uint32(b[0:4]),
		VendorType: b[4],
		VendorLength: b[5],
		Ident: b[6],
		Flags: b[7],
		PeerChallenge: b[8:24],
		// reserved 24-32
		Response: b[32:],
	}
}