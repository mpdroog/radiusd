// Copyright Apache2
// https://github.com/C0d5/go-eap/blob/1c6f8980d8f61859e41b2e9751df8a136f134b37/eap/model.go#L53
package eap

import (
	"encoding/binary"
	"fmt"
)

type EapCode uint8
type EapType uint8

const (
	EAPRequest  EapCode = 1
	EAPResponse EapCode = 2
	EAPSuccess  EapCode = 3
	EAPFailure  EapCode = 4
)

// https://www.vocal.com/secure-communication/eap-types/
const (
	Identity  EapType = 1
	LegacyNak EapType = 3
	Peap      EapType = 25
	MsChapv2  EapType = 26
	TLV       EapType = 33
	TLS       EapType = 13
)

type EAPPacket struct {
	code    EapCode
	id      uint8
	length  uint16
	msgType EapType

	PayloadIdentity string
}

func Decode(b []byte) (*EAPPacket, error) {
	p := new(EAPPacket)
	p.code = EapCode(b[0])
	p.id = uint8(b[1])
	p.length = binary.BigEndian.Uint16(b[2:])

	if p.length != uint16(len(b)) {
		return nil, fmt.Errorf("EAP packet.length invalid")
	}

	if len(b) > 4 && (p.code == EAPRequest || p.code == EAPResponse) {
		p.msgType = EapType(b[4])
	}

	if p.msgType != Identity {
		return nil, fmt.Errorf("EAP only supports Identity-auth")
	}

	p.PayloadIdentity = string(b[5:])
	return p, nil
}
