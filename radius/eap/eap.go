// Copyright Apache2
// https://github.com/C0d5/go-eap/blob/1c6f8980d8f61859e41b2e9751df8a136f134b37/eap/model.go#L53
package eap

import (
	"encoding/binary"
	"fmt"
	"github.com/mpdroog/radiusd/radius/eap/pwd"
	"log"
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
	TLS       EapType = 13
	Peap      EapType = 25
	MSChapv2  EapType = 26
	TLV       EapType = 33
	EAPpwd    EapType = 52
)

type EAPPacket struct {
	Code    EapCode
	ID      uint8
	Length  uint16
	MsgType EapType

	PayloadIdentity string // Only used for decoding
	PWD             *pwd.PWD
	Data            []byte // Used for encoding
}

func Decode(b []byte) (*EAPPacket, error) {
	p := new(EAPPacket)
	p.Code = EapCode(b[0])
	p.ID = uint8(b[1])
	p.Length = binary.BigEndian.Uint16(b[2:])

	if p.Length != uint16(len(b)) {
		return nil, fmt.Errorf("EAP packet.length invalid")
	}

	if len(b) > 4 && (p.Code == EAPRequest || p.Code == EAPResponse) {
		p.MsgType = EapType(b[4])
	}

	if p.MsgType == Identity {
		p.PayloadIdentity = string(b[5:])
	} else if p.MsgType == EAPpwd {
		p.PWD = pwd.Decode(b[5:p.Length]) // pre-calc length so we can be lazy in pwd-pkg
	} else {
		p.Data = b[5:]
	}

	return p, nil
}

func Encode(p *EAPPacket, verbose bool, logger *log.Logger) ([]byte, error) {
	b := make([]byte, 1024)
	b[0] = uint8(p.Code)
	b[1] = uint8(p.ID)
	// Skip Len for now, as we don't know this yet (pos 2+3)

	if p.Code == EAPFailure {
		binary.BigEndian.PutUint16(b[2:4], uint16(4))
		return b[:4], nil
	}

	b[4] = uint8(p.MsgType)
	aLen := len(p.Data) + 2 // add type+len fields
	if aLen > 255 || aLen < 2 {
		panic("Value too big for attr")
	}
	copy(b[5:], p.Data)

	// Now set Len
	binary.BigEndian.PutUint16(b[2:4], uint16(aLen+3))
	if verbose {
		logger.Printf("packet.send: %+v\n", p)
	}
	return b[:aLen+3], nil
}
