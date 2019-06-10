package radius

import (
	"fmt"
)

func asString(a AttributeType) bool {
	bytes := map[AttributeType]bool{
		UserName:         true,
		CallingStationId: true,
		CalledStationId:  true,
		NASIdentifier:    true,
		ReplyMessage:     true,
		AcctSessionId:    true,
		ConnectInfo:      true,
	}
	return bytes[a]
}

/*
	type Packet struct {
		secret     string // shared secret
		Code       PacketCode
		Identifier uint8
		Len        uint16
		Auth       []byte // Request Authenticator
		Attrs   []AttrEncoder
	}
*/
func debug(p *Packet) string {
	s := fmt.Sprintf("Code=%s Ident=%d\n", p.Code, p.Identifier)
	for _, attr := range p.Attrs {
		b := attr.Bytes()
		if asString(attr.Type()) {
			s += fmt.Sprintf("\t%s = %s\n", attr.Type(), string(b))
		} else {
			s += fmt.Sprintf("\t%s = %+v\n", attr.Type(), b)
		}
	}
	return s + "\n"
}
