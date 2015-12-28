package radius

import (
	"fmt"
)

func asByte(a AttributeType) bool {
	bytes := map[AttributeType]bool {
		UserPassword: true,
		NASIPAddress: true,
		NASPort: true,
		NASPortType: true,
		AcctStatusType: true,
		AcctAuthentic: true,
		FramedIPAddress: true,
		AcctSessionTime: true,
		AcctInputPackets: true,
		AcctOutputPackets: true,
		AcctInputOctets: true,
		AcctOutputOctets: true,
		AcctTerminateCause: true,
		CHAPPassword: true,
		VendorSpecific: true,
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
		if asByte(attr.Type()) {
			s += fmt.Sprintf("\t%s = %+v\n", attr.Type(), b)
		} else {
			s += fmt.Sprintf("\t%s = %s\n", attr.Type(), string(b))
		}
	}
	return s + "\n"
}