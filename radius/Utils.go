package radius

import (
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"net"
)

// Decode 4 octets to IPv4 address
func DecodeIP(b []byte) net.IP {
	return net.IPv4(b[0], b[1], b[2], b[3])
}

func DecodeFour(b []byte) uint32 {
	return binary.BigEndian.Uint32(b)
}

func EncodeFour(in uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, uint32(in))
	return b
}

func DecryptPassword(raw []byte, p *Packet) string {
	if len(raw) != 16 {
		panic("User-Password invalid length (not 16 octets)")
	}

	h := md5.New()
	h.Write([]byte(p.secret))
	h.Write(p.Auth)
	digest := h.Sum(nil)

	for i := 0; i < len(raw); i++ {
		// XOR
		raw[i] = raw[i] ^ digest[i]
	}

	raw = bytes.TrimRight(raw, string([]rune{0}))
	return string(raw)
}

// Create a simple response.
func DefaultPacket(p *Packet, code PacketCode, msg string) []byte {
	return p.Response(
		code, []AttrEncoder{
			NewAttr(ReplyMessage, []byte(msg), 0),
		},
	)
}

func ValidateAuthRequest(p *Packet) string {
	// An Access-Request SHOULD contain a User-Name attribute.
	if !p.HasAttr(UserName) {
		return "UserName missing"
	}

	// It MUST contain either a NAS-IP-Address attribute or a NAS-Identifier
	// attribute (or both).
	if !p.HasAttr(NASIPAddress) {
		return "NasIPAddress missing"
	}
	if !p.HasAttr(NASIdentifier) {
		return "NasIdentifier missing"
	}

	// An Access-Request MUST contain either a User-Password or a CHAP-
	// Password or a State.  An Access-Request MUST NOT contain both a
	// User-Password and a CHAP-Password.
	if !p.HasAttr(UserPassword) {
		if !p.HasAttr(CHAPPassword) {
			if !p.HasAttr(VendorSpecific) {
				return "UserPassword/CHAP-Password/VendorSpeficic missing"
			}
		}
	}

	// An Access-Request SHOULD contain a NAS-Port or NAS-Port-Type
	// attribute or both unless the type of access being requested does
	// not involve a port or the NAS does not distinguish among its
	// ports.
	if !p.HasAttr(NASPort) {
		return "NASPort missing"
	}
	if !p.HasAttr(NASPortType) {
		return "NASPortType missing"
	}

	// All OK
	return ""
}

// Return non-empty string on error
func ValidateAcctRequest(p *Packet) string {
	// the following attributes MUST NOT be present in an Accounting-
	// Request:  User-Password, CHAP-Password, Reply-Message, State.
	if p.HasAttr(UserPassword) {
		return "UserPassword not allowed"
	}
	if p.HasAttr(CHAPPassword) {
		return "CHAPPassword not allowed"
	}
	if p.HasAttr(ReplyMessage) {
		return "ReplyMessage not allowed"
	}
	if p.HasAttr(State) {
		return "State not allowed"
	}

	// Either NAS-IP-Address or NAS-Identifier MUST be present in a
	// RADIUS Accounting-Request.
	if !p.HasAttr(NASIPAddress) {
		return "NASIPAddress missing"
	}
	if !p.HasAttr(NASIdentifier) {
		return "NASIdentifier missing"
	}

	// It SHOULD contain a NAS-Port or NAS-
	// Port-Type attribute or both unless the service does not involve a
	// port or the NAS does not distinguish among its ports.
	if !p.HasAttr(NASPort) {
		return "NASPort missing"
	}
	if !p.HasAttr(NASPortType) {
		return "NASPortType missing"
	}

	// All OK!
	return ""
}
