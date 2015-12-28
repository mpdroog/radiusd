// Packet to interpret the bits
// https://tools.ietf.org/html/rfc2865
// https://tools.ietf.org/html/rfc2866
//
// https://github.com/bronze1man/radius
// https://github.com/hoffoo/go-radius
// https://github.com/alouca/goradius
package radius

// TODO: Convert magicnumbers to const?

import (
	"crypto/hmac"
	"crypto/md5"
	"encoding/binary"
	"radiusd/config"
	"fmt"
)

type Packet struct {
	secret     string // shared secret
	Code       PacketCode
	Identifier uint8
	Len        uint16
	Auth       []byte // Request Authenticator
	Attrs   []AttrEncoder
}

func (p *Packet) Secret() string {
	return p.secret
}
// Get first packet by key
func (p *Packet) Attr(key AttributeType) []byte {
	for _, a := range p.Attrs {
		if a.Type() == key {
			return a.Bytes()
		}
	}
	panic(fmt.Sprintf("No such key %s", key.String()))
}
// If requested attribute exists
func (p *Packet) HasAttr(key AttributeType) bool {
	for _, a := range p.Attrs {
		if a.Type() == key {
			return true
		}
	}
	return false
}

// Decode bytes into packet
func decode(buf []byte, n int, secret string) (*Packet, error) {
	p := &Packet{}
	p.secret = secret
	p.Code = PacketCode(buf[0])
	p.Identifier = buf[1]
	p.Len = binary.BigEndian.Uint16(buf[2:4])

	p.Auth = buf[4:20] // 16 octets

	// attrs
	i := 20
	for {
		if i >= n {
			break
		}

		length := uint8(buf[i+1])
		b := i + 2
		e := b + int(length) - 2 // Length is including type+Length fields
		attr := NewAttr(AttributeType(buf[i]), buf[b:e], length)
		p.Attrs = append(p.Attrs, attr)

		i = e
	}
	if config.Verbose {
		config.Log.Printf("packet.receive: " + debug(p))
	}
	return p, nil
}

// Encode packet into bytes
func encode(p *Packet) []byte {
	b := make([]byte, 1024)
	b[0] = uint8(p.Code)
	b[1] = p.Identifier
	// Skip Len for now 2+3
	copy(b[4:20], p.Auth)
	written := 20

	bb := b[20:]
	for _, attr := range p.Attrs {
		aLen := len(attr.Bytes()) + 2 // add type+len fields
		if aLen > 255 || aLen < 2 {
			panic("Value too big for attr")
		}
		bb[0] = uint8(attr.Type())
		bb[1] = uint8(aLen)
		copy(bb[2:], attr.Bytes())

		written += aLen
		bb = bb[aLen:]
	}

	// Now set Len
	binary.BigEndian.PutUint16(b[2:4], uint16(written))
	if config.Verbose {
		config.Log.Printf("packet.send: " + debug(p))
	}
	return b[:written]
}

// MessageAuthenticate if any
func validate(p *Packet) bool {
	if p.HasAttr(MessageAuthenticator) {
		check := p.Attr(MessageAuthenticator)
		h := md5.New()
		temp := encode(p)
		//h.Write(temp[0:4])
		//h.Write([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
		//h.Write(temp[20:])
		h.Write(temp)
		h.Write([]byte(p.secret))

		if !hmac.Equal(check, h.Sum(nil)) {
			return false
		}
	}
	return true
}

// Create response packet
func (p *Packet) Response(code PacketCode, attrs []AttrEncoder) []byte {
	n := &Packet{
		Code:       code,
		Identifier: p.Identifier,
		Auth:       p.Auth, // Set req auth
		Len:        0,      // Set by Encode
		//Attrs:      make(map[AttributeType]Attr),
	}

	for _, attr := range attrs {
		msg := NewAttr(attr.Type(), attr.Bytes(), uint8(2 + len(attr.Bytes())))
		n.Attrs = append(n.Attrs, msg)
	}

	// Encode
	r := encode(n)

	// Set right Response Authenticator
	// MD5(Code+ID+Length+RequestAuth+Attributes+Secret)
	h := md5.New()
	h.Write(r)
	h.Write([]byte(p.secret))
	res := h.Sum(nil)[:16]
	copy(r[4:20], res)

	return r
}
