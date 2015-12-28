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

type Attr struct {
	Type   AttributeType
	Length uint8
	Value  []byte
}

// Wrapper around Attr
type PubAttr struct {
	Type  AttributeType
	Value []byte
}

type Packet struct {
	secret     string // shared secret
	Code       uint8
	Identifier uint8
	Len        uint16
	Auth       []byte // Request Authenticator
	AllAttrs   []Attr
}

func (p *Packet) Secret() string {
	return p.secret
}
// Get first packet by key
func (p *Packet) Attr(key AttributeType) []byte {
	for _, a := range p.AllAttrs {
		if a.Type == key {
			return a.Value
		}
	}
	panic(fmt.Sprintf("No such key %s", key.String()))
}
// If requested attribute exists
func (p *Packet) HasAttr(key AttributeType) bool {
	for _, a := range p.AllAttrs {
		if a.Type == key {
			return true
		}
	}
	return false
}

// Decode bytes into packet
func decode(buf []byte, n int, secret string) (*Packet, error) {
	p := &Packet{}
	p.secret = secret
	p.Code = buf[0]
	p.Identifier = buf[1]
	p.Len = binary.BigEndian.Uint16(buf[2:4])

	p.Auth = buf[4:20] // 16 octets
	//p.Attrs = make(map[AttributeType]Attr)

	// attrs
	i := 20
	for {
		if i >= n {
			break
		}

		attr := Attr{
			Type:   AttributeType(buf[i]),
			Length: buf[i+1],
		}
		b := i + 2
		e := b + int(attr.Length) - 2 // Length is including type+Length fields
		attr.Value = buf[b:e]
		p.AllAttrs = append(p.AllAttrs, attr)
		//p.Attrs[AttributeType(attr.Type)] = attr

		i = e
	}
	if config.Debug {
		config.Log.Printf("packet.decode: %+v", p)
		/*logAttrs := "packet.decode:\n"
		for _, attr := range p.AllAttrs {
			logAttrs += fmt.Sprintf("\t%s\t\t%s", attr.String() + "\n"
		}
		config.Log.Printf(logAttrs)*/
	}
	return p, nil
}

// Encode packet into bytes
func encode(p *Packet) []byte {
	b := make([]byte, 1024)
	b[0] = p.Code
	b[1] = p.Identifier
	// Skip Len for now 2+3
	copy(b[4:20], p.Auth)
	written := 20

	bb := b[20:]
	for _, attr := range p.AllAttrs {
		aLen := len(attr.Value) + 2 // add type+len fields
		if aLen > 255 || aLen < 2 {
			panic("Value too big for attr")
		}
		bb[0] = uint8(attr.Type)
		bb[1] = uint8(aLen)
		copy(bb[2:], attr.Value)

		written += aLen
		bb = bb[aLen:]
	}

	// Now set Len
	binary.BigEndian.PutUint16(b[2:4], uint16(written))
	if config.Debug {
		config.Log.Printf("packet.encode: %+v", p)
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
func (p *Packet) Response(code PacketCode, attrs []PubAttr) []byte {
	n := &Packet{
		Code:       uint8(code),
		Identifier: p.Identifier,
		Auth:       p.Auth, // Set req auth
		Len:        0,      // Set by Encode
		//Attrs:      make(map[AttributeType]Attr),
	}

	for _, attr := range attrs {
		msg := Attr{
			Type:  attr.Type,
			Value: attr.Value,
		}
		msg.Length = uint8(2 + len(msg.Value))
		n.AllAttrs = append(n.AllAttrs, msg)
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
