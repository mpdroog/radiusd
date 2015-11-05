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
)

type Attr struct {
    Type uint8
    Length uint8
    Value []byte
}

// Wrapper around Attr
type PubAttr struct {
    Type AttributeType
    Value []byte
}

type Packet struct {
    Code uint8
    Identifier uint8
    Len uint16
    Auth []byte // Request Authenticator
    Attrs map[AttributeType]Attr
}

// Decode bytes into packet
func decode(buf []byte, n int) (*Packet, error) {
    p := &Packet{}
    p.Code = buf[0]
    p.Identifier = buf[1]
    p.Len = uint16(buf[2] + buf[3])
    p.Auth = buf[4:20] // 16 octets
    p.Attrs = make(map[AttributeType]Attr)

    // attrs
    i := 20
    for {
        if i >= n {
            break
        }

        attr := Attr{
            Type: buf[i],
            Length: buf[i+1],
        }
        b := i+2
        e := b + int(attr.Length) -2 // Length is including type+Length fields
        attr.Value = buf[b:e]
        p.Attrs[ AttributeType(attr.Type) ] = attr

        i = e
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
    for _, attr := range p.Attrs {
        aLen := len(attr.Value) +2 // add type+len fields
        if aLen > 255 || aLen < 2 {
            panic("Value too big for attr")
        }
        bb[0] = attr.Type
        bb[1] = uint8(aLen)
        copy(bb[2:], attr.Value)

        written += aLen
        bb = bb[aLen:]
    }

    // Now set Len
    binary.BigEndian.PutUint16(b[2:4], uint16(written))
    //fmt.Println("Enc", b[:written])
    return b[:written]
}

// MessageAuthenticate if any
func validate(secret string, p *Packet) bool {
    if check, ok := p.Attrs[MessageAuthenticator]; ok {
        h := md5.New()
        temp := encode(p)
        //h.Write(temp[0:4])
        //h.Write([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
        //h.Write(temp[20:])
        h.Write(temp)
        h.Write([]byte(secret))
        
        if !hmac.Equal(check.Value, h.Sum(nil)) {
            return false
        }
    }
    return true
}


// Create response packet
func (p *Packet) Response(secret string, code PacketCode, attrs []PubAttr) []byte {
    n := &Packet{
        Code: uint8(code),
        Identifier: p.Identifier,
        Auth: p.Auth, // Set req auth
        Len: 0, // Set by Encode
        Attrs: make(map[AttributeType]Attr),
    }

    for _, attr := range attrs {
        msg := Attr{
            Type: uint8(attr.Type),
            Value: attr.Value,
        }
        msg.Length = uint8(2 + len(msg.Value))
        n.Attrs[AttributeType(msg.Type)] = msg
    }

    // Encode
    r := encode(n)

    // Set right Response Authenticator
    // MD5(Code+ID+Length+RequestAuth+Attributes+Secret)
    h := md5.New()
    h.Write(r)
    h.Write([]byte(secret))
    res := h.Sum(nil)[:16]
    copy(r[4:20], res)

    return r
}