package main

import (
    "fmt"
    "net"

    "io"
    "encoding/binary"
    //"crypto"
    "crypto/hmac"
    "crypto/md5"
    "bytes"
)
const AUTH_PORT = 1812
const ACCOUNTING_PORT = 1813

type Attr struct {
    Type uint8
    Length uint8
    Value []byte
}

type Packet struct {
    Code uint8
    Identifier uint8
    Len uint16
    Auth []byte // Request Authenticator
    Attrs map[AttributeType]Attr
}

func Decode(buf []byte, n int) (*Packet, error) {
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

// Encode msg for validation
func Encode(p *Packet) []byte {
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
    fmt.Println("Enc", b[:written])
    return b[:written]
}

func Validate(p *Packet) bool {
    if check, ok := p.Attrs[MessageAuthenticator]; ok {
        fmt.Println("MessageAuthenticator found!")
        h := md5.New()
        temp := Encode(p)
        //h.Write(temp[0:4])
        //h.Write([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
        //h.Write(temp[20:])
        h.Write(temp)
        io.WriteString(h, "secret")
        
        if !hmac.Equal(check.Value, h.Sum(nil)) {
            return false
        }
    }
    return true
}

func main() {
    // auth
    addr, e := net.ResolveUDPAddr("udp", "127.0.0.1:1813")
    if e != nil {
        panic(e)
    }
    server, e := net.ListenUDP("udp", addr)
    if e != nil {
        panic(e)
    }
    defer server.Close()

    // Start reading packets
    buf := make([]byte, 1024)
    n, client, e := server.ReadFromUDP(buf)
    if e != nil {
        panic(e)
    }
    fmt.Println("RAW", buf)

    p, e := Decode(buf, n)
    if e != nil {
        panic(e)
    }
    fmt.Println(fmt.Sprintf("%+v", p))
    if !Validate(p) {
        panic("Validate failed!")
    }

    if PacketCode(p.Code) == AccessRequest {
        // Auth
        user := ""
        password := ""
        for _, attr := range p.Attrs {
            if AttributeType(attr.Type) == UserName {
                user = string(attr.Value)
            }
            if AttributeType(attr.Type) == UserPassword {
                h := md5.New()
                h.Write([]byte("secret"))
                h.Write(p.Auth)
                digest := h.Sum(nil)
                pass := attr.Value
                if len(pass) != 16 {
                    panic("Password field wrong?")
                }
                for i := 0; i < len(pass); i++ {
                    pass[i] = pass[i] ^ digest[i]
                }
                pass = bytes.TrimRight(pass, string([]rune{0}))
                password = string(pass)
            }
        }
        fmt.Println(user, password)

        // Packet
        np := &Packet{
            Code: uint8(AccessReject),
            Identifier: p.Identifier,
            Auth: p.Auth, // Set req auth
            Len: 0, // Set by Encode
            Attrs: make(map[AttributeType]Attr),
        }
        msg := Attr{
            Type: uint8(ReplyMessage),
            Value: []byte("Invalid user or pass"),
        }
        msg.Length = uint8(2 + len(msg.Value))
        np.Attrs[ReplyMessage] = msg

        if user == "herp" && password == "derp" {
            fmt.Println("Valid user+pass")
            np.Code = uint8(AccessAccept)
            msg := Attr{
                Type: uint8(ReplyMessage),
                Value: []byte("Accepted."),
            }
            msg.Length = uint8(2 + len(msg.Value))
            np.Attrs[ReplyMessage] = msg
        }

        // Encode
        nb := Encode(np)
        // Set right Response Authenticator
        //np.Auth = MD5(Code+ID+Length+RequestAuth+Attributes+Secret)
        h := md5.New()
        h.Write(nb)
        h.Write([]byte("secret"))
        res := h.Sum(nil)[:16]
        copy(nb[4:20], res)

        fmt.Println("OUT", nb)
        // Reply!
        if _, e := server.WriteTo(nb, client); e != nil {
            panic(e)
        }

        fmt.Println("Done!")
    }

    if PacketCode(p.Code) == AccountingRequest {
        // Acct!
        var (
            acctType uint32
            user string
            sessionId string
        )
        for _, attr := range p.Attrs {
            if AttributeType(attr.Type) == AcctStatusType {
                acctType = binary.BigEndian.Uint32(attr.Value)
            }
            if AttributeType(attr.Type) == UserName {
                user = string(attr.Value)
            }
            if AttributeType(attr.Type) == AcctSessionId {
                sessionId = string(attr.Value)
            }
        }
        fmt.Println(fmt.Sprintf(
            "type=%d sess=%s for user=%s",
            acctType, sessionId, user,
        ))
        /*
       1      Start
       2      Stop
       3      Interim-Update
       7      Accounting-On
       8      Accounting-Off
       9-14   Reserved for Tunnel Accounting
      15      Reserved for Failed
        */
        if acctType == 1 {
            //
            fmt.Println("One")
        }
    }
}