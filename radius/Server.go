// Simple Radius server inspired on net/http.
package radius

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"radiusd/config"
)

var handlers map[string]func(io.Writer, *Packet)

func init() {
	handlers = make(map[string]func(io.Writer, *Packet))
}

func HandleFunc(code PacketCode, statusType int, handler func(io.Writer, *Packet)) {
	key := fmt.Sprintf("%d-%d", code, statusType)
	if _, inuse := handlers[key]; inuse {
		panic(fmt.Errorf("DevErr: HandleFunc-add for already assigned code=%d", code))
	}
	handlers[key] = handler
}

func Listen(addr string) (*net.UDPConn, error) {
	udpAddr, e := net.ResolveUDPAddr("udp", addr)
	if e != nil {
		return nil, e
	}
	return net.ListenUDP("udp", udpAddr)
}

func Serve(conn *net.UDPConn, secret string, cidrs []string) error {
	var whitelist []*net.IPNet

	for _, cidr := range cidrs {
		_, net, e := net.ParseCIDR(cidr)
		if e != nil {
			return e
		}
		whitelist = append(whitelist, net)
	}

	buf := make([]byte, 1024)
	readBuf := new(bytes.Buffer)
	for {
		n, client, e := conn.ReadFromUDP(buf)
		if e != nil {
			// TODO: Silently ignore?
			return e
		}
		ok := false
		for _, cidr := range whitelist {
			if cidr.Contains(client.IP) {
				ok = true
				break
			}
		}
		if !ok {
			config.Log.Printf("Request dropped for invalid IP=" + client.String())
			continue
		}

		p, e := decode(buf, n, secret)
		if e != nil {
			// TODO: Silently ignore decode?
			return e
		}
		if !validate(p) {
			// TODO: Silently ignore invalidate package?
			return fmt.Errorf("Invalid MessageAuthenticator")
		}

		statusType := uint32(0)
		if p.HasAttr(AcctStatusType) {
			attr := p.Attr(AcctStatusType)
			statusType = binary.BigEndian.Uint32(attr)
		}

		key := fmt.Sprintf("%d-%d", p.Code, statusType)
		handle, ok := handlers[key]
		if ok {
			handle(readBuf, p)
			if len(readBuf.Bytes()) != 0 {
				// Only send a packet if we got anything
				if _, e := conn.WriteTo(readBuf.Bytes(), client); e != nil {
					// TODO: ignore clients that gone away?
					panic(e)
				}
			}
		} else {
			fmt.Println(fmt.Sprintf("Drop packet with code=%d, statusType=%d", p.Code, statusType))
		}

		readBuf.Reset()
	}
}
