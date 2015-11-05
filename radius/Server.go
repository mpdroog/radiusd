// Simple Radius server inspired on net/http.
package radius

import (
	"bytes"
	"io"
	"fmt"
	"net"
	"encoding/binary"
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
	handlers[ key ] = handler
}

func ListenAndServe(addr string, secret string) error {
	udpAddr, e := net.ResolveUDPAddr("udp", addr)
    if e != nil {
        return e
    }
    conn, e := net.ListenUDP("udp", udpAddr)
    if e != nil {
        return e
    }

	buf := make([]byte, 1024)
	readBuf := new(bytes.Buffer)
    for {
	    n, client, e := conn.ReadFromUDP(buf)
	    if e != nil {
	    	// TODO: Silently ignore?
	    	return e
	    }
	    p, e := decode(buf, n)
	    if e != nil {
	    	// TODO: Silently ignore decode?
	    	return e
	    }
        if !validate(secret, p) {
	        // TODO: Silently ignore invalidate package?
	        return fmt.Errorf("Invalid MessageAuthenticator")
    	}

    	statusType := uint32(0)
    	if attr, ok := p.Attrs[AcctStatusType]; ok {
			statusType = binary.BigEndian.Uint32(attr.Value)
    	}

    	key := fmt.Sprintf("%d-%d", p.Code, statusType)
    	handle, ok := handlers[key]
    	if ok {
    		handle(readBuf, p)
    		if _, e := conn.WriteTo(readBuf.Bytes(), client); e != nil {
    			// TODO: ignore clients that gone away?
            	panic(e)
        	}
    	} else {
    		fmt.Println(fmt.Sprintf("Drop packet with code=%d, statusType=%d", p.Code, statusType))
    	}

	    readBuf.Reset()
    }
}
