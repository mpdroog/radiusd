package eap

import (
	"fmt"
	"github.com/mpdroog/radiusd/radius/eap/pwd"
	"testing"
)

// TODO: MsgType == Identity

func TestDecodeEAPPwd(t *testing.T) {
	// Datadump collect with Wireshark and freeradius-server
	bin := []byte{
		0x01, 0x31, 0x00, 0x24, 0x34, 0x01, 0x00, 0x13, 0x01, 0x01, 0xcf, 0x47, 0x8f, 0x15, 0x00, 0x74,
		0x68, 0x65, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x40, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,
		0x2e, 0x63, 0x6f, 0x6d,
	}
	p, e := Decode(bin)
	if e != nil {
		t.Fatal(e)
	}
	if testing.Verbose() {
		fmt.Printf("eap.PWD=%+v\n", p)
	}

	if p.Code != EAPRequest {
		t.Errorf("packet.Code not EAPRequest")
	}
	if p.ID != 49 {
		t.Errorf("packet.ID not 49")
	}
	if p.Length != 36 {
		t.Errorf("packet.Length not 36")
	}
	if p.MsgType != EAPpwd {
		t.Errorf("packet.MsgType not EAPPWD")
	}
	if p.PWD.GetType() != pwd.PWDIDExchange {
		t.Errorf("packet.PWDIDExchange expected")
	}
	if p.PWD.GroupDesc != 19 {
		t.Errorf("packet.GroupDesc not 19, recv=%d", p.PWD.GroupDesc)
	}
	if p.PWD.RandomFunc != pwd.DefaultRandomFunc {
		t.Errorf("packet.RandomFunc should be default")
	}
	if p.PWD.PRF != pwd.PRFHMACSHA256 {
		t.Errorf("packet.PRF should be HMACSHA256")
	}
	if p.PWD.Prep != 0 {
		t.Errorf("packet.Prep should be 0")
	}
	if p.PWD.Identity != "theserver@example.com" {
		t.Errorf("packet.Identity is wrong")
	}
}
