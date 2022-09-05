package eap

import (
	"fmt"
	"github.com/mpdroog/radiusd/radius/eap/pwd"
	"testing"
)

// TODO: MsgType == Identity
func TestDecodeEAPIdentity(t *testing.T) {
	bin := []byte{0x02, 0x2f, 0x00, 0x0a, 0x01, 0x73, 0x74, 0x65, 0x76, 0x65}
	p, e := Decode(bin)
	if e != nil {
		t.Fatal(e)
	}
	if testing.Verbose() {
		fmt.Printf("eap.Identity=%+v\n", p)
	}

	if p.Code != EAPResponse {
		t.Errorf("packet.Code not EAPResponse")
	}
	if p.ID != 47 {
		t.Errorf("packet.ID not valid")
	}
	if p.Length != 10 {
		t.Errorf("packet.Length not valid")
	}
	if p.MsgType != Identity {
		t.Errorf("packet.MsgType not valid")
	}
	if p.PayloadIdentity != "steve" {
		t.Errorf("packet.PayloadIdentity not valid")
	}
}

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

func TestEncodeEAPPwdResponse(t *testing.T) {
	// PWD:PWD={LMPWD=1, TotalLength=0 GroupDesc=19 RandomFunc=1 PRF=1 Token=3477573397 Prep=0 Identity=theserver@example.com}
	p := EAPPacket{
		Code:    EAPRequest,
		ID:      49,
		MsgType: EAPpwd,
		Data: pwd.Encode(&pwd.PWD{
			LMPWD:      1,
			GroupDesc:  19,
			RandomFunc: pwd.DefaultRandomFunc,
			PRF:        pwd.PRFHMACSHA256,
			Token:      3477573397,
			Prep:       0,
			Identity:   "theserver@example.com",
		}),
	}
	// Encode(p *EAPPacket, verbose bool, logger *log.Logger) ([]byte, error) {
	bin, e := Encode(&p, false, nil)
	if e != nil {
		t.Fatal(e)
	}
	if testing.Verbose() {
		fmt.Printf("eap.PWDEncode=%+x\n", bin)
	}
	out := fmt.Sprintf("%x", bin)
	if out != "01310024340100130101cf478f1500746865736572766572406578616d706c652e636f6d" {
		t.Errorf("Encode failed")
	}
}

func TestEncodeEAPPwdResponseInvalid(t *testing.T) {
	p := EAPPacket{
		Code: EAPFailure,
		ID:   49,
	}
	bin, e := Encode(&p, false, nil)
	if e != nil {
		t.Fatal(e)
	}
	if testing.Verbose() {
		fmt.Printf("eap.PWDEncode=%+x\n", bin)
	}
	out := fmt.Sprintf("%x", bin)
	if out != "04310004" {
		t.Errorf("Encode failed")
	}
}

func TestSecondChallenge(t *testing.T) {
	// Experiment with Wireshark dump
	// Server-Challenge > EAP-pwd-Commit > Element+Scalar
	{
		bin := []byte{
			0x01, 0x11, 0x00, 0x66, 0x34,
			0x02, 0x00, 0x6a, 0x5c, 0x04, 0x8b, 0x30, 0x07, 0x65, 0xdf, 0x15, 0x32, 0x7c, 0x64, 0x57, 0x34, //16
			0x34, 0x00, 0x5b, 0xd6, 0xcd, 0xa8, 0xeb, 0x8f, 0x08, 0x78, 0xc9, 0xb9, 0x15, 0xde, 0x8c, 0x43,
			0x18, 0x1f, 0xfc, 0xc1, 0x81, 0xfd, 0x6a, 0x01, 0x0b, 0x31, 0xad, 0xa3, 0x4c, 0x5f, 0x0e, 0xa0,
			0x7b, 0xef, 0x85, 0xb6, 0x1b, 0x88, 0xbc, 0xbb, 0x98, 0xbc, 0x44, 0x08, 0xf9, 0xe4, 0xb5, 0x7b,
			0xbe, 0x45, 0xc6, 0x53, 0x4b, 0x50, 0xe1, 0xbc, 0xf1, 0x6d, 0x69, 0xb0, 0xf5, 0xbd, 0x06, 0x3e,
			0xcb, 0xfe, 0x5f, 0x02, 0x44, 0x20, 0xa5, 0x3c, 0xfe, 0x89, 0x10, 0xa7, 0x6f, 0x24, 0x35, 0x06,
			0x73,
		}
		p, e := Decode(bin)
		if e != nil {
			t.Fatal(e)
		}
		if testing.Verbose() {
			fmt.Printf("eap.PWD=%+v\n", p)
		}

		if e := pwd.ProcessPeerCommit(p.PWD.CommitData); e != nil {
			t.Errorf("eap.ProcessPeerCommit e=%s\n", e)
		}
	}

	// Client-Request > EAP-pwd-Confirm > Confirm_P
	{
		bin := []byte{
			0x02, 0x11, 0x00, 0x66, 0x34, 0x02, 0x9c, 0xbe, 0xee, 0x93, 0x4b, 0x9f, 0xf2, 0x19, // 14
			0x37, 0xe3, 0x6f, 0xb8, 0x9a, 0x0e, 0x0e, 0x5f, 0x06, 0x30, 0x7b, 0x32, 0xea, 0xac, // 28
			0x52, 0x96, 0x49, 0xf4, 0xb2, 0x88, 0xd6, 0xe1, 0xdd, 0xa0, 0x55, 0x8e, 0xe3, 0xd5, //
			0x4b, 0x3f, 0xe4, 0xbd, 0x8e, 0x55, 0x98, 0x93, 0xd9, 0x7b, 0x75, 0xe3, 0xb9, 0x29,
			0x3d, 0x1d, 0x4f, 0xd8, 0xc3, 0x94, 0x76, 0xfe, 0xa7, 0xb0, 0x7f, 0x60, 0x8a, 0x78,
			0x9a, 0x16, 0x90, 0x06, 0xb8, 0xf3, 0xa5, 0xef, 0x6e, 0x8a, 0x44, 0x88, 0x2b, 0xa7,
			0x5c, 0x40, 0xd0, 0xab, 0x39, 0x5a, 0xfd, 0x28, 0x3e, 0xb8, 0x15, 0xa3, 0x63, 0xd2, // 98
			0xf4, 0x4b, 0x8c, 0x90, // 102
		}
		p, e := Decode(bin)
		if e != nil {
			t.Fatal(e)
		}
		if testing.Verbose() {
			fmt.Printf("eap.PWD2=%+v\n", p)
		}

		if e := pwd.ProcessPeerCommit(p.PWD.CommitData); e != nil {
			t.Errorf("eap.ProcessPeerCommit e=%s\n", e)
		}

	}
}
