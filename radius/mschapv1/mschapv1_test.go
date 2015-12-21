// tests for mschapv1 from https://tools.ietf.org/html/rfc2433#appendix-B.2
package mschapv1

import (
	"fmt"
	"testing"
	"bytes"
)

func TestNTPassword(t *testing.T) {
	ntPass := ntPassword("MyPw")
	if len(ntPass) != 8 {
		t.Error(fmt.Printf("NTPassword len expect=8 actual=%d", len(ntPass)))
	}

	expect := []byte{0x4D, 0x00, 0x79, 0x00, 0x50, 0x00, 0x77, 0x00}
	if bytes.Compare(ntPass, expect) != 0 {
		t.Fatal(fmt.Printf("NTPassword bytes wrong. expect=%d found=%d", expect, ntPass))
	}
}

func TestNTPasswordHash(t *testing.T) {
	// 16oct
	val := ntPasswordHash(ntPassword("MyPw"))
	expect := []byte{
		0xFC, 0x15, 0x6A, 0xF7, 0xED, 0xCD, 0x6C,
		0x0E, 0xDD, 0xE3, 0x33, 0x7D, 0x42, 0x7F,
		0x4E, 0xAC,
	}
	if bytes.Compare(val, expect) != 0 {
		t.Fatal(fmt.Printf("NTPasswordHash bytes wrong. expect=%d found=%d", expect, val))
	}
}

func TestEncryptMSCHAP1(t *testing.T) {
	challenge := []byte{0x10, 0x2D, 0xB5, 0xDF, 0x08, 0x5D, 0x30, 0x41}
	expect := []byte{
		0x4E, 0x9D, 0x3C, 0x8F, 0x9C, 0xFD, 0x38, 0x5D,
		0x5B, 0xF4, 0xD3, 0x24, 0x67, 0x91, 0x95, 0x6C,
		0xA4, 0xC3, 0x51, 0xAB, 0x40, 0x9A, 0x3D, 0x61,
	}

	res, e := Encrypt(challenge, "MyPw")
	if e != nil {
		t.Fatal(e)
	}
	if bytes.Compare(res, expect) != 0 {
		t.Fatal(fmt.Printf("TestEncryptMSCHAP1 bytes wrong. expect=%d found=%d", expect, res))
	}
}

/*
 radclient test.
 MS-CHAP-Challenge = 0x15516e769584c6d8
 MS-CHAP-Response = 0x00010000000000000000000000000000000000000000000000003a3c9f1c7da79174dc167532d360ab5efd01853173c8214e
 */
func TestAnotherEncrypt(t *testing.T) {
	challenge := []byte{0x15, 0x51, 0x6e, 0x76, 0x95, 0x84, 0xc6, 0xd8}
	expect := []byte{
		0x3a, 0x3c, 0x9f, 0x1c, 0x7d, 0xa7, 0x91, 0x74,
		0xdc, 0x16, 0x75, 0x32, 0xd3, 0x60, 0xab, 0x5e,
		0xfd, 0x01, 0x85, 0x31, 0x73, 0xc8, 0x21, 0x4e,
	}

	res, e := Encrypt(challenge, "derpderp")
	if e != nil {
		t.Fatal(e)
	}
	if bytes.Compare(res, expect) != 0 {
		t.Fatal(fmt.Printf("TestAnotherEncrypt bytes wrong. expect=%d found=%d", expect, res))
	}
}