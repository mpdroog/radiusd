// tests for mschapv1 from https://tools.ietf.org/html/rfc2433#appendix-B.2
package mschap

import (
	"fmt"
	"testing"
	"bytes"
)

func TestNTPassword(t *testing.T) {
	ntPass := NTPassword("MyPw")
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
	val := NTPasswordHash(NTPassword("MyPw"))
	expect := []byte{
		0xFC, 0x15, 0x6A, 0xF7, 0xED, 0xCD, 0x6C,
		0x0E, 0xDD, 0xE3, 0x33, 0x7D, 0x42, 0x7F,
		0x4E, 0xAC,
	}
	if bytes.Compare(val, expect) != 0 {
		t.Fatal(fmt.Printf("NTPasswordHash bytes wrong. expect=%d found=%d", expect, val))
	}
}

func TestNtChallengeResponse(t *testing.T) {
	challenge := []byte{0x10, 0x2D, 0xB5, 0xDF, 0x08, 0x5D, 0x30, 0x41}
	passHash := NTPasswordHash(NTPassword("MyPw"))
	expect := []byte{
		0x4E, 0x9D, 0x3C, 0x8F, 0x9C, 0xFD, 0x38, 0x5D,
		0x5B, 0xF4, 0xD3, 0x24, 0x67, 0x91, 0x95, 0x6C,
		0xA4, 0xC3, 0x51, 0xAB, 0x40, 0x9A, 0x3D, 0x61,
	}

	res, e := NtChallengeResponse(challenge, passHash)
	if e != nil {
		t.Fatal(e)
	}
	if bytes.Compare(res, expect) != 0 {
		t.Fatal(fmt.Printf("NtChallengeResponse bytes wrong. expect=%d found=%d", expect, res))
	}
}