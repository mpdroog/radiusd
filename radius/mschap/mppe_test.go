// tests for MPPE from https://www.ietf.org/rfc/rfc3079.txt
package mschap

import (
	"testing"
	"bytes"
	"fmt"
)

func TestLmPasswordHash(t *testing.T) {
	pass := "clientPass"
	expect := []byte{
		0x76, 0xa1, 0x52, 0x93, 0x60, 0x96, 0xd7, 0x83,
		0x0e, 0x23, 0x90, 0x22, 0x74, 0x04, 0xaf, 0xd2,
	}
	res, e := lmPasswordHash(pass)
	if e != nil {
		t.Fatal(e)
	}

	if bytes.Compare(res, expect) != 0 {
		t.Fatal(fmt.Printf("LmPasswordHash bytes wrong. expect=%d found=%d", expect, res))
	}
}

func TestMppev1(t *testing.T) {
	pass := "bob"
	passHash := ntPasswordHash(ntPassword(pass))
	expect := []byte{
		0x43, 0x18, 0xb1, 0x76, 0xc3, 0xd8, 0xe3, 0xde,
		0x9a, 0x93, 0x6f, 0xaf, 0x34, 0x43, 0x59, 0xa0,
		0xf1, 0xe3, 0xc9, 0xb5, 0x58, 0x5b, 0x9f, 0x1f,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}

	res, e := mppev1(pass, passHash)
	if e != nil {
		t.Fatal(e)
	}
	if bytes.Compare(res, expect) != 0 {
		t.Fatal(fmt.Printf("TestAnotherEncrypt bytes wrong. expect=%d found=%d", expect, res))
	}

}