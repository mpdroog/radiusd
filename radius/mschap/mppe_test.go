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