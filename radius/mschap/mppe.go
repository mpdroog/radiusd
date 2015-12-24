// MPPE to support Microsoft Point-to-Point Encryption Protocol
package mschap

import (
	"crypto/des"
	"strings"
)

func desHash(clear []byte) ([]byte, error) {
	block, e := des.NewCipher(strToKey(clear)) // clear=secret
	if e != nil {
		return nil, e
	}

	res := make([]byte, 8)
	mode := newECBEncrypter(block)
	mode.CryptBlocks(res, []byte(`KGS!@#$%`))
	return res, nil
}

// Implement LmPasswordHash for 40-bit MPPE
func lmPasswordHash(pass string) ([]byte, error) {
	pass = strings.ToUpper(pass) // enforce uppercase
	ZUCPass := make([]byte, 14)  // zero UpperCasePass
	maxlen := len(pass)
	if maxlen > 14 {
		maxlen = 14
	}
	for i := 0; i < maxlen; i++ {
		ZUCPass[i] = byte(pass[i])
	}

	var res []byte
	// Des "Hash" first 7 bytes
	{
		hash, e := desHash(ZUCPass[:7])
		if e != nil {
			return nil, e
		}
		res = append(res, hash...)
	}
	// Des "Hash" second 7 bytes
	{
		hash, e := desHash(ZUCPass[7:14])
		if e != nil {
			return nil, e
		}
		res = append(res, hash...)
	}

	return res, nil
}
