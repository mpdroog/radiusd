// MPPE to support encryption with MSCHAPv1
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

// Implement LmPasswordHash for MPPE with MSCHAPv1
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

func Mppev1(pass string) ([]byte, error) {
	var res []byte
	passHash := ntPasswordHash(ntPassword(pass))

	lm, e := lmPasswordHash(pass)
	if e != nil {
		return nil, e
	}
	lm = lm[:8]

	res = append(res, lm...)
	/*
	 *	According to RFC 2548 we
	 *	should send NT hash.  But in
	 *	practice it doesn't work.
	 *	Instead, we should send nthashhash
	 *	This is an error in RFC 2548.
	 * https://github.com/FreeRADIUS/freeradius-server/blob/5ea87f156381174ea24340db9b450d4eca8189c9/src/modules/rlm_mschap/rlm_mschap.c#L1956
	 */
	res = append(res, hashNtPasswordHash(passHash)[:16]...)
	// padding
	res = append(res, []byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}...)

	return res, nil
}
