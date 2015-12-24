// mschap impl heavily inspired by https://github.com/FreeRADIUS/freeradius-server (C-code)
// Function naming same as https://tools.ietf.org/html/rfc2433 Appendix A - Pseudocode
package mschap

import (
	"crypto/des"
	"unicode/utf16"
	"golang.org/x/crypto/md4"
	"encoding/binary"
)

// Convert pass to UCS-2 (UTF-16)
func ntPassword(pass string) []byte {
	buf := utf16.Encode([]rune(pass))
	enc := make([]byte, len(pass)*2)
	for i := 0; i < len(pass); i++ {
		pos := 2*i
		binary.LittleEndian.PutUint16(enc[pos: pos+2], buf[i])
	}
	return enc
}

// MD4 hash the UCS-2 value
func ntPasswordHash(r []byte) []byte {
	d := md4.New()
	d.Write(r)
	return d.Sum(nil)
}

// Convert 7byte string into 8bit key
// https://github.com/FreeRADIUS/freeradius-server/blob/5ea87f156381174ea24340db9b450d4eca8189c9/src/modules/rlm_mschap/smbdes.c#L268
func strToKey(str []byte) []byte {
	key := make([]byte, 8)
    key[0] = str[0]>>1;
    key[1] = ((str[0]&0x01)<<6) | (str[1]>>2);
    key[2] = ((str[1]&0x03)<<5) | (str[2]>>3);
    key[3] = ((str[2]&0x07)<<4) | (str[3]>>4);
    key[4] = ((str[3]&0x0F)<<3) | (str[4]>>5);
    key[5] = ((str[4]&0x1F)<<2) | (str[5]>>6);
    key[6] = ((str[5]&0x3F)<<1) | (str[6]>>7);
    key[7] = str[6]&0x7F;

    for i := 0; i < 8; i++ {
        key[i] = (key[i]<<1);
    }
    return key
}

// Create Response for comparison
func ntChallengeResponse(challenge []byte, passHash []byte) ([]byte, error) {
	// Pass is already encoded (NTPasswordHash)
	// ChallengeResponse
	res := make([]byte, 24)
	zPasswordHash := make([]byte, 21)

    // Set ZPasswordHash to PasswordHash zero-padded to 21 octets
	for i := 0; i < len(passHash); i++ {
		zPasswordHash[i] = passHash[i]
	}

	// DesEncrypt first 7 bytes
	{
		block, e := des.NewCipher(strToKey(zPasswordHash[:7]))
		if e != nil {
			return nil, e
		}
		mode := newECBEncrypter(block)
		mode.CryptBlocks(res, challenge)
	}

	// DesEncrypt second 7 bytes
	{
		block, e := des.NewCipher(strToKey(zPasswordHash[7:14]))
		if e != nil {
			return nil, e
		}
		mode := newECBEncrypter(block)
		mode.CryptBlocks(res[8:], challenge)
	}

	// DesEncrypt last 7 bytes
	{
		block, e := des.NewCipher(strToKey(zPasswordHash[14:]))
		if e != nil {
			return nil, e
		}
		mode := newECBEncrypter(block)
		mode.CryptBlocks(res[16:], challenge)
	}
	return res, nil
}

// Encrypt MSCHAPv1 challenge+pass and return challengeresponse+MPPE
// OUT1 = ChallengeResponse is a computed value you can compare with the user
// supplied value.
// OUT2 = MPPE is to support 40bit encryption
func Encryptv1(challenge []byte, pass string) ([]byte, []byte, error) {
	passHash := ntPasswordHash(ntPassword(pass))
	res, e := ntChallengeResponse(challenge, passHash)
	if e != nil {
		return nil, nil, e
	}

	var mppe []byte
	{
		lm, e := lmPasswordHash(pass)
		if e != nil {
			return nil, nil, e
		}
		mppe = append(mppe, lm...)
		mppe = append(mppe, passHash...)
		mppe = append(mppe, []byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}...)
	}

	return res, mppe, nil
}
