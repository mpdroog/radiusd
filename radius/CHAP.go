package radius

import (
	"bytes"
	"crypto/md5"
)

/*
  MD5(ID+secret+challenge)

  The Response Value is the one-way hash calculated over a stream of
  octets consisting of the Identifier, followed by (concatenated
  with) the "secret", followed by (concatenated with) the Challenge
  Value.  The length of the Response Value depends upon the hash
  algorithm used (16 octets for MD5).
  https://tools.ietf.org/html/rfc1994
*/
func CHAPMatch(pass string, chapPass []byte, chapChallenge []byte) bool {
	hash := chapPass[1:]

	h := md5.New()
	h.Write(chapPass[0:1]) // first byte is ID
	h.Write([]byte(pass))
	h.Write(chapChallenge)
	calc := h.Sum(nil)

	if bytes.Compare(hash, calc) == 0 {
		return true
	}
	return false
}
