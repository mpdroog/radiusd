// EAP-PWD
// https://datatracker.ietf.org/doc/html/rfc5931
package pwd

import (
	"encoding/binary"
	"fmt"
)

type PWDExch uint8
type PrepTechnique uint8

const (
	Reserved           PWDExch = 0
	PWDIDExchange      PWDExch = 1
	PWDCommitExchange  PWDExch = 2
	PWDConfirmExchange PWDExch = 3

	DefaultRandomFunc uint8 = 0x01
	PRFHMACSHA256     uint8 = 0x01

	PrepNone    PrepTechnique = 0x00
	PrepRFC2759 PrepTechnique = 0x01
	PrepSASL    PrepTechnique = 0x02
)

// Ciphersuite, Token, Password Processing Method, Server_ID
// https://datatracker.ietf.org/doc/html/rfc5931#section-2.8.5.1
// https://datatracker.ietf.org/doc/html/rfc5931#section-3.2.1
type PWD struct {
	LMPWD       uint8 // Byte-field containing L|M|PWDType
	TotalLength uint16

	// PWDID
	GroupDesc  uint16 // Oakley group??
	RandomFunc uint8  // H(x) = HMAC-SHA-256([0]32, x)
	PRF        uint8
	Token      uint32        // contains an unpredictable value assigned by the server in an EAP-pwd-ID/Request and acknowledged by the peer
	Prep       PrepTechnique // Password Pre-processing technique
	Identity   string        // ServerID/PeerID
}

func (p *PWD) String() string {
	return fmt.Sprintf("PWD={LMPWD=%d, TotalLength=%d GroupDesc=%d RandomFunc=%d PRF=%d Token=%d Prep=%d Identity=%s}", p.LMPWD, p.TotalLength, p.GroupDesc, p.RandomFunc, p.PRF, p.Token, p.Prep, p.Identity)
}

func (p *PWD) GetType() PWDExch {
	// Extract first two bits out (L+M)
	// 00111111(2)=63(10)
	return PWDExch(p.LMPWD & 63)
}
func (p *PWD) IsLBitSet() bool {
	// L=10000000(2)=128(10)
	return (p.LMPWD & 128) == 1
}
func (p *PWD) IsMBitSet() bool {
	// L=01000000(2)=64(10)
	return (p.LMPWD & 64) == 1
}
func Decode(buf []byte) *PWD {
	p := &PWD{}
	p.LMPWD = buf[0]

	// The Total-Length field is two octets in length, and is present
	// only if the L bit is set.  This field provides the total length of
	// the EAP-pwd message or set of messages that is being fragmented.
	if p.IsLBitSet() {
		// TODO: Need to save this number when next packet comes in for checking length?
		p.TotalLength = binary.BigEndian.Uint16(buf[1:3])
		// TODO: nasty trick/does it work?
		buf = buf[3:]
	}
	if p.IsMBitSet() {
		panic("Need second packet...")
	}

	if p.GetType() == PWDIDExchange {
		p.GroupDesc = binary.BigEndian.Uint16(buf[1:3])
		p.RandomFunc = buf[3]
		p.PRF = buf[4]
		p.Token = binary.BigEndian.Uint32(buf[5:9])
		p.Prep = PrepTechnique(buf[9])
		p.Identity = string(buf[10:])
	} else {
		panic("Unsupported PWD Type")
	}

	return p
}
