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
	DefaultLMPWD uint8 = 1

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

/**
  In order to use a Diffie-Hellman group with IKE, it is required that
  a transform ID for the group be registered with IANA.  The following
  table provides the Transform IDs of each Diffie-Hellman group

  NAME                                                    | NUMBER
  --------------------------------------------------------+---------
  1024-bit MODP Group with 160-bit Prime Order Subgroup   |   22
  2048-bit MODP Group with 224-bit Prime Order Subgroup   |   23
  2048-bit MODP Group with 256-bit Prime Order Subgroup   |   24
  192-bit Random ECP Group                                |   25
  224-bit Random ECP Group                                |   26
  256-bit Random ECP Group                                |   19 // NID_X9_62_prime256v1
  384-bit Random ECP Group                                |   20
  521-bit Random ECP Group                                |   21

  https://datatracker.ietf.org/doc/html/rfc5114#section-3.2
*/

// Ciphersuite, Token, Password Processing Method, Server_ID
// https://datatracker.ietf.org/doc/html/rfc5931#section-2.8.5.1
// https://datatracker.ietf.org/doc/html/rfc5931#section-3.2.1
type PWD struct {
	LMPWD       uint8 // Byte-field containing L|M|PWDType
	TotalLength uint16

	// Type=EAP-PWD ExchangeStep=PWDID
	GroupDesc  uint16 // Oakley groups? 19=Diffie-Hellman Group
	RandomFunc uint8  // H(x) = HMAC-SHA-256([0]32, x)
	PRF        uint8
	Token      uint32        // contains an unpredictable value assigned by the server in an EAP-pwd-ID/Request and acknowledged by the peer
	Prep       PrepTechnique // Password Pre-processing technique

	//Type=EAP-PWD ExchangeStep=Commit
	CommitData []byte

	// Type=Identity
	Identity string // ServerID/PeerID
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

	pwType := p.GetType()
	if pwType == PWDIDExchange {
		p.GroupDesc = binary.BigEndian.Uint16(buf[1:3])
		p.RandomFunc = buf[3]
		p.PRF = buf[4]
		p.Token = binary.BigEndian.Uint32(buf[5:9])
		p.Prep = PrepTechnique(buf[9])
		p.Identity = string(buf[10:])
	} else if pwType == PWDCommitExchange {
		// The Element is encoded according to Section 3.3.  The length of the
		// Element is inferred by the finite cyclic group from the agreed-upon
		// Ciphersuite.  The length of the scalar can then be computed from the
		// Length in the EAP header.
		p.CommitData = buf[1:]

	} else {
		panic(fmt.Sprintf("Unsupported PWD Type=%d", p.GetType()))
	}

	return p
}
func Encode(p *PWD) []byte {
	b := make([]byte, 1024)
	b[0] = p.LMPWD
	if p.IsLBitSet() || p.IsMBitSet() {
		panic("L+M bits unsupported")
	}
	binary.BigEndian.PutUint16(b[1:3], p.GroupDesc)
	b[3] = p.RandomFunc
	b[4] = p.PRF
	binary.BigEndian.PutUint32(b[5:9], p.Token)
	b[9] = uint8(p.Prep)
	copy(b[10:], []byte(p.Identity))

	return b[:len(p.Identity)+10]
}
