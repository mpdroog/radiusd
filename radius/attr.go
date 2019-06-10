package radius

import (
	"fmt"
)

type AttrEncoder interface {
	Encode() []byte
	Type() AttributeType
	Bytes() []byte
	Length() uint8
	String() string
}

type Attr struct {
	attrType AttributeType
	length   uint8
	bytes    []byte
}

func (a Attr) Encode() []byte {
	panic("TODO")
}
func (a Attr) Type() AttributeType {
	return a.attrType
}
func (a Attr) Bytes() []byte {
	return a.bytes
}
func (a Attr) Length() uint8 {
	if a.length == 0 {
		// Calc if not set
		return uint8(2 + len(a.Bytes()))
	}
	return a.length
}
func (a Attr) String() string {
	// TODO: More verbosely print bytes?
	return fmt.Sprintf("{Type=%s bytes=%+v}", a.Type().String(), a.bytes)
}

func NewAttr(attrType AttributeType, bytes []byte, length uint8) AttrEncoder {
	return Attr{
		attrType: attrType,
		length:   length,
		bytes:    bytes,
	}
}
