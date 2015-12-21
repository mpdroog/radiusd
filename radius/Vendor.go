package radius

import (
	"radiusd/radius/vendor"
	"encoding/binary"
)

type VendorAttrString struct {
	Type vendor.AttributeType
	Value []byte
}

type VendorAttr struct {
	Type AttributeType
	VendorId uint32
	Values []VendorAttrString
}

type VendorHeader struct {
	VendorId uint32
	VendorType uint8
}

// Convert VendorAttr to generic Attr
func (t VendorAttr) Encode() PubAttr {
	val := make([]byte, 4)
	binary.BigEndian.PutUint32(val, t.VendorId)

	// Parse Values
	for _, value := range t.Values {
		raw := []byte(value.Value)

		b := make([]byte, 2+len(raw))
		b[0] = uint8(value.Type) // vendor type
		b[1] = uint8(2+len(raw)) // vendor length
		copy(b[2:], raw)
		//sum += 2+len(raw)
		val = append(val, b...)
	}

	return PubAttr{
		Type: t.Type,
		Value: val,
	}
}

func VendorSpecificHeader(b []byte) VendorHeader {
	return VendorHeader{
		VendorId: binary.BigEndian.Uint32(b[0:4]),
		VendorType: b[4],
	}
}