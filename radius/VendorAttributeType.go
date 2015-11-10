package radius

import (
	"encoding/binary"
)

type VendorAttributeType uint8

// 	Mikrotik
const (
	// http://wiki.mikrotik.com/wiki/Manual:RADIUS_Client/vendor_dictionary
	_                                                     = iota //drop the zero
	MikrotikRecvLimit               VendorAttributeType = iota //1
	MikrotikXmitLimit               VendorAttributeType = iota //2
	MikrotikGroup                   VendorAttributeType = iota //3
	MikrotikWirelessForward         VendorAttributeType = iota //4
	MikrotikWirelessSkipDot1x       VendorAttributeType = iota //5
	MikrotikWirelessEncAlgo         VendorAttributeType = iota //6
	MikrotikWirelessEncKey          VendorAttributeType = iota //7
	MikrotikRateLimit               VendorAttributeType = iota //8
	MikrotikRealm                   VendorAttributeType = iota //9
	MikrotikHostIP                  VendorAttributeType = iota //10
	MikrotikMarkId                  VendorAttributeType = iota //11
	MikrotikAdvertiseURL            VendorAttributeType = iota //12
	MikrotikAdvertiseInterval       VendorAttributeType = iota //13
	MikrotikRecvLimitGigawords      VendorAttributeType = iota //14
	MikrotikXmitLimitGigawords      VendorAttributeType = iota //15
	MikrotikWirelessPSK             VendorAttributeType = iota //16
	MikrotikTotalLimit              VendorAttributeType = iota //17
	MikrotikTotalLimitGigawords     VendorAttributeType = iota //18
	MikrotikAddressList             VendorAttributeType = iota //19
	MikrotikWirelessMPKey           VendorAttributeType = iota //20
	MikrotikWirelessComment         VendorAttributeType = iota //21
	MikrotikDelegatedIPv6Pool       VendorAttributeType = iota //22
	Mikrotik_DHCP_Option_Set        VendorAttributeType = iota //23
	Mikrotik_DHCP_Option_Param_STR1 VendorAttributeType = iota //24
	Mikortik_DHCP_Option_Param_STR2 VendorAttributeType = iota //25
	Mikrotik_Wireless_VLANID        VendorAttributeType = iota //26
	Mikrotik_Wireless_VLANIDtype    VendorAttributeType = iota //27
	Mikrotik_Wireless_Minsignal     VendorAttributeType = iota //28
	Mikrotik_Wireless_Maxsignal     VendorAttributeType = iota //29

	MikrotikVendor uint32 = 14988
)

// Microsoft
const (
	MSPrimaryDNSServer VendorAttributeType = 28
	MSSecondaryDNSServer VendorAttributeType = 29

	MicrosoftVendor uint32 = 311
)

type VendorAttrString struct {
	Type VendorAttributeType
	Value []byte	
}

type VendorAttr struct {
	Type AttributeType
	VendorId uint32
	Values []VendorAttrString
}

// Convert VendorAttr to generic Attr
func (t VendorAttr) Encode() PubAttr {
	val := make([]byte, 4)
	binary.BigEndian.PutUint32(val, t.VendorId)

	//sum := 0
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