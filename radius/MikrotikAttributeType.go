package radius

type MikrotikAttributeType uint8

// 	MikrotikVendor	int	= 14988
const (
	// http://wiki.mikrotik.com/wiki/Manual:RADIUS_Client/vendor_dictionary
	_                                                     = iota //drop the zero
	MikrotikRecvLimit               MikrotikAttributeType = iota //1
	MikrotikXmitLimit               MikrotikAttributeType = iota //2
	MikrotikGroup                   MikrotikAttributeType = iota //3
	MikrotikWirelessForward         MikrotikAttributeType = iota //4
	MikrotikWirelessSkipDot1x       MikrotikAttributeType = iota //5
	MikrotikWirelessEncAlgo         MikrotikAttributeType = iota //6
	MikrotikWirelessEncKey          MikrotikAttributeType = iota //7
	MikrotikRateLimit               MikrotikAttributeType = iota //8
	MikrotikRealm                   MikrotikAttributeType = iota //9
	MikrotikHostIP                  MikrotikAttributeType = iota //10
	MikrotikMarkId                  MikrotikAttributeType = iota //11
	MikrotikAdvertiseURL            MikrotikAttributeType = iota //12
	MikrotikAdvertiseInterval       MikrotikAttributeType = iota //13
	MikrotikRecvLimitGigawords      MikrotikAttributeType = iota //14
	MikrotikXmitLimitGigawords      MikrotikAttributeType = iota //15
	MikrotikWirelessPSK             MikrotikAttributeType = iota //16
	MikrotikTotalLimit              MikrotikAttributeType = iota //17
	MikrotikTotalLimitGigawords     MikrotikAttributeType = iota //18
	MikrotikAddressList             MikrotikAttributeType = iota //19
	MikrotikWirelessMPKey           MikrotikAttributeType = iota //20
	MikrotikWirelessComment         MikrotikAttributeType = iota //21
	MikrotikDelegatedIPv6Pool       MikrotikAttributeType = iota //22
	Mikrotik_DHCP_Option_Set        MikrotikAttributeType = iota //23
	Mikrotik_DHCP_Option_Param_STR1 MikrotikAttributeType = iota //24
	Mikortik_DHCP_Option_Param_STR2 MikrotikAttributeType = iota //25
	Mikrotik_Wireless_VLANID        MikrotikAttributeType = iota //26
	Mikrotik_Wireless_VLANIDtype    MikrotikAttributeType = iota //27
	Mikrotik_Wireless_Minsignal     MikrotikAttributeType = iota //28
	Mikrotik_Wireless_Maxsignal     MikrotikAttributeType = iota //29

	MikrotikVendor uint32 = 14988
)
