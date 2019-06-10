package vendor

const (
	_                                             = iota //drop the zero
	MikrotikRecvLimit               AttributeType = iota //1
	MikrotikXmitLimit               AttributeType = iota //2
	MikrotikGroup                   AttributeType = iota //3
	MikrotikWirelessForward         AttributeType = iota //4
	MikrotikWirelessSkipDot1x       AttributeType = iota //5
	MikrotikWirelessEncAlgo         AttributeType = iota //6
	MikrotikWirelessEncKey          AttributeType = iota //7
	MikrotikRateLimit               AttributeType = iota //8
	MikrotikRealm                   AttributeType = iota //9
	MikrotikHostIP                  AttributeType = iota //10
	MikrotikMarkId                  AttributeType = iota //11
	MikrotikAdvertiseURL            AttributeType = iota //12
	MikrotikAdvertiseInterval       AttributeType = iota //13
	MikrotikRecvLimitGigawords      AttributeType = iota //14
	MikrotikXmitLimitGigawords      AttributeType = iota //15
	MikrotikWirelessPSK             AttributeType = iota //16
	MikrotikTotalLimit              AttributeType = iota //17
	MikrotikTotalLimitGigawords     AttributeType = iota //18
	MikrotikAddressList             AttributeType = iota //19
	MikrotikWirelessMPKey           AttributeType = iota //20
	MikrotikWirelessComment         AttributeType = iota //21
	MikrotikDelegatedIPv6Pool       AttributeType = iota //22
	Mikrotik_DHCP_Option_Set        AttributeType = iota //23
	Mikrotik_DHCP_Option_Param_STR1 AttributeType = iota //24
	Mikortik_DHCP_Option_Param_STR2 AttributeType = iota //25
	Mikrotik_Wireless_VLANID        AttributeType = iota //26
	Mikrotik_Wireless_VLANIDtype    AttributeType = iota //27
	Mikrotik_Wireless_Minsignal     AttributeType = iota //28
	Mikrotik_Wireless_Maxsignal     AttributeType = iota //29

	Mikrotik uint32 = 14988
)
