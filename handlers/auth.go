package handlers

import (
	"bytes"
	"io"
	"net"

	"github.com/mpdroog/radiusd/model"
	"github.com/mpdroog/radiusd/radius"
	"github.com/mpdroog/radiusd/radius/eap"
	"github.com/mpdroog/radiusd/radius/mschap"
	"github.com/mpdroog/radiusd/radius/vendor"
)

func (h *Handler) Auth(w io.Writer, req *radius.Packet) {
	if e := radius.ValidateAuthRequest(req); e != "" {
		h.Logger.Printf("auth.begin e=%s", e)
		return
	}
	reply := []radius.AttrEncoder{}

	if req.HasAttr(radius.EAPMessage) {
		// EAP-decode
		p, e := eap.Decode(req.Attr(radius.EAPMessage))
		if e != nil {
			h.Logger.Printf("auth.eapDecode e=" + e.Error())
			return
		}
		h.Logger.Printf("EAPPacket=%+v", p)

		user := p.PayloadIdentity
		limits, e := model.Auth(h.Storage, user)
		if e != nil {
			h.Logger.Printf("auth.begin e=" + e.Error())
			return
		}
		if limits.Pass == "" {
			w.Write(radius.DefaultPacket(req, radius.AccessReject, "No such user", h.Verbose, h.Logger))
			return
		}

		// Add current MessageAuthenticator
		curAuth := req.Attr(radius.MessageAuthenticator)
		curMsg := req.Attr(radius.EAPMessage)
		reply = append(reply,
			radius.NewAttr(radius.EAPMessage, curMsg, uint8(2+len(curMsg))),
			radius.NewAttr(radius.MessageAuthenticator, curAuth, uint8(2+len(curAuth)),
		))

		w.Write(req.Response(radius.AccessChallenge, reply, h.Verbose, h.Logger))
		return
	}

	user := string(req.Attr(radius.UserName))
	limits, e := model.Auth(h.Storage, user)
	if e != nil {
		h.Logger.Printf("auth.begin e=" + e.Error())
		return
	}
	if limits.Pass == "" {
		w.Write(radius.DefaultPacket(req, radius.AccessReject, "No such user", h.Verbose, h.Logger))
		return
	}

	if req.HasAttr(radius.UserPassword) {
		pass := radius.DecryptPassword(req.Attr(radius.UserPassword), req)
		if pass != limits.Pass {
			w.Write(radius.DefaultPacket(req, radius.AccessReject, "Invalid password", h.Verbose, h.Logger))
			return
		}
		if h.Verbose {
			h.Logger.Printf("PAP login user=%s", user)
		}
	} else if req.HasAttr(radius.CHAPPassword) {
		challenge := req.Attr(radius.CHAPChallenge)
		hash := req.Attr(radius.CHAPPassword)

		// TODO: No challenge then use Request Authenticator

		if !radius.CHAPMatch(limits.Pass, hash, challenge) {
			w.Write(radius.DefaultPacket(req, radius.AccessReject, "Invalid password", h.Verbose, h.Logger))
			return
		}
		if h.Verbose {
			h.Logger.Printf("CHAP login user=%s", user)
		}
	} else {
		// Search for MSCHAP attrs
		attrs := make(map[vendor.AttributeType]radius.AttrEncoder)
		for _, attr := range req.Attrs {
			if radius.AttributeType(attr.Type()) == radius.VendorSpecific {
				hdr := radius.VendorSpecificHeader(attr.Bytes())
				if hdr.VendorId == vendor.Microsoft {
					attrs[vendor.AttributeType(hdr.VendorType)] = attr
				}
			}
		}

		if len(attrs) > 0 && len(attrs) != 2 {
			w.Write(radius.DefaultPacket(req, radius.AccessReject, "MSCHAP: Missing attrs? MS-CHAP-Challenge/MS-CHAP-Response", h.Verbose, h.Logger))
			return
		} else if len(attrs) == 2 {
			// Collect our data
			challenge := mschap.DecodeChallenge(attrs[vendor.MSCHAPChallenge].Bytes()).Value
			if _, isV1 := attrs[vendor.MSCHAPResponse]; isV1 {
				// MSCHAPv1
				res := mschap.DecodeResponse(attrs[vendor.MSCHAPResponse].Bytes())
				if res.Flags == 0 {
					// If it is zero, the NT-Response field MUST be ignored and
					// the LM-Response field used.
					w.Write(radius.DefaultPacket(req, radius.AccessReject, "MSCHAPv1: LM-Response not supported.", h.Verbose, h.Logger))
					return
				}
				if bytes.Compare(res.LMResponse, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}) != 0 {
					w.Write(radius.DefaultPacket(req, radius.AccessReject, "MSCHAPv1: LM-Response set.", h.Verbose, h.Logger))
					return
				}

				// Check for correctness
				calc, e := mschap.Encryptv1(challenge, limits.Pass)
				if e != nil {
					h.Logger.Printf("MSCHAPv1: " + e.Error())
					w.Write(radius.DefaultPacket(req, radius.AccessReject, "MSCHAPv1: Server-side processing error", h.Verbose, h.Logger))
					return
				}
				mppe, e := mschap.Mppev1(limits.Pass)
				if e != nil {
					h.Logger.Printf("MPPEv1: " + e.Error())
					w.Write(radius.DefaultPacket(req, radius.AccessReject, "MPPEv1: Server-side processing error", h.Verbose, h.Logger))
					return
				}

				if bytes.Compare(res.NTResponse, calc) != 0 {
					if h.Verbose {
						h.Logger.Printf(
							"MSCHAPv1 user=%s mismatch expect=%x, received=%x",
							user, calc, res.NTResponse,
						)
					}
					w.Write(radius.DefaultPacket(req, radius.AccessReject, "Invalid password", h.Verbose, h.Logger))
					return
				}
				if h.Verbose {
					h.Logger.Printf("MSCHAPv1 login user=%s", user)
				}

				reply = append(reply, radius.VendorAttr{
					Type:     radius.VendorSpecific,
					VendorId: vendor.Microsoft,
					/* 1 Encryption-Allowed, 2 Encryption-Required */
					Values: []radius.VendorAttrString{
						radius.VendorAttrString{
							Type:  vendor.MSMPPEEncryptionPolicy,
							Value: []byte{0x0, 0x0, 0x0, 0x01},
						},
						/* encryption types, allow RC4[40/128bit] */
						radius.VendorAttrString{
							Type:  vendor.MSMPPEEncryptionTypes,
							Value: []byte{0x0, 0x0, 0x0, 0x06},
						},
						/* mppe - encryption negotation key */
						radius.VendorAttrString{
							Type:  vendor.MSCHAPMPPEKeys,
							Value: mppe,
						},
					},
				}.Encode())

			} else if _, isV2 := attrs[vendor.MSCHAP2Response]; isV2 {
				// MSCHAPv2
				res := mschap.DecodeResponse2(attrs[vendor.MSCHAP2Response].Bytes())
				if res.Flags != 0 {
					w.Write(radius.DefaultPacket(req, radius.AccessReject, "MSCHAPv2: Flags should be set to 0", h.Verbose, h.Logger))
					return
				}
				enc, e := mschap.Encryptv2(challenge, res.PeerChallenge, user, limits.Pass)
				if e != nil {
					h.Logger.Printf("MSCHAPv2: " + e.Error())
					w.Write(radius.DefaultPacket(req, radius.AccessReject, "MSCHAPv2: Server-side processing error", h.Verbose, h.Logger))
					return
				}
				send, recv := mschap.Mmpev2(req.Secret(), limits.Pass, req.Auth, res.Response)

				if bytes.Compare(res.Response, enc.ChallengeResponse) != 0 {
					if h.Verbose {
						h.Logger.Printf(
							"MSCHAPv2 user=%s mismatch expect=%x, received=%x",
							user, enc.ChallengeResponse, res.Response,
						)
					}
					w.Write(radius.DefaultPacket(req, radius.AccessReject, "Invalid password", h.Verbose, h.Logger))
					return
				}
				if h.Verbose {
					h.Logger.Printf("MSCHAPv2 login user=%s", user)
				}
				// TODO: Framed-Protocol = PPP, Framed-Compression = Van-Jacobson-TCP-IP
				reply = append(reply, radius.VendorAttr{
					Type:     radius.VendorSpecific,
					VendorId: vendor.Microsoft,
					Values: []radius.VendorAttrString{
						/* 1 Encryption-Allowed, 2 Encryption-Required */
						radius.VendorAttrString{
							Type:  vendor.MSMPPEEncryptionPolicy,
							Value: []byte{0x0, 0x0, 0x0, 0x01},
						},
						/* encryption types, allow RC4[40/128bit] */
						radius.VendorAttrString{
							Type:  vendor.MSMPPEEncryptionTypes,
							Value: []byte{0x0, 0x0, 0x0, 0x06},
						},
						/* success challenge */
						radius.VendorAttrString{
							Type:  vendor.MSCHAP2Success,
							Value: append([]byte{byte(res.Ident)}, []byte(enc.AuthenticatorResponse)...),
						},
						/* Send-Key */
						radius.VendorAttrString{
							Type:  vendor.MSMPPESendKey,
							Value: send,
						},
						/* Recv-Key */
						radius.VendorAttrString{
							Type:  vendor.MSMPPERecvKey,
							Value: recv,
						},
					},
				}.Encode())

			} else {
				w.Write(radius.DefaultPacket(req, radius.AccessReject, "MSCHAP: Response1/2 not found", h.Verbose, h.Logger))
				return
			}
		}
	}

	conns, e := model.Conns(h.Storage, user)
	if e != nil {
		h.Logger.Printf("auth.begin e=" + e.Error())
		return
	}
	if conns >= limits.SimultaneousUse {
		w.Write(radius.DefaultPacket(req, radius.AccessReject, "Max conns reached", h.Verbose, h.Logger))
		return
	}

	if limits.Ok {
		if limits.DedicatedIP != nil {
			reply = append(reply, radius.NewAttr(
				radius.FramedIPAddress,
				net.ParseIP(*limits.DedicatedIP).To4(),
				0,
			))
		}
		if limits.Ratelimit != nil {
			// 	MT-Rate-Limit = MikrotikRateLimit
			reply = append(reply, radius.VendorAttr{
				Type:     radius.VendorSpecific,
				VendorId: vendor.Mikrotik,
				Values: []radius.VendorAttrString{radius.VendorAttrString{
					Type:  vendor.MikrotikRateLimit,
					Value: []byte(*limits.Ratelimit),
				}},
			}.Encode())
		}
		if limits.DnsOne != nil {
			// MS-Primary-DNS-Server
			// MS-Secondary-DNS-Server
			reply = append(reply, radius.VendorAttr{
				Type:     radius.VendorSpecific,
				VendorId: vendor.Microsoft,
				Values: []radius.VendorAttrString{radius.VendorAttrString{
					Type:  vendor.MSPrimaryDNSServer,
					Value: net.ParseIP(*limits.DnsOne).To4(),
				}, radius.VendorAttrString{
					Type:  vendor.MSSecondaryDNSServer,
					Value: net.ParseIP(*limits.DnsTwo).To4(),
				}},
			}.Encode())
		}

		//reply = append(reply, radius.PubAttr{Type: radius.PortLimit, Value: radius.EncodeFour(limits.SimultaneousUse-conns)})
		w.Write(req.Response(radius.AccessAccept, reply, h.Verbose, h.Logger))
		return
	}

	w.Write(radius.DefaultPacket(req, radius.AccessReject, "Invalid user/pass", h.Verbose, h.Logger))
}
