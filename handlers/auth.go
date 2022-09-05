package handlers

import (
	"bytes"
	"io"
	"net"
	"time"

	"github.com/mpdroog/radiusd/model"
	"github.com/mpdroog/radiusd/radius"
	"github.com/mpdroog/radiusd/radius/eap"
	"github.com/mpdroog/radiusd/radius/eap/pwd"
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

		// Although EAP provides an Identity method to determine the identity of
		// the peer, the value in the Identity Response may have been truncated
		// or obfuscated to provide privacy or decorated for routing purposes
		// [RFC3748], making it inappropriate for usage by the EAP-pwd method.
		// https://datatracker.ietf.org/doc/html/rfc5931#section-2.8.5.1
		if p.MsgType == eap.Identity {
			// TODO: eap logic:
			// State (radius) + Id (eap, where id keeps +1 on every reply)
			// also store remote id to check we miss nothing?
			stateID, e := GenRand(16)
			if e != nil {
				h.Logger.Printf("auth.genRand(16) e=" + e.Error())
				return
			}
			if _, used := h.State[string(stateID)]; used {
				panic("DevErr: stateID already used")
			}
			stateToken := randToken()

			// Instruct we want EAP-PWD-ID
			eapBin, e := eap.Encode(&eap.EAPPacket{
				Code:    eap.EAPRequest,
				ID:      240,
				MsgType: eap.EAPpwd,
				Data: pwd.Encode(&pwd.PWD{
					LMPWD:      pwd.DefaultLMPWD,
					GroupDesc:  19,
					RandomFunc: pwd.DefaultRandomFunc,
					PRF:        pwd.PRFHMACSHA256,
					Token:      stateToken,
					Prep:       pwd.PrepNone,
					Identity:   "radius@rootdev.nl", // todo: config?
				}),
			}, h.Verbose, h.Logger)
			if e != nil {
				h.Logger.Printf("auth.begin(eapEncode) e=" + e.Error())
				return
			}

			// Add current MessageAuthenticator (so we get right amount of bytes in memory, they are nullified automatically)
			curAuth := req.Attr(radius.MessageAuthenticator)
			reply = append(reply,
				radius.NewAttr(radius.EAPMessage, eapBin, uint8(2+len(eapBin))),
				radius.NewAttr(radius.MessageAuthenticator, curAuth, uint8(2+len(curAuth))),
				radius.NewAttr(radius.State, stateID, uint8(2+16)),
			)
			w.Write(req.Response(radius.AccessChallenge, reply, h.Verbose, h.Logger))
			h.State[string(stateID)] = State{
				LastID:   240,
				Token:    stateToken,
				Added:    time.Now(),
				RemoteID: p.ID,
			}
			return
		}
		if p.MsgType == eap.EAPpwd {
			// EAP-PWD
			stateID := string(req.Attr(radius.State))
			state, ok := h.State[stateID]
			if !ok {
				h.Logger.Printf("auth.begin(getState) nothing found")
				return
			}

			user := p.PWD.Identity
			limits, e := model.Auth(h.Storage, user)
			if e != nil {
				h.Logger.Printf("auth.begin e=" + e.Error())
				return
			}
			if limits.Pass == "" {
				eapBin, e := eap.Encode(&eap.EAPPacket{
					Code: eap.EAPFailure,
					ID:   state.LastID + 1,
				}, h.Verbose, h.Logger)
				if e != nil {
					h.Logger.Printf("auth.begin(eapEncode) e=" + e.Error())
					return
				}
				curAuth := req.Attr(radius.MessageAuthenticator)
				reply = append(reply,
					radius.NewAttr(radius.EAPMessage, eapBin, uint8(2+len(eapBin))),
					radius.NewAttr(radius.MessageAuthenticator, curAuth, uint8(2+len(curAuth))),
					radius.NewAttr(radius.State, req.Attr(radius.State), 18),
				)

				w.Write(req.Response(radius.AccessReject, reply, h.Verbose, h.Logger))
				// TODO: Save state in map again?
				state.LastID++
				h.State[string(stateID)] = state
				return
			}

			//panic("N")
			// I guess we can add compute_password_element+compute_scalar_element
			ecState, e := pwd.PassElement(pwd.State{
				Token:    2, // todo: whats up with this?
				IDPeer:   "client",
				IDServer: "radius.rootdev.nl",
				Password: "minimum",
			})
			// TODO: Really sure N==order from C?
			myElement, myScalar, e := pwd.Compute_scalar_element(ecState.Order, ecState.X, ecState.Order)
			if e != nil {
				h.Logger.Printf("auth.begin(Compute_scalar_element) e=" + e.Error())
				return
			}

			data := new(bytes.Buffer)
			if _, e := data.Write(myElement); e != nil {
				h.Logger.Printf("auth.begin(data.Write1) e=" + e.Error())
				return
			}
			if _, e := data.Write(myScalar); e != nil {
				h.Logger.Printf("auth.begin(data.Write2) e=" + e.Error())
				return
			}

			eapBin, e := eap.Encode(&eap.EAPPacket{
				Code: eap.EAPRequest,
				ID:   state.LastID + 1,
				Data: data.Bytes(),
			}, h.Verbose, h.Logger)
			if e != nil {
				h.Logger.Printf("auth.begin(eapEncode) e=" + e.Error())
				return
			}
			curAuth := req.Attr(radius.MessageAuthenticator)
			reply = append(reply,
				radius.NewAttr(radius.EAPMessage, eapBin, uint8(2+len(eapBin))),
				radius.NewAttr(radius.MessageAuthenticator, curAuth, uint8(2+len(curAuth))),
				radius.NewAttr(radius.State, req.Attr(radius.State), 18),
			)

			if _, e := w.Write(req.Response(radius.AccessChallenge, reply, h.Verbose, h.Logger)); e != nil {
				h.Logger.Printf("auth.begin(Write-end) e=" + e.Error())
				return
			}
			state.LastID++
			h.State[string(stateID)] = state
			return
		}

		panic("Unsupported state?")
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
