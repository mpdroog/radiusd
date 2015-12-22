// radius commands
package main

import (
	"io"
	"radiusd/config"
	"radiusd/model"
	"radiusd/queue"
	"radiusd/radius"
	"radiusd/radius/mschapv1"
	"radiusd/radius/vendor"
	"net"
	"bytes"
)

func createSess(req *radius.Packet) model.Session {
	return model.Session{
		BytesIn: radius.DecodeFour(req.Attrs[radius.AcctInputOctets].Value),
		BytesOut: radius.DecodeFour(req.Attrs[radius.AcctOutputOctets].Value),
		PacketsIn: radius.DecodeFour(req.Attrs[radius.AcctInputPackets].Value),
		PacketsOut: radius.DecodeFour(req.Attrs[radius.AcctOutputPackets].Value),
		SessionID: string(req.Attrs[radius.AcctSessionId].Value),
		SessionTime: radius.DecodeFour(req.Attrs[radius.AcctSessionTime].Value),
		User: string(req.Attrs[radius.UserName].Value),
		NasIP: radius.DecodeIP(req.Attrs[radius.NASIPAddress].Value).String(),
	}
}

func auth(w io.Writer, req *radius.Packet) {
	if e := radius.ValidateAuthRequest(req); e != "" {
		config.Log.Printf("auth.begin e=%s", e)
		return
	}

	user := string(req.Attrs[radius.UserName].Value)
	raw := req.Attrs[radius.UserPassword].Value
	limits, e := model.Auth(user)
	if e != nil {
		config.Log.Printf("auth.begin e=" + e.Error())
		return
	}
	if limits.Pass == "" {
		w.Write(radius.DefaultPacket(req, radius.AccessReject, "No such user"))
		return
	}

	if _, isPass := req.Attrs[radius.UserPassword]; isPass {
		pass := radius.DecryptPassword(raw, req)
		if pass != limits.Pass {
			w.Write(radius.DefaultPacket(req, radius.AccessReject, "Invalid password"))
			return
		}
		if config.Verbose {
			config.Log.Printf("PAP login user=%s", user)
		}
	} else if _, isChap := req.Attrs[radius.CHAPPassword]; isChap {
		challenge := req.Attrs[radius.CHAPChallenge].Value
		hash := req.Attrs[radius.CHAPPassword].Value

		if !radius.CHAPMatch(limits.Pass, hash, challenge) {
			w.Write(radius.DefaultPacket(req, radius.AccessReject, "Invalid password"))
			return
		}
		if config.Verbose {
			config.Log.Printf("CHAP login user=%s", user)
		}
	} else {
		// Search for MSCHAP attrs
		attrs := make(map[vendor.AttributeType]radius.Attr)
		for _, attr := range req.AllAttrs {
			if radius.AttributeType(attr.Type) == radius.VendorSpecific {
				hdr := radius.VendorSpecificHeader(attr.Value)
				if hdr.VendorId == vendor.Microsoft {
					attrs[ vendor.AttributeType(hdr.VendorType) ] = attr
				}
			}
		}

		if len(attrs) > 0 && len(attrs) != 2 {
			w.Write(radius.DefaultPacket(req, radius.AccessReject, "MSCHAP: Missing attrs? MS-CHAP-Challenge/MS-CHAP-Response"))
			return
		} else if len(attrs) == 2 {
			// Collect our data
			challenge := mschapv1.DecodeChallenge(attrs[vendor.MSCHAPChallenge].Value).Value
			if _, isV1 := attrs[vendor.MSCHAPResponse]; isV1 {
				// MSCHAPv1
				res := mschapv1.DecodeResponse(attrs[vendor.MSCHAPResponse].Value)
				if res.Flags == 0 {
					// If it is zero, the NT-Response field MUST be ignored and
					// the LM-Response field used.
					w.Write(radius.DefaultPacket(req, radius.AccessReject, "MSCHAPv1: LM-Response not supported."))
					return
				}
				if bytes.Compare(res.LMResponse, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}) != 0 {
					w.Write(radius.DefaultPacket(req, radius.AccessReject, "MSCHAPv1: LM-Response set."))
					return
				}

				// Check for correctness
				calc, e := mschapv1.Encryptv1(challenge, limits.Pass)
				if e != nil {
					config.Log.Printf("MSCHAPv1: " + e.Error())
					w.Write(radius.DefaultPacket(req, radius.AccessReject, "MSCHAPv1: Server-side processing error"))
					return
				}

				if bytes.Compare(res.NTResponse, calc) != 0 {
					if config.Verbose {
						config.Log.Printf(
							"MSCHAPv1 user=%s mismatch expect=%x, received=%x",
							user, calc, res.NTResponse,
						)
					}
					w.Write(radius.DefaultPacket(req, radius.AccessReject, "Invalid password"))
					return
				}
				if config.Verbose {
					config.Log.Printf("MSCHAPv1 login user=%s", user)
				}

			} else if _, isV2 := attrs[vendor.MSCHAP2Response]; isV2 {
				// MSCHAPv2
				res := mschapv1.DecodeResponse2(attrs[vendor.MSCHAP2Response].Value)
				if res.Flags != 0 {
					w.Write(radius.DefaultPacket(req, radius.AccessReject, "MSCHAPv2: Flags should be set to 0"))
					return
				}
				calc, e := mschapv1.Encryptv2(challenge, res.PeerChallenge, user, limits.Pass)
				if e != nil {
					config.Log.Printf("MSCHAPv2: " + e.Error())
					w.Write(radius.DefaultPacket(req, radius.AccessReject, "MSCHAPv2: Server-side processing error"))
					return
				}
				if bytes.Compare(res.Response, calc) != 0 {
					if config.Verbose {
						config.Log.Printf(
							"MSCHAPv2 user=%s mismatch expect=%x, received=%x",
							user, calc, res.Response,
						)
					}
					w.Write(radius.DefaultPacket(req, radius.AccessReject, "Invalid password"))
					return
				}
				if config.Verbose {
					config.Log.Printf("MSCHAPv2 login user=%s", user)
				}

			} else {
				w.Write(radius.DefaultPacket(req, radius.AccessReject, "MSCHAP: Response1/2 not found"))
				return
			}
		}

	/*} else if _, maybeMSChap := req.Attrs[radius.VendorSpecific]; maybeMSChap {
		conf := radius.DecodeMSCHAPv1(req.Attrs[radius.VendorSpecific].Value)
		if conf.VendorId == radius.MicrosoftVendor {
			if conf.VendorType == 1 {
				// MSCHAPV1
				config.Log.Printf("CHAP raw=%+v", conf)
				if conf.Flags == 0 {
					// If it is zero, the NT-Response field MUST be ignored and
      				// the LM-Response field used.
      				w.Write(radius.DefaultPacket(req, radius.AccessReject, "MSCHAPv1: LM-Response not supported."))
					return
				}
			} else if conf.VendorType == 25 {
				// MSCHAPv2
				conf := radius.DecodeMSCHAPv2(req.Attrs[radius.VendorSpecific].Value)
				if conf.Flags != 0 {
					// The Flags field is one octet in length.  It is reserved for future
					// use and MUST be zero.
      				w.Write(radius.DefaultPacket(req, radius.AccessReject, "MSCHAPv2: Flags not 0 as expected."))
					return					
				}
			}

			//
		}

		config.Log.Printf("auth.begin Unsupported auth-type (not MS-CHAP as expected)")
		return

	} else {
		config.Log.Printf("auth.begin Unsupported auth-type (neither PAP/CHAP)")
		return*/
	}

	conns, e := model.Conns(user)
	if e != nil {
		config.Log.Printf("auth.begin e=" + e.Error())
		return
	}
	if conns >= limits.SimultaneousUse {
		w.Write(radius.DefaultPacket(req, radius.AccessReject, "Max conns reached"))
		return
	}

	if limits.Ok {
		reply := []radius.PubAttr{}
		if limits.DedicatedIP != nil {
			reply = append(reply, radius.PubAttr{
				Type: radius.FramedIPAddress,
				Value: net.ParseIP(*limits.DedicatedIP).To4(),
			})
		}
		if limits.Ratelimit != nil {
			// 	MT-Rate-Limit = MikrotikRateLimit
			reply = append(reply, radius.VendorAttr{
				Type: radius.VendorSpecific,
				VendorId: vendor.Mikrotik,
				Values: []radius.VendorAttrString{radius.VendorAttrString{
					Type: vendor.MikrotikRateLimit,
					Value: []byte(*limits.Ratelimit),
				}},
			}.Encode())
		}
		if limits.DnsOne != nil {
			// MS-Primary-DNS-Server
			// MS-Secondary-DNS-Server
			reply = append(reply, radius.VendorAttr{
				Type: radius.VendorSpecific,
				VendorId: vendor.Microsoft,
				Values: []radius.VendorAttrString{radius.VendorAttrString{
					Type: vendor.MSPrimaryDNSServer,
					Value: net.ParseIP(*limits.DnsOne).To4(),
				}, radius.VendorAttrString{
					Type: vendor.MSSecondaryDNSServer,
					Value: net.ParseIP(*limits.DnsTwo).To4(),
				}},
			}.Encode())
		}

		//reply = append(reply, radius.PubAttr{Type: radius.PortLimit, Value: radius.EncodeFour(limits.SimultaneousUse-conns)})
		w.Write(req.Response(radius.AccessAccept, reply))
		return
	}

	w.Write(radius.DefaultPacket(req, radius.AccessReject, "Invalid user/pass"))
}

func acctBegin(w io.Writer, req *radius.Packet) {
	if e := radius.ValidateAcctRequest(req); e != "" {
		config.Log.Printf("WARN: acct.begin err=" + e)
		return
	}
	if _, there := req.Attrs[radius.FramedIPAddress]; !there {
		config.Log.Printf("WARN: acct.begin missing FramedIPAddress")
		return
	}

	user := string(req.Attrs[radius.UserName].Value)
	sess := string(req.Attrs[radius.AcctSessionId].Value)
	nasIp := radius.DecodeIP(req.Attrs[radius.NASIPAddress].Value).String()
	clientIp := string(req.Attrs[radius.CallingStationId].Value)
	assignedIp := radius.DecodeIP(req.Attrs[radius.FramedIPAddress].Value).String()

	if config.Verbose {
		config.Log.Printf("acct.begin sess=%s for user=%s on nasIP=%s", sess, user, nasIp)
	}
	reply := []radius.PubAttr{}
	_, e := model.Limits(user)
	if e != nil {
		if e == model.ErrNoRows {
			config.Log.Printf("acct.begin received invalid user=" + user)
			return
		}
		config.Log.Printf("acct.begin e=" + e.Error())
		return
	}

	if e := model.SessionAdd(sess, user, nasIp, assignedIp, clientIp); e != nil {
		config.Log.Printf("acct.begin e=%s", e.Error())
		return
	}
	w.Write(req.Response(radius.AccountingResponse, reply))
}

func acctUpdate(w io.Writer, req *radius.Packet) {
	if e := radius.ValidateAcctRequest(req); e != "" {
		config.Log.Printf("acct.update e=" + e)
		return
	}

	sess := createSess(req)
	if config.Verbose {
		config.Log.Printf(
			"acct.update sess=%s for user=%s on NasIP=%s sessTime=%d octetsIn=%d octetsOut=%d",
			sess.SessionID, sess.User, sess.NasIP, sess.SessionTime, sess.BytesIn, sess.BytesOut,
		)
	}
	txn, e := model.Begin()
	if e != nil {
		config.Log.Printf("acct.update e=" + e.Error())
		return
	}
	if e := model.SessionUpdate(txn, sess); e != nil {
		config.Log.Printf("acct.update e=" + e.Error())
		return
	}
	queue.Queue(sess.User, sess.BytesIn, sess.BytesOut, sess.PacketsIn, sess.PacketsOut)
	if e := txn.Commit(); e != nil {
		config.Log.Printf("acct.update e=" + e.Error())
		return
	}
	w.Write(radius.DefaultPacket(req, radius.AccountingResponse, "Updated accounting."))
}

func acctStop(w io.Writer, req *radius.Packet) {
	if e := radius.ValidateAcctRequest(req); e != "" {
		config.Log.Printf("acct.stop e=" + e)
		return
	}
	user := string(req.Attrs[radius.UserName].Value)
	sess := string(req.Attrs[radius.AcctSessionId].Value)
	nasIp := radius.DecodeIP(req.Attrs[radius.NASIPAddress].Value).String()

	sessTime := radius.DecodeFour(req.Attrs[radius.AcctSessionTime].Value)
	octIn := radius.DecodeFour(req.Attrs[radius.AcctInputOctets].Value)
	octOut := radius.DecodeFour(req.Attrs[radius.AcctOutputOctets].Value)

	packIn := radius.DecodeFour(req.Attrs[radius.AcctInputPackets].Value)
	packOut := radius.DecodeFour(req.Attrs[radius.AcctOutputPackets].Value)

	if config.Verbose {
		config.Log.Printf(
			"acct.stop sess=%s for user=%s sessTime=%d octetsIn=%d octetsOut=%d",
			sess, user, sessTime, octIn, octOut,
		)
	}

	txn, e := model.Begin()
	if e != nil {
		config.Log.Printf("acct.update e=" + e.Error())
		return
	}
	sessModel := createSess(req)
	if e := model.SessionUpdate(txn, sessModel); e != nil {
		config.Log.Printf("acct.update e=" + e.Error())
		return
	}
	if e := model.SessionLog(txn, sess, user, nasIp); e != nil {
		config.Log.Printf("acct.update e=" + e.Error())
		return
	}
	if e := model.SessionRemove(txn, sess, user, nasIp); e != nil {
		config.Log.Printf("acct.update e=" + e.Error())
		return
	}
	queue.Queue(user, octIn, octOut, packIn, packOut)
	if e := txn.Commit(); e != nil {
		config.Log.Printf("acct.update e=" + e.Error())
		return
	}

	w.Write(radius.DefaultPacket(req, radius.AccountingResponse, "Finished accounting."))
}
