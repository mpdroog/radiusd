// radius commands
package main

import (
	"io"
	"radiusd/config"
	"radiusd/model"
	"radiusd/queue"
	"radiusd/radius"
	"net"
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
	pass := radius.DecryptPassword(raw, req)

	if config.Verbose {
		config.Log.Printf("auth user=%s pass=%s", user, pass)
	}
	limits, e := model.Auth(user, pass)
	if e != nil {
		config.Log.Printf("auth.begin e=" + e.Error())
		return
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
				VendorId: radius.MikrotikVendor,
				Values: []radius.VendorAttrString{radius.VendorAttrString{
					Type: radius.MikrotikRateLimit,
					Value: []byte(*limits.Ratelimit),
				}},
			}.Encode())
		}
		if limits.Adfilter {
			dns := config.C.DNS
			if len(dns) < 2 {
				config.Log.Printf("WARN: DNS in config.json missing 2 DNS-servers for adfilter!")
			} else {
				// MS-Primary-DNS-Server
				reply = append(reply, radius.VendorAttr{
					Type: radius.VendorSpecific,
					VendorId: radius.MicrosoftVendor,
					Values: []radius.VendorAttrString{radius.VendorAttrString{
						Type: radius.MSPrimaryDNSServer,
						Value: net.ParseIP(dns[0]).To4(),
					}},
				}.Encode())
				// MSSecondaryDNSServer
				reply = append(reply, radius.VendorAttr{
					Type: radius.VendorSpecific,
					VendorId: radius.MicrosoftVendor,
					Values: []radius.VendorAttrString{radius.VendorAttrString{
						Type: radius.MSSecondaryDNSServer,
						Value: net.ParseIP(dns[1]).To4(),
					}},
				}.Encode())
			}
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
	queue.Queue(sess.User, sess.BytesIn, sess.BytesOut)
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
	queue.Queue(user, octIn, octOut)
	if e := txn.Commit(); e != nil {
		config.Log.Printf("acct.update e=" + e.Error())
		return
	}

	w.Write(radius.DefaultPacket(req, radius.AccountingResponse, "Finished accounting."))
}
