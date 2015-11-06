// radius commands
package main

import (
	"io"
	"radiusd/config"
	"radiusd/model"
	"radiusd/queue"
	"radiusd/radius"
)

func auth(w io.Writer, req *radius.Packet) {
	if e := radius.ValidateAuthRequest(req); e != "" {
		if config.Verbose {
			config.Log.Printf("auth.begin err=" + e)
		}
		w.Write(radius.DefaultPacket(req, radius.AccessReject, e))
		return
	}

	user := string(req.Attrs[radius.UserName].Value)
	raw := req.Attrs[radius.UserPassword].Value
	pass := radius.DecryptPassword(raw, req)

	if config.Verbose {
		config.Log.Printf("auth user=%s pass=%s", user, pass)
	}
	state, e := model.Auth(user, pass)
	if e != nil {
		config.Log.Printf("auth.begin err=" + e.Error())
		w.Write(radius.DefaultPacket(req, radius.AccessReject, "Database error"))
		return
	}

	if state.Ok {
		w.Write(radius.DefaultPacket(req, radius.AccessAccept, "Ok."))
		return
	}

	w.Write(radius.DefaultPacket(req, radius.AccessReject, "Invalid user/pass"))
}

func acctBegin(w io.Writer, req *radius.Packet) {
	if e := radius.ValidateAcctRequest(req); e != "" {
		if config.Verbose {
			config.Log.Printf("acct.begin err=" + e)
		}
		w.Write(radius.DefaultPacket(req, radius.AccountingResponse, e))
		return
	}
	user := string(req.Attrs[radius.UserName].Value)
	sess := string(req.Attrs[radius.AcctSessionId].Value)
	nasIp := radius.DecodeIP(req.Attrs[radius.NASIPAddress].Value).String()

	if config.Verbose {
		config.Log.Printf("acct.begin sess=%s for user=%s", sess, user)
	}
	if e := model.SessionAdd(sess, user, nasIp, config.Hostname); e != nil {
		config.Log.Printf("acct.begin err=%s", e.Error())
		w.Write(radius.DefaultPacket(req, radius.AccountingResponse, "Database error"))
	}
	w.Write(radius.DefaultPacket(req, radius.AccountingResponse, "Session begin"))
}

func acctUpdate(w io.Writer, req *radius.Packet) {
	if e := radius.ValidateAcctRequest(req); e != "" {
		if config.Verbose {
			config.Log.Printf("acct.update err=" + e)
		}
		w.Write(radius.DefaultPacket(req, radius.AccountingResponse, e))
		return
	}
	user := string(req.Attrs[radius.UserName].Value)
	sess := string(req.Attrs[radius.AcctSessionId].Value)

	sessTime := radius.DecodeFour(req.Attrs[radius.AcctSessionTime].Value)
	octIn := radius.DecodeFour(req.Attrs[radius.AcctInputOctets].Value)
	octOut := radius.DecodeFour(req.Attrs[radius.AcctOutputOctets].Value)

	if config.Verbose {
		config.Log.Printf(
			"acct.update sess=%s for user=%s sessTime=%d octetsIn=%d octetsOut=%d",
			sess, user, sessTime, octIn, octOut,
		)
	}
	queue.Queue(user, octIn, octOut)
	w.Write(radius.DefaultPacket(req, radius.AccountingResponse, "Updated accounting."))
}

func acctStop(w io.Writer, req *radius.Packet) {
	if e := radius.ValidateAcctRequest(req); e != "" {
		if config.Verbose {
			config.Log.Printf("acct.stop err=" + e)
		}
		w.Write(radius.DefaultPacket(req, radius.AccountingResponse, e))
		return
	}
	user := string(req.Attrs[radius.UserName].Value)
	sess := string(req.Attrs[radius.AcctSessionId].Value)

	sessTime := radius.DecodeFour(req.Attrs[radius.AcctSessionTime].Value)
	octIn := radius.DecodeFour(req.Attrs[radius.AcctInputOctets].Value)
	octOut := radius.DecodeFour(req.Attrs[radius.AcctOutputOctets].Value)

	if config.Verbose {
		config.Log.Printf(
			"acct.stop sess=%s for user=%s sessTime=%d octetsIn=%d octetsOut=%d",
			sess, user, sessTime, octIn, octOut,
		)
	}
	queue.Queue(user, octIn, octOut)
	if e := model.SessionRemove(sess); e != nil {
		w.Write(radius.DefaultPacket(req, radius.AccountingResponse, e.Error()))
	}
	w.Write(radius.DefaultPacket(req, radius.AccountingResponse, "Finished accounting."))
}
