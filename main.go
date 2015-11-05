package main

import (
	"fmt"
	"io"
	"radiusd/radius"
)

func auth(w io.Writer, req *radius.Packet) {
	err := radius.ValidateAuthRequest(req)
	if err != "" {
		fmt.Println("auth.begin err=" + err)
		w.Write(req.Response(
			radius.AccessReject, []radius.PubAttr{
				radius.PubAttr{Type: radius.ReplyMessage, Value: []byte(err)},
			},
		))
		return
	}

	user := string(req.Attrs[radius.UserName].Value)
	raw := req.Attrs[radius.UserPassword].Value
	pass := radius.DecryptPassword(raw, req)

	fmt.Println(fmt.Sprintf("auth user=%s pass=%s", user, pass))
	if user == "herp" && pass == "derp" {
		w.Write(req.Response(
			radius.AccessAccept, []radius.PubAttr{
				radius.PubAttr{Type: radius.ReplyMessage, Value: []byte("Valid.")},
			},
		))
		return
	}

	w.Write(req.Response(
		radius.AccessReject, []radius.PubAttr{
			radius.PubAttr{Type: radius.ReplyMessage, Value: []byte("Invalid user/pass.")},
		},
	))
}

func acctBegin(w io.Writer, req *radius.Packet) {
	err := radius.ValidateAcctRequest(req)
	if err != "" {
		fmt.Println("acct.begin err=" + err)
		w.Write(req.Response(
			radius.AccountingResponse, []radius.PubAttr{
				radius.PubAttr{Type: radius.ReplyMessage, Value: []byte(err)},
			},
		))
		return
	}
	user := string(req.Attrs[radius.UserName].Value)
	sess := string(req.Attrs[radius.AcctSessionId].Value)

	fmt.Println(fmt.Sprintf(
		"acct.begin sess=%s for user=%s",
		sess, user,
	))

	w.Write(req.Response(
		radius.AccountingResponse, []radius.PubAttr{
			radius.PubAttr{Type: radius.ReplyMessage, Value: []byte("Gimme those bits")},
		},
	))
}

func acctUpdate(w io.Writer, req *radius.Packet) {
	err := radius.ValidateAcctRequest(req)
	if err != "" {
		fmt.Println("acct.begin err=" + err)
		w.Write(req.Response(
			radius.AccountingResponse, []radius.PubAttr{
				radius.PubAttr{Type: radius.ReplyMessage, Value: []byte(err)},
			},
		))
		return
	}
	user := string(req.Attrs[radius.UserName].Value)
	sess := string(req.Attrs[radius.AcctSessionId].Value)

	sessTime := string(req.Attrs[radius.AcctSessionTime].Value)
	octIn := string(req.Attrs[radius.AcctInputOctets].Value)
	octOut := string(req.Attrs[radius.AcctOutputOctets].Value)

	fmt.Println(fmt.Sprintf(
		"acct.update sess=%s for user=%s sessTime=%s octetsIn=%s octetsOut=%s",
		sess, user, sessTime, octIn, octOut,
	))

	w.Write(req.Response(
		radius.AccountingResponse, []radius.PubAttr{
			radius.PubAttr{Type: radius.ReplyMessage, Value: []byte("Got it!")},
		},
	))
}

func main() {
	radius.HandleFunc(radius.AccessRequest, 0, auth)
	radius.HandleFunc(radius.AccountingRequest, 1, acctBegin)
	radius.HandleFunc(radius.AccountingRequest, 3, acctUpdate)

	go func() {
		fmt.Println("Listening on 127.0.0.1:1812")
		if e := radius.ListenAndServe("127.0.0.1:1812", "secret"); e != nil {
			panic(e)
		}
	}()
	fmt.Println("Listening on 127.0.0.1:1813")
	if e := radius.ListenAndServe("127.0.0.1:1813", "secret"); e != nil {
		panic(e)
	}

	/*
	    1      Start
	    2      Stop
	    3      Interim-Update
	    7      Accounting-On
	    8      Accounting-Off
	    9-14   Reserved for Tunnel Accounting
	   15      Reserved for Failed
	*/
}
