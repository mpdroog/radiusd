package main

import (
    "fmt"
    "radiusd/radius"
    "io"
)

func auth(w io.Writer, req *radius.Packet) {
    user := string(req.Attrs[radius.UserName].Value)
    raw := req.Attrs[radius.UserPassword].Value
    pass := radius.DecryptPassword(raw, req.Auth, "secret") // << Design bug!

    fmt.Println(fmt.Sprintf("auth user=%s pass=%s", user, pass))
    if (user == "herp" && pass == "derp") {
        w.Write(req.Response(
            "secret", radius.AccessAccept, []radius.PubAttr{
                radius.PubAttr{Type: radius.ReplyMessage, Value: []byte("Valid.")},
            },
        )) // << Design bug!
        return
    }

    w.Write(req.Response(
        "secret", radius.AccessReject, []radius.PubAttr{
            radius.PubAttr{Type: radius.ReplyMessage, Value: []byte("Invalid user/pass.")},
        },
    )) // << Design bug!
}

func acctBegin(w io.Writer, req *radius.Packet) {
    err := radius.ValidateAcctRequest(req)
    if err != "" {
        fmt.Println("acct.begin err=" + err)
        w.Write(req.Response(
            "secret", radius.AccountingResponse, []radius.PubAttr{
                radius.PubAttr{Type: radius.ReplyMessage, Value: []byte(err)},
            },
        )) // << Design bug!
        return        
    }
    user := string(req.Attrs[radius.UserName].Value)
    sess := string(req.Attrs[radius.AcctSessionId].Value)

    fmt.Println(fmt.Sprintf(
        "acct.begin sess=%s for user=%s",
        sess, user,
    ))

    w.Write(req.Response(
        "secret", radius.AccountingResponse, []radius.PubAttr{
            radius.PubAttr{Type: radius.ReplyMessage, Value: []byte("Gimme those bits")},
        },
    )) // << Design bug!
}

func main() {
    radius.HandleFunc(radius.AccessRequest, 0, auth)
    radius.HandleFunc(radius.AccountingRequest, 1, acctBegin)

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