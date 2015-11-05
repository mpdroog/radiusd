package main

import (
    "flag"
	"radiusd/radius"
    "radiusd/config"
    "radiusd/sync"
    "radiusd/model"
)

func listenAndServe(l config.Listener) {
    if config.Verbose {
        config.Log.Printf("Listening on " + l.Addr)
    }
    if e := radius.ListenAndServe(l.Addr, l.Secret, l.CIDR); e != nil {
        panic(e)
    }
}

func main() {
    var configPath string
    flag.BoolVar(&config.Debug, "d", false, "Debug packetdata")
    flag.BoolVar(&config.Verbose, "v", false, "Show all that happens")
    flag.StringVar(&configPath, "c", "./config.json", "Configuration")
    flag.Parse()

    if e := config.Init(configPath); e != nil {
        panic(e)
    }
    if e := sync.Init(); e != nil {
        panic(e)
    }
    if config.Verbose {
        config.Log.Printf("%+v", config.C)
    }
    if config.Debug {
        config.Log.Printf("Auth RFC2865 https://tools.ietf.org/html/rfc2865")
        config.Log.Printf("Acct RFC2866 https://tools.ietf.org/html/rfc2866")
    }

    hang, e := model.SessionClear(config.Hostname)
    if e != nil {
        panic(e)
    }
    if hang != 0 {
        config.Log.Printf("WARN: Deleted %d sessions", hang)
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
	radius.HandleFunc(radius.AccessRequest, 0, auth)
	radius.HandleFunc(radius.AccountingRequest, 1, acctBegin)
	radius.HandleFunc(radius.AccountingRequest, 3, acctUpdate)
    radius.HandleFunc(radius.AccountingRequest, 2, acctStop)

    go sync.Loop()
    for idx, listen := range config.C.Listeners {
        if (idx+1 == len(config.C.Listeners)) {
            // Run last listener in main thread
            listenAndServe(listen)
        } else {
            go listenAndServe(listen)
        }
    }
}
