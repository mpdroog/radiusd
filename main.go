package main

import (
	"flag"
	"radiusd/config"
	"radiusd/radius"
	"radiusd/sync"
	S "sync"
)

var wg *S.WaitGroup

func listenAndServe(l config.Listener) {
	defer wg.Done()

	if config.Verbose {
		config.Log.Printf("Listening on " + l.Addr)
	}
	conn, e := radius.Listen(l.Addr)
	if e != nil {
		panic(e)
	}
	config.Sock = append(config.Sock, conn)
	if e := radius.Serve(conn, l.Secret, l.CIDR); e != nil {
		if config.Stopping {
			// Ignore close errors
			return
		}
		panic(e)
	}
}

func main() {
	var configPath string
	flag.BoolVar(&config.Debug, "d", false, "Debug packetdata")
	flag.BoolVar(&config.Verbose, "v", false, "Show all that happens")
	flag.StringVar(&configPath, "c", "./config.toml", "Configuration")
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

	go Control()
	go sync.Loop()

	wg = new(S.WaitGroup)
	for _, listen := range config.C.Listen {
		wg.Add(1)
		go listenAndServe(listen)
	}
	wg.Wait()

	// Write all stats
	sync.Force()
}
