package main

import (
	"flag"
	S "sync"

	"github.com/mpdroog/radiusd/config"
	"github.com/mpdroog/radiusd/handlers"
	"github.com/mpdroog/radiusd/radius"
	"github.com/mpdroog/radiusd/storage"
	"github.com/mpdroog/radiusd/sync"
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
	if e := radius.Serve(conn, l.Secret, l.CIDR, config.Verbose, config.Log); e != nil {
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

	storage, e := storage.NewMySQL(config.C.Dsn)
	if e != nil {
		panic(e)
	}
	if e := storage.Strict(); e != nil {
		panic(e)
	}

	h := &handlers.Handler{
		Storage: storage,
		Logger:  config.Log,
		Verbose: config.Verbose,
		State:   make(map[string]handlers.State, 1024), // start with 1024 size
	}
	radius.HandleFunc(radius.AccessRequest, 0, h.Auth)
	radius.HandleFunc(radius.AccountingRequest, 1, h.AcctBegin)
	radius.HandleFunc(radius.AccountingRequest, 3, h.AcctUpdate)
	radius.HandleFunc(radius.AccountingRequest, 2, h.AcctStop)

	go Control()
	go sync.Loop(storage, config.Hostname, config.Verbose, config.Log)

	wg = new(S.WaitGroup)
	for _, listen := range config.C.Listen {
		wg.Add(1)
		go listenAndServe(listen)
	}
	wg.Wait()

	// Write all stats
	sync.Force(storage, config.Hostname, config.Verbose, config.Log)
}
