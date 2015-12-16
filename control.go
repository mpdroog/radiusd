// Control offers an HTTP JSON API.
package main

import (
	"fmt"
	"net"
	"net/http"
	"radiusd/config"
	"github.com/itshosted/webutils/httpd"
	"github.com/itshosted/webutils/middleware"
	"github.com/itshosted/webutils/muxdoc"
	"github.com/itshosted/webutils/ratelimit"
)

var (
	mux muxdoc.MuxDoc
	ln net.Listener
)

func Control() {
	mux.Title = "RadiusdD API"
	mux.Desc = "Administrative API"
	mux.Add("/", doc, "This documentation")
	mux.Add("/shutdown", shutdown, "Finish jobs and close application")
	mux.Add("/verbose", verbose, "Toggle verbosity-mode")

	middleware.Add(ratelimit.Use(5, 5))
	http.Handle("/", middleware.Use(mux.Mux))

	var e error
	server := &http.Server{Addr: config.C.ControlListen, Handler: nil}
	ln, e = net.Listen("tcp", server.Addr)
	if e != nil {
		panic(e)
	}
	if config.Verbose {
		config.Log.Printf("httpd listening on " + config.C.ControlListen)
	}
	if e := server.Serve(tcpKeepAliveListener{ln.(*net.TCPListener)}); e != nil {
		if !config.Stopping {
			panic(e)
		}
	}
}

// Return API Documentation (paths)
func doc(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(404)
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(mux.String()))
}

// Finish pending jobs and close application
func shutdown(w http.ResponseWriter, r *http.Request) {
	if config.Stopping {
		if _, e := w.Write([]byte(fmt.Sprintf(`{success: true, msg: "Already stopping."}`))); e != nil {
			httpd.Error(w, e, "Flush failed")
			return
		}
	}

	config.Log.Printf("Disconnecting")
	config.Stopping = true

	if e := ln.Close(); e != nil {
		httpd.Error(w, e, `{success: false, msg: "Error stopping HTTP-listener"}`)
	}
	for _, sock := range config.Sock {
		if e := sock.Close(); e != nil {
			httpd.Error(w, e, `{success: false, msg: "Error stopping listener"}`)
		}
	}
	if _, e := w.Write([]byte(`{success: true, msg: "Stopped listening, waiting for empty queue."}`)); e != nil {
		httpd.Error(w, e, "Flush failed")
		return
	}
}

func verbose(w http.ResponseWriter, r *http.Request) {
	msg := `{success: true, msg: "Set verbosity to `
	if config.Verbose {
		config.Verbose = false
		msg += "OFF"
	} else {
		config.Verbose = true
		msg += "ON"
	}
	msg += `"}`

	if _, e := w.Write([]byte(msg)); e != nil {
		httpd.Error(w, e, "Flush failed")
		return
	}
}
