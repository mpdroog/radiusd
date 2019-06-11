package config

import (
	"fmt"
	"log"
	"net"
	"os"

	"github.com/BurntSushi/toml"
)

type Listener struct {
	Addr   string
	Secret string
	CIDR   []string
}

type Conf struct {
	Dsn           string
	Listen        map[string]Listener
	ControlListen string
}

var (
	C        *Conf
	Log      *log.Logger
	Debug    bool
	Verbose  bool
	Hostname string
	Stopping bool
	Sock     []*net.UDPConn
)

func Init(path string) error {
	r, e := os.Open(path)
	if e != nil {
		return e
	}
	defer r.Close()

	C = new(Conf)
	if _, e := toml.DecodeReader(r, &C); e != nil {
		return fmt.Errorf("TOML: %s", e)
	}
	Hostname, e = os.Hostname()
	if e != nil {
		panic(e)
	}

	Log = log.New(os.Stdout, "radiusd ", log.LstdFlags)

	return nil
}
