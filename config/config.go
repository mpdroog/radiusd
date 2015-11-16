package config

import (
	"database/sql"
	"encoding/json"
	_ "github.com/go-sql-driver/mysql"
	"io/ioutil"
	"log"
	"os"
	"net"
)

type Listener struct {
	Addr   string
	Secret string
	CIDR   []string
}

type Conf struct {
	Dsn          string
	Listeners    []Listener
	ControlListen string
}

var (
	C *Conf
	Log *log.Logger
	Debug bool
	Verbose bool
	Hostname string
	DB *sql.DB
	ErrNoRows = sql.ErrNoRows
	Stopping bool
	Sock []*net.UDPConn
)

func Init(path string) error {
	b, e := ioutil.ReadFile(path)
	if e != nil {
		return e
	}
	C = new(Conf)
	if e := json.Unmarshal(b, C); e != nil {
		return e
	}
	Hostname, e = os.Hostname()
	if e != nil {
		panic(e)
	}

	Log = log.New(os.Stdout, "radiusd ", log.LstdFlags)
	return dbInit("mysql", C.Dsn)
}

func dbInit(driver string, dsn string) error {
	var e error
	DB, e = sql.Open(driver, dsn)
	if e != nil {
		return e
	}
	return DB.Ping()
}

func DbClose() error {
	return DB.Close()
}
