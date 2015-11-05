package config

import (
	"os"
	"io/ioutil"
	"encoding/json"
	"log"
	"database/sql"
	_ "github.com/go-sql-driver/mysql"
)

type Listener struct {
	Addr string
	Secret string
	CIDR []string
}

type Conf struct {
	Dsn string
	Listeners []Listener
}

var C *Conf
var Log *log.Logger
var Debug bool
var Verbose bool
var Hostname string
var DB *sql.DB
var ErrNoRows = sql.ErrNoRows

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