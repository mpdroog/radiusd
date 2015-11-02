package model;

import "database/sql"
import _ "github.com/go-sql-driver/mysql"

var db *sql.DB

type User struct {
	ActiveUntil // Account active until YYYY-MM-DD
	BlockRemain // Remaining bandwidth
}

func Init(driver string, dsn string) error {
	var e error
	db, e = sql.Open(driver, dsn)
	if e != nil {
		return e
	}
	if e := db.Ping(); e != nil {
		return e
	}
	return nil
}

func Close() error {
	return db.Close()
}

func Auth(user string, pass string) (User, error) {
	u := &User{}
	e := db.QueryRow(
		`SELECT
			block_remaining,
			active_until
		FROM
			user			
		WHERE
			radius_login = ?
		AND
			radius_pass = ?`,
		user, pass,
	).Scan(&u.BlockRemain, &u.ActiveUntil)
	return u, e
}