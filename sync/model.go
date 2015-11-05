package sync

import (
	"radiusd/config"
	"database/sql"
	"fmt"
)

var (
	acct *sql.Stmt
	usage *sql.Stmt
)

func Init() error {
	var e error
	acct, e = config.DB.Prepare(
		`INSERT INTO
			accounting
		(user, date, bytes_in, bytes_out, hostname)
		VALUES (?, ?, ?, ?, ?)`,
	)
	if e != nil {
		return e
	}

	usage, e = config.DB.Prepare(
		`UPDATE
			user
		SET
			block_remaining = IF(CAST(block_remaining as SIGNED) - ? < 0, 0, block_remaining - ?)
		WHERE
			user = ?`,
	)
	return e
}

func SessionAcct(user string, date string, octetIn uint32, octetOut uint32, hostname string) error {
	res, e := acct.Exec(user, date, octetIn, octetOut, hostname)
	if e != nil {
		return e
	}
	affect, e := res.RowsAffected()
	if e != nil {
		return e
	}
	if affect != 1 {
		return fmt.Errorf(
			"Affect fail for user=%s",
			user,
		)
	}
	return nil
}

func UpdateRemaining(user string, remain uint32) error {
	if remain == 0 {
		return nil
	}

	res, e := usage.Exec(remain, remain, user)
	if e != nil {
		return e
	}
	affect, e := res.RowsAffected()
	if e != nil {
		return e
	}
	if affect != 1 {
		// TODO: zero check?
		return fmt.Errorf(
			"Affect fail for user=%s",
			user,
		)
	}
	return nil
}
