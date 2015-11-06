package sync

import (
	"database/sql"
	"fmt"
	"radiusd/config"
)

var (
	acct  *sql.Stmt
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
		// Nothing changed, check if this behaviour is correct
		remain, e := checkRemain(user)
		if e != nil {
			return e
		}
		if !remain {
			return fmt.Errorf(
				"Affect fail for user=%s",
				user,
			)
		}
	}
	return nil
}

func checkRemain(user string) (bool, error) {
	var remain *int64
	n := int64(0)
	remain = &n

	e := config.DB.QueryRow(
		`SELECT
			block_remaining
		FROM
			user
		WHERE
			user = ?`,
		user,
	).Scan(remain)
	if remain == nil || *remain == 0 {
		return true, e
	}
	return false, e
}
