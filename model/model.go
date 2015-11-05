package model;

import (
	"radiusd/config"
	"time"
	"fmt"
)

type User struct {
	ActiveUntil *string // Account active until YYYY-MM-DD
	BlockRemain *int64 // Remaining bandwidth
	Ok bool
}

func Auth(user string, pass string) (User, error) {
	u := User{}
	e := config.DB.QueryRow(
		`SELECT
			block_remaining,
			active_until,
			1
		FROM
			user			
		WHERE
			user = ?
		AND
			pass = ?`,
		user, pass,
	).Scan(&u.BlockRemain, &u.ActiveUntil, &u.Ok)
	if e == config.ErrNoRows {
		return u, nil
	}
	return u, e
}

func SessionAdd(sessionId, user string, nasIp string, hostname string) error {
	res, e := config.DB.Exec(
		`INSERT INTO
			session
		(session_id, user, time_added, nas_ip, hostname)
		VALUES
		(?, ?, ?, ?, ?)`,
		sessionId, user, time.Now().Unix(), nasIp, hostname,
	)
	if e != nil {
		return e
	}
	affect, e := res.RowsAffected()
	if e != nil {
		return e
	}
	if affect != 1 {
		return fmt.Errorf(
			"Affect fail for sess=%s user=%s",
			sessionId, user,
		)
	}
	return nil
}

func SessionRemove(sessionId string) error {
	res, e := config.DB.Exec(
		`DELETE FROM
			session
		WHERE
			session_id = ?`,
		sessionId,
	)
	if e != nil {
		return e
	}
	affect, e := res.RowsAffected()
	if e != nil {
		return e
	}
	if affect != 1 {
		return fmt.Errorf(
			"Affect fail for sess=%s",
			sessionId,
		)
	}
	return nil
}

// Delete all sessions for this app
func SessionClear(hostname string) (int64, error) {
	res, e := config.DB.Exec(
		`DELETE FROM
			session
		WHERE
			hostname = ?`,
		hostname,
	)
	if e != nil {
		return 0, e
	}
	return res.RowsAffected()
}
