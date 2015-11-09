package model

import (
	"fmt"
	"radiusd/config"
	"time"
	"database/sql"
)

type User struct {
	ActiveUntil *string // Account active until YYYY-MM-DD
	BlockRemain *int64  // Remaining bandwidth
	Ok          bool
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

func affectCheck(res sql.Result, expect int64, errMsg error) error {
	affect, e := res.RowsAffected()
	if e != nil {
		return e
	}
	if affect != expect {
		return errMsg
	}
	return nil
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
	return affectCheck(res, 1, fmt.Errorf(
		"Affect fail for sess=%s user=%s",
		sessionId, user,
	))
}

func SessionRemove(sessionId string, user string, nasIp string) error {
	res, e := config.DB.Exec(
		`DELETE FROM
			session
		WHERE
			session_id = ?
		AND
			user = ?
		AND
			nas_ip = ?`,
		sessionId, user, nasIp,
	)
	if e != nil {
		return e
	}
	return affectCheck(res, 1, fmt.Errorf(
		"Affect fail for sess=%s",
		sessionId,
	))
	return nil
}

// Copy session to log
func SessionLog(sessionId string, user string, nasIp string) error {
	res, e := config.DB.Exec(
		`INSERT INTO
			session_log
			(assigned_ip, bytes_in, bytes_out, client_ip,
			nas_ip, packets_in, packets_out, session_id,
			session_time, user)
		SELECT
			assigned_ip, bytes_in, bytes_out, client_ip,
			nas_ip, packets_in, packets_out, session_id,
			session_time, user
		FROM
			session
		WHERE
			session_id = ?
		AND
			user = ?
		AND
			nas_ip = ?`,
		sessionId, user, nasIp,
	)
	if e != nil {
		return e
	}
	return affectCheck(res, 1, fmt.Errorf(
		"session.log fail for sess=%s",
		sessionId,
	))
}
