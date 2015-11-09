package model

import (
	"fmt"
	"radiusd/config"
	"time"
	"database/sql"
)

type User struct {
	ActiveUntil     *string // Account active until YYYY-MM-DD
	BlockRemain     *int64  // Remaining bandwidth
	SimultaneousUse uint32 // Max conns allowed
	DedicatedIP     *string
	Ratelimit       *string
	Ok              bool
}
type Session struct {
	BytesIn     uint32
	BytesOut    uint32
	PacketsIn   uint32
	PacketsOut  uint32
	SessionID   string
	SessionTime uint32
	User        string
	NasIP       string
}
type UserLimits struct {
	Exists bool
}

var ErrNoRows = sql.ErrNoRows

func Begin() (*sql.Tx, error) {
	return config.DB.Begin()
}

func Auth(user string, pass string) (User, error) {
	u := User{}
	e := config.DB.QueryRow(
		`SELECT
			block_remaining,
			active_until,
			1,
			simultaneous_use,
			dedicated_ip,
			CONCAT(ratelimit_up, ratelimit_unit, '/', ratelimit_down, ratelimit_unit)
		FROM
			user
		JOIN
			product
		ON
			user.product_id = product.id
		WHERE
			user = ?
		AND
			pass = ?`,
		user, pass,
	).Scan(&u.BlockRemain, &u.ActiveUntil, &u.Ok, &u.SimultaneousUse, &u.DedicatedIP, &u.Ratelimit)
	if e == config.ErrNoRows {
		return u, nil
	}
	return u, e
}

func Conns(user string) (uint32, error) {
	var count uint32 = 0;
	e := config.DB.QueryRow(
		`SELECT
			COUNT(*)
		FROM
			session
		WHERE
			user = ?`,
		user,
	).Scan(&count)
	return count, e
}

func Limits(user string) (UserLimits, error) {
	u := UserLimits{}
	e := config.DB.QueryRow(
		`SELECT
			1
		FROM
			user
		JOIN
			product
		ON
			user.product_id = product.id
		WHERE
			user = ?`,
		user,
	).Scan(&u.Exists)
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

func SessionAdd(sessionId, user, nasIp, assignedIp, clientIp string) error {
	exists := false
	e := config.DB.QueryRow(
		`SELECT
			1
		FROM
			session
		WHERE
			user = ?
		AND
			session_id = ?
		AND
			nas_ip = ?`,
		user, sessionId, nasIp,
	).Scan(&exists)
	if e != nil && e != sql.ErrNoRows {
		return e
	}
	if exists {
		// Session already stored
		return nil
	}

	res, e := config.DB.Exec(
		`INSERT INTO
			session
		(session_id, user, time_added, nas_ip, assigned_ip, client_ip, bytes_in, bytes_out, packets_in, packets_out, session_time)
		VALUES
		(?, ?, ?, ?, ?, ?, 0, 0, 0, 0, 0)`,
		sessionId, user, time.Now().Unix(), nasIp, assignedIp, clientIp,
	)
	if e != nil {
		return e
	}
	return affectCheck(res, 1, fmt.Errorf(
		"session.add fail for sess=%s user=%s",
		sessionId, user,
	))
}

func SessionUpdate(txn *sql.Tx, s Session) error {
	res, e := txn.Exec(
		`UPDATE
			session
		SET
			bytes_in = ?,
			bytes_out = ?,
			packets_in = ?,
			packets_out = ?,
			session_time = ?
		WHERE
			session_id = ?
		AND
			user = ?
		AND
			nas_ip = ?`,
		s.BytesIn, s.BytesOut, s.PacketsIn, s.PacketsOut, s.SessionTime,
		s.SessionID, s.User, s.NasIP,
	)
	if e != nil {
		return e
	}
	return affectCheck(res, 1, fmt.Errorf(
		"session.update fail for sess=%s user=%s",
		s.SessionID, s.User,
	))

}

func SessionRemove(txn *sql.Tx, sessionId, user, nasIp string) error {
	res, e := txn.Exec(
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
		"session.remove fail for sess=%s",
		sessionId,
	))
	return nil
}

// Copy session to log
func SessionLog(txn *sql.Tx, sessionId string, user string, nasIp string) error {
	res, e := txn.Exec(
		`INSERT INTO
			session_log
			(assigned_ip, bytes_in, bytes_out, client_ip,
			nas_ip, packets_in, packets_out, session_id,
			session_time, user, time_added)
		SELECT
			assigned_ip, bytes_in, bytes_out, client_ip,
			nas_ip, packets_in, packets_out, session_id,
			session_time, user, time_added
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
