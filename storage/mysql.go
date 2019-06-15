package storage

// go get -u github.com/tscholl2/embd
//go:generate embd -n archiveSession      archiveSession.sql
//go:generate embd -n deleteSession       deleteSession.sql
//go:generate embd -n insertAcct          insertAcct.sql
//go:generate embd -n insertSession       insertSession.sql
//go:generate embd -n selectLimits        selectLimits.sql
//go:generate embd -n selectSessCount     selectSessCount.sql
//go:generate embd -n selectSessionExists selectSessionExists.sql
//go:generate embd -n selectUser          selectUser.sql
//go:generate embd -n updateSession       updateSession.sql
//go:generate embd -n updateUsage         updateUsage.sql
//go:generate embd -n selectUsage         selectUsage.sql

import (
	"database/sql"
	"time"

	"github.com/mpdroog/radiusd/model"
	"github.com/mpdroog/radiusd/sync"
	_ "github.com/go-sql-driver/mysql"
	"github.com/pkg/errors"
)

type MySQL struct {
	DB *sql.DB
}

func NewMySQL(dsn string) (*MySQL, error) {
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, err
	}

	err = db.Ping()
	if err != nil {
		db.Close()
		return nil, err
	}

	return &MySQL{DB: db}, nil
}

func (s *MySQL) Strict() (err error) {
	_, err = s.DB.Exec(`SET SESSION sql_mode = 'TRADITIONAL,NO_AUTO_VALUE_ON_ZERO,NO_BACKSLASH_ESCAPES'`)
	return err
}

func (s *MySQL) GetUser(name string) (user model.User, err error) {
	err = s.DB.QueryRow(selectUser, name).Scan(
		&user.Pass,
		&user.BlockRemain,
		&user.ActiveUntil,
		&user.Ok,
		&user.SimultaneousUse,
		&user.DedicatedIP,
		&user.Ratelimit,
		&user.DnsOne,
		&user.DnsTwo,
	)
	if err == sql.ErrNoRows {
		return user, nil
	}
	return user, err
}

func (s *MySQL) CountSessions(name string) (count int, err error) {
	err = s.DB.QueryRow(selectSessCount, name).Scan(&count)
	return count, err
}

func (s *MySQL) GetLimits(user string) (limits model.UserLimits, err error) {
	err = s.DB.QueryRow(selectLimits, user).Scan(&limits.Exists)
	return limits, err
}

func (s *MySQL) IsSessionExists(name string, sessID string, nasIP string) (exists bool, err error) {
	err = s.DB.QueryRow(
		selectSessionExists,
		name, sessID, nasIP,
	).Scan(&exists)
	if err == sql.ErrNoRows {
		return false, nil
	}

	return exists, err
}

func (s *MySQL) CreateSession(
	name string,
	sessID string,
	nasIP string,
	assignedIP string,
	clientIP string,
) error {
	res, err := s.DB.Exec(
		insertSession,
		sessID, name, time.Now().Unix(), nasIP, assignedIP, clientIP,
	)
	if err != nil {
		return err
	}

	return errors.Wrapf(affectCheck(res, 1, model.ErrCreateSession), "sess=%s user=%s", sessID, name)
}

func (s *MySQL) UpdateSession(
	name string,
	sessID string,
	nasIP string,
	rx int,
	tx int,
	rxPackets int,
	txPackets int,
	duration int,
) error {
	res, err := s.DB.Exec(
		updateSession,
		rx, tx, rxPackets, txPackets, duration, name, sessID, nasIP,
	)
	if err != nil {
		return err
	}

	return errors.Wrapf(affectCheck(res, 1, model.ErrUpdateSession), "sess=%s user=%s", sessID, name)
}

func (s *MySQL) FinishSession(name string, sessID string, nasIP string) error {
	res, err := s.DB.Exec(
		deleteSession,
		name, sessID, nasIP,
	)
	if err != nil {
		return err
	}

	return errors.Wrapf(affectCheck(res, 1, model.ErrFinishSession), "sess=%s user=%s", sessID, name)
}

func (s *MySQL) ArchiveSession(name string, sessID string, nasIP string) error {
	res, err := s.DB.Exec(
		archiveSession,
		name, sessID, nasIP,
	)
	if err != nil {
		return err
	}

	return errors.Wrapf(affectCheck(res, 1, model.ErrArchiveSession), "sess=%s user=%s", sessID, name)
}

func (s *MySQL) InsertAcct(name string, date string, rx int, tx int, rxPackets int, txPackets int, hostname string) error {
	res, err := s.DB.Exec(
		insertAcct,
		name, date, rx, tx, rxPackets, txPackets, hostname,
	)
	if err != nil {
		return err
	}

	return errors.Wrapf(affectCheck(res, 1, sync.ErrInsertAcct), "user=%s", name)
}

func (s *MySQL) UpdateUsage(name string, remain int) error {
	res, err := s.DB.Exec(
		updateUsage,
		remain, remain, name,
	)
	if err != nil {
		return err
	}

	return errors.Wrapf(affectCheck(res, 1, sync.ErrUpdateUsage), "user=%s", name)
}

func (s *MySQL) SelectRemain(name string) (remain int64, err error) {
	err = s.DB.QueryRow(selectUsage, name).Scan(&remain)
	return remain, err
}

func affectCheck(res sql.Result, expect int64, unexpected error) error {
	affect, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if affect != expect {
		return unexpected
	}
	return nil
}
