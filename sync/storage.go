package sync

import "errors"

var (
	ErrInsertAcct     = errors.New("account.add fail")
	ErrUpdateUsage    = errors.New("user.update fail")
	ErrFinishSession  = errors.New("session.finish fail")
	ErrArchiveSession = errors.New("session.archive fail")
)

type Storage interface {
	InsertAcct(name string, date string, rx int, tx int, rxPackets int, txPackets int, hostname string) error
	UpdateUsage(name string, remain int) error
	SelectRemain(name string) (remain int64, err error)
}
