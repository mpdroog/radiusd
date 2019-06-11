package model

import "errors"

var (
	ErrNoRows         = errors.New("no such record")
	ErrCreateSession  = errors.New("session.add fail")
	ErrUpdateSession  = errors.New("session.update fail")
	ErrFinishSession  = errors.New("session.finish fail")
	ErrArchiveSession = errors.New("session.archive fail")
)

type Storage interface {
	GetUser(name string) (user User, err error)
	CountSessions(name string) (count int, err error)
	GetLimits(name string) (user UserLimits, err error)
	IsSessionExists(name string, sessID string, nasIP string) (exists bool, err error)
	CreateSession(name string, sessID string, nasIP string, assignedIP string, clientIP string) error
	UpdateSession(name string, sessID string, nasIP string, rx int, tx int, rxPackets int, txPackets int, duration int) error
	FinishSession(name string, sessID string, nasIP string) error
	ArchiveSession(name string, sessID string, nasIP string) error
}
