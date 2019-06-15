package model

type User struct {
	Pass            string
	ActiveUntil     *string // Account active until YYYY-MM-DD
	BlockRemain     *int64  // Remaining bandwidth
	SimultaneousUse uint32  // Max conns allowed
	DedicatedIP     *string
	Ratelimit       *string
	DnsOne          *string
	DnsTwo          *string
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

func Auth(storage Storage, user string) (User, error) {
	return storage.GetUser(user)
}

func Conns(storage Storage, user string) (uint32, error) {
	count, err := storage.CountSessions(user)
	return uint32(count), err
}

func Limits(storage Storage, user string) (UserLimits, error) {
	return storage.GetLimits(user)
}

func SessionAdd(storage Storage, sessionId, user, nasIp, assignedIp, clientIp string) error {
	exists, e := storage.IsSessionExists(user, sessionId, nasIp)
	if e != nil {
		return e
	}
	if exists {
		// Session already stored
		return nil
	}

	return storage.CreateSession(user, sessionId, nasIp, assignedIp, clientIp)
}

func SessionUpdate(storage Storage, s Session) error {
	return storage.UpdateSession(
		s.User,
		s.SessionID,
		s.NasIP,
		int(s.BytesIn),
		int(s.BytesOut),
		int(s.PacketsIn),
		int(s.PacketsOut),
		int(s.SessionTime),
	)
}

func SessionRemove(storage Storage, sessionId, user, nasIp string) error {
	return storage.FinishSession(user, sessionId, nasIp)
}

// Copy session to log
func SessionLog(storage Storage, sessionId string, user string, nasIp string) error {
	return storage.ArchiveSession(user, sessionId, nasIp)
}
