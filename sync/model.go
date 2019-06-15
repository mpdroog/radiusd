package sync

import (
	"github.com/pkg/errors"
)

func SessionAcct(
	storage Storage,
	user string,
	date string,
	octetIn uint32,
	octetOut uint32,
	packetIn uint32,
	packetOut uint32,
	hostname string,
) error {
	return storage.InsertAcct(
		user,
		date,
		int(octetIn),
		int(octetOut),
		int(packetIn),
		int(packetOut),
		hostname,
	)
}

func UpdateRemaining(storage Storage, user string, remain uint32) error {
	if remain == 0 {
		return nil
	}

	err := storage.UpdateUsage(user, int(remain))
	if errors.Cause(err) == ErrUpdateUsage {
		// Nothing changed, check if this behaviour is correct
		remain, e := checkRemain(storage, user)
		if e != nil {
			return e
		}
		if !remain {
			return errors.Wrapf(ErrUpdateUsage, "user=%s", user)
		}
	}
	return nil
}

func checkRemain(storage Storage, user string) (bool, error) {
	remain, e := storage.SelectRemain(user)

	if remain == 0 {
		return true, e
	}
	return false, e
}
