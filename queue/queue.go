// Queue metrics for 5min so we send less
// data to the DB and lower load/change of racing
// conditions.
package queue

import (
	"sync"
)

type Stat struct {
	InOctet   uint32
	OutOctet  uint32
	InPacket  uint32
	OutPacket uint32
}

var remains map[string]Stat
var lock *sync.Mutex

func init() {
	remains = make(map[string]Stat)
	lock = new(sync.Mutex)
}

// Add to queue
func Queue(user string, in uint32, out uint32, inPack uint32, outPack uint32) {
	lock.Lock()
	defer lock.Unlock()

	remain, ok := remains[user]
	if ok {
		remain.InOctet += in
		remain.OutOctet += out
		remain.InPacket += inPack
		remain.OutPacket += outPack
	} else {
		remain = Stat{InOctet: in, OutOctet: out, InPacket: inPack, OutPacket: outPack}
	}
	remains[user] = remain
}

// Empty queue and return anything in it.
func Flush() map[string]Stat {
	nw := make(map[string]Stat)
	lock.Lock()

	out := remains
	remains = nw

	lock.Unlock()
	return out
}
