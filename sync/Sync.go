package sync

import (
	"math/rand"
	"radiusd/config"
	"radiusd/queue"
	"time"
)

func save() {
	entries := queue.Flush()
	if config.Verbose {
		config.Log.Printf("sync.flush %d metrics", len(entries))
	}
	for user, entry := range entries {
		if e := SessionAcct(user, time.Now().Format("2006-01-02 15:04"), entry.InOctet, entry.OutOctet, entry.InPacket, entry.OutPacket, config.Hostname); e != nil {
			config.Log.Printf("WARN: Losing statistic data err=" + e.Error())
		}
		if e := UpdateRemaining(user, entry.InOctet+entry.OutOctet); e != nil {
			config.Log.Printf("WARN: Losing statistic data err=" + e.Error())
		}
	}
}

func Loop() {
	rand.Seed(time.Now().Unix())
	rnd := time.Duration(rand.Int31n(20)) * time.Second
	sleep := time.Duration(time.Minute + rnd)
	if config.Verbose {
		config.Log.Printf("Sync every: %s", sleep.String())
	}

	for range time.Tick(sleep) {
		save()
	}
}

// Force writing stats now
func Force() {
	save()
}
