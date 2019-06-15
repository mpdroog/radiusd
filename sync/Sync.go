package sync

import (
	"log"
	"math/rand"
	"time"

	"github.com/mpdroog/radiusd/queue"
)

func save(storage Storage, hostname string, verbose bool, logger *log.Logger) {
	entries := queue.Flush()
	if verbose {
		logger.Printf("sync.flush %d metrics", len(entries))
	}
	for user, entry := range entries {
		if e := SessionAcct(storage, user, time.Now().UTC().Format("2006-01-02 15:04"), entry.InOctet, entry.OutOctet, entry.InPacket, entry.OutPacket, hostname); e != nil {
			logger.Printf("WARN: Losing statistic data err=" + e.Error())
		}
		if e := UpdateRemaining(storage, user, entry.InOctet+entry.OutOctet); e != nil {
			logger.Printf("WARN: Losing statistic data err=" + e.Error())
		}
	}
}

func Loop(storage Storage, hostname string, verbose bool, logger *log.Logger) {
	rand.Seed(time.Now().Unix())
	rnd := time.Duration(rand.Int31n(20)) * time.Second
	sleep := time.Duration(time.Minute + rnd)
	if verbose {
		logger.Printf("Sync every: %s", sleep.String())
	}

	for range time.Tick(sleep) {
		save(storage, hostname, verbose, logger)
	}
}

// Force writing stats now
func Force(storage Storage, hostname string, verbose bool, logger *log.Logger) {
	save(storage, hostname, verbose, logger)
}
