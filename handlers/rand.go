package handlers

import (
	mrand "math/rand"
    "crypto/rand"
    "time"
)

func init() {
	mrand.Seed(time.Now().UnixNano())
}

// TODO: Prove its random between runs?
func GenRand(size int) (blk []byte, err error) {
    blk = make([]byte, size)
    _, err = rand.Read(blk)
    return
}

func randToken() uint32 {
	return mrand.Uint32();
}