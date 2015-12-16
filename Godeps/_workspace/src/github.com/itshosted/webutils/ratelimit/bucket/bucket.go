package bucket

// Limit the amount of requests per second.
// Based off: http://en.wikipedia.org/wiki/Leaky_bucket
import (
	"math"
	"time"
)

type Bucket struct {
	Fillrate   float64   // The rate at which the bucket is filled
	Capacity   float64   // Max capacity of a full bucket
	Available  float64   // Current available tokens in bucket
	LastUpdate time.Time // The last time the bucket was updated

	Delay        time.Duration // Delay in seconds after a ratelimited request
	DelayUntil   time.Time     // Delay requests until this time is surpassed
	DelayCounter int           // Amount of times the request surparassed the ratelimit without waiting for delay
}

// Increase request counter by amount.
// Return false if limit is reached
func (b *Bucket) Request(amount float64) bool {
	now := time.Now()

	// Are we delaying requests? if so increase counter and delay time
	if b.DelayUntil.Unix() > now.Unix() {
		b.DelayCounter++
		b.DelayUntil = time.Now().Add(b.Delay)
		return false
	}

	// Calculate bucket fill based on elapsed time
	timeDiff := now.Sub(b.LastUpdate).Seconds()
	b.Available = math.Min(b.Capacity, b.Available+(timeDiff*b.Fillrate))
	b.LastUpdate = now

	if b.Available >= amount {
		// Request is OK,
		b.Available -= amount
		return true
	}

	// Ratelimit was exceeded, init counter and set time delay
	b.DelayCounter = 1
	b.DelayUntil = time.Now().Add(b.Delay)
	return false
}

// Create new bucket.
//
// fillrate = Amount of requests per second
// capacity = Extra requests allowed a-top fillrate
// delay = Time delay request if ratelimited
//
// Example: fillrate=10 capacity=10
//  this allows 10reqs/sec and if surpassed allow 10 reqs more
//  before returning false with Request()
func New(fillrate float64, capacity float64, delay time.Duration) *Bucket {
	return &Bucket{
		Fillrate:   fillrate,
		Capacity:   capacity,
		Available:  capacity,
		LastUpdate: time.Now(),
		Delay:      delay,
	}
}
