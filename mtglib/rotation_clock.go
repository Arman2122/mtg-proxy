package mtglib

import (
	"sync/atomic"
	"time"
)

// behindThreshold is how far the wall clock must be behind the latest time a
// RotationClock has seen before the clock calls it an episode worth reporting.
// A step of a second or less is ordinary NTP slewing and is not reported.
const behindThreshold = time.Second

// RotationClock is the wall clock retiring keys expire by, never allowed to run
// backwards within a process. One instance per process, shared by whatever reads
// a config and the proxy, so that both judge an overlap by the same instant: an
// NTP step back after an overlap's until must not make a later reload accept the
// old key again.
//
// It is a high-water mark over a time source. Now returns the larger of what the
// source says and the latest time it has returned. When the source is more than
// a second behind that mark, the clock reports the episode once, through the
// callback given to NewRotationClock, and judges by the mark all the same.
//
// The zero value is usable: it is a high-water clock on time.Now that reports
// nothing. A nil *RotationClock reads time.Now with no mark at all. A
// RotationClock must not be copied after first use.
type RotationClock struct {
	now      func() time.Time       // time.Now when nil; injected in tests
	mark     atomic.Int64           // the latest wall time seen, unix nanos
	behind   atomic.Bool            // the current behind episode was reported
	onBehind func(by time.Duration) // called once per episode; nil logs nothing
}

// NewRotationClock builds a clock on the given time source (nil is time.Now).
// onBehind, if not nil, is called with how far the source was behind the clock's
// mark, once for each episode of the source being more than a second behind it.
func NewRotationClock(now func() time.Time, onBehind func(time.Duration)) *RotationClock {
	return &RotationClock{now: now, onBehind: onBehind}
}

// Now is the time to judge an expiry by: the larger of the source's time and the
// latest time this clock has returned, which it then holds. A nil receiver reads
// time.Now. It is safe for concurrent use.
//
// A source at or past the mark moves the mark and ends a behind episode. A
// source more than a second behind the mark starts one, and onBehind is called
// for it once, whichever goroutine gets there first, until a read reaches the
// mark again. A source behind the mark by a second or less neither starts nor
// ends an episode.
func (c *RotationClock) Now() time.Time {
	if c == nil {
		return time.Now()
	}

	source := time.Now
	if c.now != nil {
		source = c.now
	}

	at := source()
	ns := at.UnixNano()

	for {
		mark := c.mark.Load()

		if ns < mark {
			return c.heldAt(at, time.Duration(mark-ns))
		}

		if ns == mark || c.mark.CompareAndSwap(mark, ns) {
			// The source has reached the mark: whatever episode it was in is over.
			// The load keeps the common read from writing.
			if c.behind.Load() {
				c.behind.Store(false)
			}

			return at
		}
	}
}

// heldAt is the mark, for a read whose source was gap behind it: at moved up by
// the gap, as a wall time without a monotonic reading, so that it compares with
// a time read from a file by its wall clock. It reports the episode when the gap
// is more than behindThreshold and nobody has yet.
func (c *RotationClock) heldAt(at time.Time, gap time.Duration) time.Time {
	if gap > behindThreshold && c.behind.CompareAndSwap(false, true) && c.onBehind != nil {
		c.onBehind(gap)
	}

	return at.Add(gap).Round(0)
}
