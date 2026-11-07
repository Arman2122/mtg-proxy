package mtglib

import (
	"sync"
	"time"
)

// blockedTracker is the time at least one of an address's streams spent
// blocked at one bucket: a union over the streams, not a sum. Fifty streams each
// blocked a hundredth of the time are an address blocked a hundredth of the
// time, or a little more, not one blocked half of it.
//
// It is kept incrementally, so a wait is credited while it lasts and not only
// when it ends: a chunk held for seconds at a small fair share must show in the
// ticks it spans, or those ticks would see an address with no duty and next to
// no rate, and release it as one that had paused. A stream enters before a wait
// and leaves after it, and a snapshot counts an interval still open up to its
// own instant.
//
// It is touched only by the streams of an address that has a fair share, and by
// those around every wait at the fair limiter and at the user's bucket it
// divides, whether or not the wait sleeps: two lock pairs per chunk in that
// bucket's direction, contended across the address's streams. A small mutex of
// its own is enough. It is a leaf in the lock order: nothing is taken while it
// is held. The zero value is ready, with nothing blocked.
//
// A stream reads the clock before it takes the lock, so readings can reach the
// lock out of order. No instant is credited twice: an interval is never opened
// from before the last instant already accounted for -- the end of the last
// interval, or the last snapshot -- so the sum over all windows is never more
// than the time the address was blocked. One window can still hold a little
// more than its own length, when a leave read the clock after the snapshot did
// but took the lock before it; by no more than the time between a reading and
// the lock.
type blockedTracker struct {
	mu sync.Mutex

	// blocked is how many streams are waiting now, and since is when that last
	// rose from zero -- or the last snapshot, if one was taken while they were.
	blocked int
	since   time.Time

	// edge is the latest instant already accounted for: where the last
	// interval closed, or where the last snapshot was taken. No interval is
	// credited from before it.
	edge time.Time

	// total is the blocked time closed in the current window.
	total time.Duration
}

// enter counts one more stream blocked from now, or from the last instant
// already accounted for if now is older than that.
func (b *blockedTracker) enter(now time.Time) {
	b.mu.Lock()

	if b.blocked == 0 {
		b.since = later(now, b.edge)
	}

	b.blocked++

	b.mu.Unlock()
}

// leave counts one stream let go at now. The last one to leave closes the
// interval. A leave with nothing blocked changes nothing.
func (b *blockedTracker) leave(now time.Time) {
	b.mu.Lock()

	if b.blocked > 0 {
		b.blocked--

		if b.blocked == 0 {
			if now.After(b.since) {
				b.total += now.Sub(b.since)
			}

			b.edge = later(b.edge, now)
		}
	}

	b.mu.Unlock()
}

// snapshot is the blocked time since the last snapshot, up to now: the
// intervals that closed in the window, and the one still open if streams are
// blocked now. It starts the next window at now, with an open interval carried
// into it from there. An instant before the open interval began -- two clocks
// read moments apart -- credits none of it.
func (b *blockedTracker) snapshot(now time.Time) time.Duration {
	b.mu.Lock()

	total := b.total
	b.total = 0

	if b.blocked > 0 && now.After(b.since) {
		total += now.Sub(b.since)
		b.since = now
	}

	b.edge = later(b.edge, now)

	b.mu.Unlock()

	return total
}

// later is the later of two instants.
func later(a, b time.Time) time.Time {
	if b.After(a) {
		return b
	}

	return a
}
