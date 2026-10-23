package mtglib

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// The blocked-interval tracker on its own: every instant is passed in, so each
// of these is a sequence of events and the number it must come to.

// The blocked-interval tracker is a union over the address's streams: two
// streams blocked at once are one address blocked. Fifty chatty streams each
// blocked a little must not add up to an address blocked all the time.
func TestBlockedTrackerIsAUnionOverStreams(t *testing.T) {
	t.Parallel()

	var b blockedTracker

	t0 := fakeAddrClockBase

	b.enter(t0)                      // one stream blocks
	b.enter(t0.Add(time.Second))     // a second one, while the first still is
	b.leave(t0.Add(2 * time.Second)) // the first is let go
	b.leave(t0.Add(3 * time.Second)) // and then the second

	assert.Equal(t, 3*time.Second, b.snapshot(t0.Add(4*time.Second)),
		"three seconds with a stream blocked, not four seconds of blocked streams")
}

// A wait that outlasts a window is credited in every window it spans, while it
// lasts: a snapshot counts the interval still open up to its own instant, and
// the next window starts there.
func TestBlockedTrackerCreditsAWaitWhileItLasts(t *testing.T) {
	t.Parallel()

	var b blockedTracker

	t0 := fakeAddrClockBase

	b.enter(t0)

	assert.Equal(t, time.Second, b.snapshot(t0.Add(time.Second)), "an open wait is credited up to the snapshot")
	assert.Equal(t, 1500*time.Millisecond, b.snapshot(t0.Add(2500*time.Millisecond)),
		"and the next window has what came after, not the whole wait again")

	b.leave(t0.Add(3 * time.Second))

	assert.Equal(t, 500*time.Millisecond, b.snapshot(t0.Add(5*time.Second)), "the wait ended half a second in")
	assert.Zero(t, b.snapshot(t0.Add(6*time.Second)), "and nothing is blocked any more")
}

// A snapshot takes what it reports: the window starts again empty.
func TestBlockedTrackerResetsItsWindow(t *testing.T) {
	t.Parallel()

	var b blockedTracker

	t0 := fakeAddrClockBase

	b.enter(t0)
	b.leave(t0.Add(time.Second))

	assert.Equal(t, time.Second, b.snapshot(t0.Add(2*time.Second)))
	assert.Zero(t, b.snapshot(t0.Add(3*time.Second)), "the second snapshot of the same wait finds nothing")

	b.enter(t0.Add(4 * time.Second))
	b.leave(t0.Add(4500 * time.Millisecond))

	assert.Equal(t, 500*time.Millisecond, b.snapshot(t0.Add(5*time.Second)), "and a new wait counts afresh")
}

// The tracker's edges: a leave with nothing blocked changes nothing, and a
// snapshot taken at an instant before the open interval began -- two goroutines
// read the clock moments apart and reach the lock in the other order -- credits
// none of it and leaves it whole for the next.
func TestBlockedTrackerEdges(t *testing.T) {
	t.Parallel()

	var b blockedTracker

	t0 := fakeAddrClockBase

	b.leave(t0)
	b.enter(t0.Add(time.Second))
	b.leave(t0.Add(2 * time.Second))

	assert.Equal(t, time.Second, b.snapshot(t0.Add(3*time.Second)),
		"an unmatched leave neither opens nor closes an interval")

	b.enter(t0.Add(5 * time.Second))
	assert.Zero(t, b.snapshot(t0.Add(4*time.Second)), "a snapshot before the interval began credits none of it")

	b.leave(t0.Add(6 * time.Second))
	assert.Equal(t, time.Second, b.snapshot(t0.Add(7*time.Second)), "and the interval is whole for the next")
}

// A stream reads the clock before it takes the tracker's lock, so readings can
// reach the lock out of order. Stream B read t3 while A was blocked, and took
// the lock only after A left at t5: the time from t3 to t5 is already credited,
// and crediting it again from B's reading would make the address blocked longer
// than it was. The union of [1, 5] and [3, 6] is five seconds.
func TestBlockedTrackerCreditsAnIntervalOnceWhenReadingsArriveLate(t *testing.T) {
	t.Parallel()

	var b blockedTracker

	at := func(seconds int) time.Time { return fakeAddrClockBase.Add(time.Duration(seconds) * time.Second) }

	b.enter(at(1))
	b.leave(at(5))
	b.enter(at(3)) // B's reading, older than A's leave that took the lock first
	b.leave(at(6))

	assert.Equal(t, 5*time.Second, b.snapshot(at(7)), "the union, not seven seconds of overlapping intervals")
}

// The same race against a snapshot: a snapshot at t4 found nothing blocked and
// closed its window, and a stream whose reading was t3 took the lock after it.
// The second from t3 to t4 belonged to the window already reported; it must not
// be carried into the next one, which would then hold more than its own length.
func TestBlockedTrackerNeverMovesTimeIntoTheNextWindow(t *testing.T) {
	t.Parallel()

	var b blockedTracker

	at := func(seconds int) time.Time { return fakeAddrClockBase.Add(time.Duration(seconds) * time.Second) }

	assert.Zero(t, b.snapshot(at(4)), "nothing was blocked in the first window")

	b.enter(at(3)) // a reading older than the snapshot that took the lock first
	b.leave(at(5))

	assert.Equal(t, time.Second, b.snapshot(at(6)), "the next window holds only its own second, from t4 to t5")
}
