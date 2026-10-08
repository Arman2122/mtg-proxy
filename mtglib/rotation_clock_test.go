package mtglib

import (
	"math/rand/v2"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// E5: the rotation clock. A retiring key expires by it, and it never runs
// backwards inside a process, so an NTP step back after an overlap's until
// cannot make a later read accept the old key again.

// steppedClock is a time source a test moves by hand. It can move backwards:
// holding the high-water mark is the RotationClock's job, not the source's.
type steppedClock struct{ at atomic.Int64 }

func newSteppedClock(at time.Time) *steppedClock {
	s := &steppedClock{}
	s.set(at)

	return s
}

func (s *steppedClock) set(at time.Time) { s.at.Store(at.UnixNano()) }

func (s *steppedClock) now() time.Time { return time.Unix(0, s.at.Load()).UTC() }

// TestRotationClockNeverRunsBackwards: whatever the source says, Now() is the
// latest time the clock has seen. Times are compared with Equal, never with
// assert.Equal: the clock may hand back the source's own value or one it built
// from its mark, and the two differ in zone and monotonic reading, not in the
// instant.
func TestRotationClockNeverRunsBackwards(t *testing.T) {
	t.Parallel()

	t.Run("a source stepped back and forth", func(t *testing.T) {
		t.Parallel()

		source := newSteppedClock(rotationNow)
		clock := NewRotationClock(source.now, nil)

		high := rotationNow

		for _, step := range []time.Duration{
			0, 3 * time.Second, 3 * time.Second, time.Second, -time.Hour,
			4 * time.Second, 2 * time.Second, 10 * time.Second, 10*time.Second - time.Nanosecond, 0,
		} {
			at := rotationAt(step)
			source.set(at)

			if at.After(high) {
				high = at
			}

			got := clock.Now()
			assert.True(t, got.Equal(high), "the source is at %v, so Now() is %v, not %v", step, high.Sub(rotationNow), got.Sub(rotationNow))
		}
	})

	t.Run("many readers of a source that jumps about", func(t *testing.T) {
		t.Parallel()

		// A source that returns a random instant within a minute of
		// rotationNow, so every reader sees steps back and forward at once.
		clock := NewRotationClock(func() time.Time {
			return rotationAt(time.Duration(rand.Int64N(int64(time.Minute))))
		}, nil)

		const (
			readers = 8
			reads   = 2000
		)

		var (
			wg     sync.WaitGroup
			failed atomic.Int64
			top    = make([]time.Time, readers)
		)

		for r := range readers {
			wg.Add(1)

			go func() {
				defer wg.Done()

				var last time.Time

				for range reads {
					got := clock.Now()
					if got.Before(last) {
						failed.Add(1)
					}

					last = got
				}

				top[r] = last
			}()
		}

		wg.Wait()

		assert.Zero(t, failed.Load(), "no reader ever saw the clock go back")

		final := clock.Now()
		for r, seen := range top {
			assert.False(t, final.Before(seen), "reader %d saw a time the clock has since gone back on", r)
		}
	})
}

// TestRotationClockReportsEachBehindEpisodeOnce: an episode is a run of reads
// whose source is more than a second behind the mark. onBehind fires once at its
// start, with the gap at that read, and not again until the source has caught up
// to the mark and fallen behind anew. A gap of a second or less is not behind.
func TestRotationClockReportsEachBehindEpisodeOnce(t *testing.T) {
	t.Parallel()

	var gaps []time.Duration

	source := newSteppedClock(rotationNow)
	clock := NewRotationClock(source.now, func(by time.Duration) { gaps = append(gaps, by) })

	// at moves the source to rotationNow+offset, reads the clock, and returns
	// the offset of the instant Now() answered.
	at := func(offset time.Duration) time.Duration {
		source.set(rotationAt(offset))

		return clock.Now().Sub(rotationNow)
	}

	s := time.Second

	assert.Equal(t, 10*s, at(10*s), "the mark starts at 10s")
	assert.Empty(t, gaps, "a source at the mark is not behind")

	assert.Equal(t, 10*s, at(5*s), "5s behind: the mark answers")
	assert.Equal(t, []time.Duration{5 * s}, gaps, "and the episode is reported once, with its gap")

	at(6 * s)
	at(9*s + 500*time.Millisecond)
	assert.Equal(t, []time.Duration{5 * s}, gaps, "more reads of the same episode, one of them inside the second, report nothing")

	at(4 * s)
	assert.Equal(t, []time.Duration{5 * s}, gaps,
		"a read within a second of the mark is not the end of the episode: only reaching the mark is")

	assert.Equal(t, 10*s, at(10*s))
	assert.Equal(t, 10*s, at(9*s), "exactly 1s behind")
	assert.Equal(t, []time.Duration{5 * s}, gaps, "a gap of 1s or less is never reported")

	assert.Equal(t, 12*s, at(12*s), "the source passes the mark and moves it")
	assert.Equal(t, 12*s, at(11*s), "exactly 1s behind the new mark")
	assert.Equal(t, []time.Duration{5 * s}, gaps)

	at(10*s + 900*time.Millisecond)
	assert.Equal(t, []time.Duration{5 * s, 1100 * time.Millisecond}, gaps,
		"a new episode, after the source had reached the mark, is reported again with its own gap")

	at(10 * s)
	assert.Len(t, gaps, 2, "the rest of that episode is silent")
}

// TestRotationClockWithoutAnOnBehindSaysNothing: a clock built with no callback
// reads through an episode without a panic.
func TestRotationClockWithoutAnOnBehindSaysNothing(t *testing.T) {
	t.Parallel()

	source := newSteppedClock(rotationAt(10 * time.Second))
	clock := NewRotationClock(source.now, nil)

	clock.Now()
	source.set(rotationNow)

	assert.NotPanics(t, func() { clock.Now() })
	assert.True(t, clock.Now().Equal(rotationAt(10*time.Second)))
}

// TestANilRotationClockReadsTheWallClock: a Proxy{} literal in a test has no
// clock, and it must read time.Now with no mark to hold.
func TestANilRotationClockReadsTheWallClock(t *testing.T) {
	t.Parallel()

	var clock *RotationClock

	before := time.Now()
	got := clock.Now()
	after := time.Now()

	assert.False(t, got.Before(before), "not before the call")
	assert.False(t, got.After(after), "not after it")
}

// TestTheZeroRotationClockIsAHighWaterClock: the fields are unexported, so
// &RotationClock{} is the one clock a library caller can build without
// NewRotationClock. It has no source, and must not panic on that: it reads
// time.Now and holds its mark.
func TestTheZeroRotationClockIsAHighWaterClock(t *testing.T) {
	t.Parallel()

	clock := &RotationClock{}

	var last time.Time

	for range 1000 {
		got := clock.Now()
		require.False(t, got.Before(last), "non-decreasing")

		last = got
	}

	before := time.Now()
	got := clock.Now()
	after := time.Now()

	assert.False(t, got.Before(before), "it follows the wall clock")
	assert.False(t, got.After(after))

	ahead := after.Add(time.Hour)
	clock.mark.Store(ahead.UnixNano())

	assert.True(t, clock.Now().Equal(ahead), "and holds a mark the wall clock has not reached")

	var onTheStack RotationClock

	assert.NotPanics(t, func() { onTheStack.Now() }, "a variable of the type works too")
}
