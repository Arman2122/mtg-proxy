package mtglib

import (
	"context"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/time/rate"
)

// speedLimiter.wait reads the bucket's burst and then asks the bucket for that
// many tokens, and a re-rate can lower the burst between the two. These tests
// drive that window deterministically through beforeWaitN, the seam wait calls
// between the two steps. They set a package variable, so none of them may run
// in parallel, and each restores the seam when it ends.

// waitSpinLimit is how often a test may reach the seam before it concludes that
// wait is going round and round instead of returning. The seam then ends the
// goroutine it was called on, so a regression fails the test; it does not hang
// the binary or burn a core until the process exits.
const waitSpinLimit = 50

// installWaitSeam makes each run, with the 1-based call number, every time wait
// reaches the seam, and returns the count. each may be nil.
func installWaitSeam(t *testing.T, each func(call int)) *atomic.Int32 {
	t.Helper()

	var calls atomic.Int32

	previous := beforeWaitN
	beforeWaitN = func() {
		call := int(calls.Add(1))
		if call > waitSpinLimit {
			runtime.Goexit()
		}

		if each != nil {
			each(call)
		}
	}

	t.Cleanup(func() { beforeWaitN = previous })

	return &calls
}

// runWait runs s.wait on a goroutine of its own and reports whether it came
// back (false: the seam gave up on it, see waitSpinLimit) and what it returned.
func runWait(t *testing.T, ctx context.Context, s *speedLimiter, n int) (bool, error) {
	t.Helper()

	var (
		err      error
		returned bool
	)

	finished := make(chan struct{})

	go func() {
		defer close(finished)

		err = s.wait(ctx, n)
		returned = true
	}()

	select {
	case <-finished:
	case <-time.After(15 * time.Second):
		t.Fatal("wait neither returned nor reached the spin limit")
	}

	return returned, err
}

// The bug: a reload that lowers a speed re-derives the bucket's burst, and a
// wait that had already read the old, larger burst then asked for more tokens
// than the bucket can ever hold. The rate package refuses that with an error,
// the error came out of countingConn.Write, and the stream ended. A wait that
// finds its piece too big for the bucket it now sees must pay the rest in
// smaller pieces, and every byte of it.
func TestWaitSurvivesABurstShrunkUnderIt(t *testing.T) {
	const (
		rateBytes    = 1_000_000
		shrunkBytes  = 500_000
		payloadBytes = 700_000
	)

	var s speedLimiter

	s.set(rateBytes)

	// The first time wait is about to ask for 700,000 tokens, the bucket is
	// re-rated to 500,000 B/s and with it to a 500,000 burst.
	calls := installWaitSeam(t, func(call int) {
		if call == 1 {
			s.set(shrunkBytes)
		}
	})

	started := time.Now()
	returned, err := runWait(t, t.Context(), &s, payloadBytes)
	elapsed := time.Since(started)

	require.True(t, returned)
	require.NoError(t, err, "a bucket re-rated under a wait must not end the stream")
	assert.GreaterOrEqual(t, calls.Load(), int32(2), "the shrunk piece must have been asked for again")
	assert.Equal(t, int64(shrunkBytes), s.bytesPerSecond())

	// 500,000 bytes are in the re-rated bucket, so they pass at once; the other
	// 200,000 take 400 ms at 500,000 B/s. A wait that dropped the bytes it could
	// not pay for in one go would be done in microseconds.
	assert.GreaterOrEqual(t, elapsed, 300*time.Millisecond, "every byte must be charged to the bucket")
	assert.Less(t, elapsed, 5*time.Second)

	// The time held to the cap is counted once for the whole wait, retries and
	// all: never less than the sleep and never more than the wait itself.
	throttled := time.Duration(s.throttledNanos.Load())
	assert.GreaterOrEqual(t, throttled, 300*time.Millisecond)
	assert.LessOrEqual(t, throttled, elapsed)
}

// A context that is done ends the wait with an error, as it always did. Only a
// burst that shrank is retried: treating every error as retryable would spin on
// a cancelled context forever.
func TestWaitStillFailsWhenTheContextIsDone(t *testing.T) {
	t.Run("a done context", func(t *testing.T) {
		var s speedLimiter

		s.set(1 << 20)

		ctx, cancel := context.WithCancel(t.Context())
		cancel()

		calls := installWaitSeam(t, nil)

		returned, err := runWait(t, ctx, &s, 64<<10)

		require.True(t, returned, "wait kept going on a context that is done")
		require.ErrorIs(t, err, context.Canceled)
		assert.Equal(t, int32(1), calls.Load(), "a done context must not be retried")
	})

	// The two at once: the bucket shrinks under the wait and the context ends
	// with it. The caller is leaving, so the refusal is the answer, not a retry.
	t.Run("a done context and a shrunk burst", func(t *testing.T) {
		var s speedLimiter

		s.set(1 << 20)

		ctx, cancel := context.WithCancel(t.Context())

		calls := installWaitSeam(t, func(call int) {
			if call == 1 {
				s.set(64 << 10)
				cancel()
			}
		})

		returned, err := runWait(t, ctx, &s, 512<<10)

		require.True(t, returned, "wait kept going on a context that is done")
		require.Error(t, err)
		assert.Equal(t, int32(1), calls.Load(), "a done context must not be retried")
	})
}

// An error that is not a shrunk burst is still the caller's: here the bucket
// would need a second the context does not have. Retrying anything the rate
// package refuses, rather than only the burst, would go round until the
// deadline passed.
func TestWaitReturnsAnErrorThatIsNotAShrunkBurst(t *testing.T) {
	var s speedLimiter

	s.set(MinSpeedBytesPerSecond)

	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()

	calls := installWaitSeam(t, nil)

	// Two bursts' worth. The first is in the bucket; the second is a second
	// away, and the context ends in 100 ms.
	returned, err := runWait(t, ctx, &s, 2*MinSpeedBytesPerSecond)

	require.True(t, returned)
	require.Error(t, err)
	assert.Equal(t, int32(2), calls.Load(), "one request per piece: the refusal must not be retried")
}

// The behaviour that did not change: n above the burst is paid in pieces of
// the burst, one request each, with no retry and no error.
func TestWaitWithoutAShrinkIsUnchanged(t *testing.T) {
	const rateBytes = 1_000_000

	var s speedLimiter

	s.set(rateBytes)

	calls := installWaitSeam(t, nil)

	started := time.Now()
	returned, err := runWait(t, t.Context(), &s, 3*rateBytes/2)
	elapsed := time.Since(started)

	require.True(t, returned)
	require.NoError(t, err)
	assert.Equal(t, int32(2), calls.Load(), "a full burst and then the half: two requests, no retry")

	// The bucket starts full, so the first million pass at once and the other
	// half million take half a second.
	assert.GreaterOrEqual(t, elapsed, 400*time.Millisecond)
	assert.Less(t, elapsed, 5*time.Second)
	assert.Equal(t, int64(rateBytes), s.bytesPerSecond())
}

// A bucket with no burst cannot be paid in pieces of nothing: the loop would
// subtract zero for ever. set never builds one, but wait must not depend on
// that. A finite rate with no burst can never grant a token, which the bucket
// says as an error; an unbounded one never delays anything.
func TestWaitWithNoBurstReturnsInsteadOfSpinning(t *testing.T) {
	t.Run("a finite rate", func(t *testing.T) {
		var s speedLimiter

		s.limiter.Store(rate.NewLimiter(rate.Limit(1000), 0))

		installWaitSeam(t, nil)

		returned, err := runWait(t, t.Context(), &s, 10)

		require.True(t, returned, "wait spun on a bucket with no burst")
		require.Error(t, err)
	})

	t.Run("an unbounded rate", func(t *testing.T) {
		var s speedLimiter

		s.limiter.Store(rate.NewLimiter(rate.Inf, 0))

		installWaitSeam(t, nil)

		returned, err := runWait(t, t.Context(), &s, 10)

		require.True(t, returned, "wait spun on a bucket with no burst")
		require.NoError(t, err)
	})
}
