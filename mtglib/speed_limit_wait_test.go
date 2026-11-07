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
// between the two steps, and through afterWaitN, the one it calls after a
// refusal and before it decides whether to ask again. They set package
// variables, so none of them may run in parallel, and each restores the seams
// when it ends.

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

// installAfterWaitSeam is installWaitSeam for afterWaitN: each runs, with the
// 1-based call number and the refusal, every time a WaitN failed, and the count
// of those is returned. each may be nil.
func installAfterWaitSeam(t *testing.T, each func(call int, err error)) *atomic.Int32 {
	t.Helper()

	var calls atomic.Int32

	previous := afterWaitN
	afterWaitN = func(err error) {
		call := int(calls.Add(1))
		if call > waitSpinLimit {
			runtime.Goexit()
		}

		if each != nil {
			each(call, err)
		}
	}

	t.Cleanup(func() { afterWaitN = previous })

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
// refusal under a live context is retried: retrying every error would spin on
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

// Under a context with a deadline a refusal can be the deadline's, not a burst
// that shrank, and then it is still the caller's: here the bucket would need a
// second the context does not have. Retrying it as if it were a burst would go
// round until the backstop, or the deadline, ended it.
func TestWaitReturnsAnErrorThatIsNotAShrunkBurst(t *testing.T) {
	var s speedLimiter

	s.set(MinSpeedBytesPerSecond)

	// Far longer than anything this test does before its second request, so the
	// refusal is about the second the bucket needs and never about a deadline
	// that a stalled runner let pass.
	ctx, cancel := context.WithTimeout(t.Context(), 500*time.Millisecond)
	defer cancel()

	calls := installWaitSeam(t, nil)

	// Two bursts' worth. The first is in the bucket; the second is a second
	// away, and the context ends in 500 ms.
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

// The burst can change twice under one wait: lowered inside WaitN's window, so
// that it refuses the piece, and raised again before wait looks at the burst to
// decide what the refusal was. A wait that decides by comparing the piece with
// the burst it then sees finds the piece fits, takes the refusal for the
// caller's and ends the stream. With no deadline on the context and the context
// still live, the only thing WaitN can refuse is a burst, so there is nothing
// to compare.
func TestWaitSurvivesADoubleRerate(t *testing.T) {
	const (
		rateBytes    = 1_000_000
		shrunkBytes  = 400_000
		payloadBytes = 450_000
	)

	var s speedLimiter

	s.set(rateBytes)

	// Lowered before the request: it is refused for the burst, as it would be
	// by a re-rate that landed inside WaitN.
	installWaitSeam(t, func(call int) {
		if call == 1 {
			s.set(shrunkBytes)
		}
	})

	// Raised again before wait decides: the piece now fits the burst it sees.
	var refusal error

	refusals := installAfterWaitSeam(t, func(call int, err error) {
		if call == 1 {
			refusal = err

			s.set(rateBytes)
		}
	})

	returned, err := runWait(t, t.Context(), &s, payloadBytes)

	require.True(t, returned)
	require.Error(t, refusal, "the first request must have been refused for the burst")
	require.NoError(t, err, "a burst lowered and raised again under a wait must not end the stream")
	assert.Equal(t, int32(1), refusals.Load(), "the piece was refused once, and asked for again")
	assert.Equal(t, int64(rateBytes), s.bytesPerSecond())

	// The retry paid for the bytes. The bucket was clamped to the lowered burst,
	// 400,000, and 450,000 were charged against it, so what is left is only what
	// has refilled since; a retry that charged nothing would leave 400,000.
	tokens := s.limiter.Load().TokensAt(time.Now())
	assert.Less(t, tokens, float64(300_000), "the retried piece must be charged to the bucket")
}

// A context with a deadline can refuse a request for a reason that is not the
// burst: the bucket would need longer than the deadline allows. That refusal
// is the caller's and is returned at once, from the very first request, not
// asked for again until a backstop gives up. The context is still live when it
// is refused; it is the reservation that does not fit in it.
func TestWaitDeadlineRefusalIsStillReturned(t *testing.T) {
	var s speedLimiter

	s.set(MinSpeedBytesPerSecond)

	// Empty the bucket, and charge it two seconds more, so that the next burst's
	// worth is three seconds away: further than the deadline below by a second,
	// and the deadline itself long enough that a slow runner does not pass it
	// before the check. The burst is a second of the rate whatever the rate, so
	// only a debt puts the bucket further away than that.
	require.NoError(t, s.wait(t.Context(), MinSpeedBytesPerSecond))

	for range 2 {
		require.True(t, s.limiter.Load().ReserveN(time.Now(), MinSpeedBytesPerSecond).OK())
	}

	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()

	requests := installWaitSeam(t, nil)
	refusals := installAfterWaitSeam(t, nil)

	returned, err := runWait(t, ctx, &s, MinSpeedBytesPerSecond)

	require.True(t, returned)
	require.Error(t, err)
	require.NoError(t, ctx.Err(), "the deadline must not have passed: the refusal is about the reservation")
	assert.Equal(t, int32(1), requests.Load(), "a refusal that is not a shrunk burst must not be asked for again")
	assert.Equal(t, int32(1), refusals.Load())
}

// A wait that keeps being refused gives up. Here every request finds the burst
// one byte lower than the piece it read, and the context is live and has no
// deadline, so every refusal looks like a re-rate; nothing would end the wait
// but the bound on how often it asks again.
func TestWaitGivesUpAfterTheRetryBackstop(t *testing.T) {
	var s speedLimiter

	s.set(1000)

	limiter := s.limiter.Load()

	requests := installWaitSeam(t, func(int) {
		limiter.SetBurst(limiter.Burst() - 1)
	})
	refusals := installAfterWaitSeam(t, nil)

	returned, err := runWait(t, t.Context(), &s, 1000)

	require.True(t, returned, "wait kept asking again for ever")
	require.Error(t, err, "a wait refused over and over must end with the refusal")
	assert.Equal(t, int32(maxWaitRetries+1), requests.Load(), "the first request and then every retry the backstop allows")
	assert.Equal(t, int32(maxWaitRetries+1), refusals.Load())
}

// The time a wait is held to the cap is counted once for the whole wait, a
// retry in the middle of it included. The retry here comes after the first
// piece has slept for 100 ms, so a count that added the elapsed time again at
// the retry would overshoot the wait itself, and one that began again at the
// retry would lose the first piece's sleep.
func TestWaitCountsTheThrottleOnceAcrossARetry(t *testing.T) {
	var s speedLimiter

	s.set(1_000_000)

	limiter := s.limiter.Load()

	// A rate ten times the burst: a full burst takes 100 ms, not a second.
	limiter.SetLimit(rate.Limit(10_000_000))

	// Empty the bucket, so the first piece has to sleep. Nothing was held for
	// this, and nothing is counted for it.
	require.NoError(t, s.wait(t.Context(), 1_000_000))
	s.throttledNanos.Store(0)

	// The second request is the one that finds the burst lowered: after the
	// first piece's sleep, so after a good part of the whole wait.
	installWaitSeam(t, func(call int) {
		if call == 2 {
			limiter.SetBurst(400_000)
		}
	})

	started := time.Now()
	returned, err := runWait(t, t.Context(), &s, 1_500_000)
	elapsed := time.Since(started)

	require.True(t, returned)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, elapsed, 120*time.Millisecond, "the bucket was empty: a full burst alone is 100 ms")

	throttled := time.Duration(s.throttledNanos.Load())
	assert.LessOrEqual(t, throttled, elapsed, "the time held must be counted once, not again at the retry")
	assert.GreaterOrEqual(t, throttled, elapsed/2, "the first piece's sleep must still be in the count after the retry")
}

// A chunk is never more than it was asked for, because the callers slice a
// buffer by it. clampChunk is the decision with the burst already read, so it
// is tested without a bucket and without a race.
func TestClampChunk(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name     string
		n, burst int
		want     int
	}{
		{name: "fits in the burst", n: 100, burst: 1000, want: 100},
		{name: "exactly the burst", n: 1000, burst: 1000, want: 1000},
		{name: "more than the burst", n: 5000, burst: 1000, want: 1000},
		{name: "a burst of one", n: 5000, burst: 1, want: 1},
		{name: "nothing asked", n: 0, burst: 1000, want: 0},
		{name: "no burst bounds nothing", n: 5000, burst: 0, want: 5000},
		{name: "a negative burst bounds nothing", n: 5000, burst: -1, want: 5000},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tc.want, clampChunk(tc.n, tc.burst))
		})
	}

	t.Run("never more than asked, never negative", func(t *testing.T) {
		t.Parallel()

		for _, n := range []int{0, 1, 2, 999, 1000, 1001, 1 << 20, maxSpeedBurst, maxSpeedBurst + 1} {
			for _, burst := range []int{-1, 0, 1, 2, 999, 1000, 1001, 1 << 20, maxSpeedBurst} {
				got := clampChunk(n, burst)

				assert.GreaterOrEqual(t, got, 0, "n=%d burst=%d", n, burst)
				assert.LessOrEqual(t, got, n, "n=%d burst=%d", n, burst)
			}
		}
	})
}

// The same property through the bucket, while a re-rate keeps raising and
// lowering the burst under it. chunk used to read the burst twice, once to
// compare and once to return, and a burst raised between the two reads handed
// back more than was asked for, which the relay then sliced its buffer by and
// crashed the process. The window is nanoseconds wide, so this stress test is
// a net, not a proof; TestClampChunk is the proof of the decision itself.
func TestChunkNeverReturnsMoreThanItWasAsked(t *testing.T) {
	const (
		asked      = 5000
		iterations = 1_000_000
	)

	var s speedLimiter

	s.set(1000)

	var stop atomic.Bool

	rerated := make(chan struct{})

	go func() {
		defer close(rerated)

		for !stop.Load() {
			// Below what is asked, then far above it: the two reads of a burst
			// that straddle the second are the ones that disagree.
			s.set(1000)
			s.set(1 << 20)
		}
	}()

	defer func() {
		stop.Store(true)
		<-rerated
	}()

	for range iterations {
		got := s.chunk(asked)

		if got < 0 || got > asked {
			t.Fatalf("chunk(%d) returned %d: more than it was asked for, or negative", asked, got)
		}
	}
}
