package mtglib

import (
	"context"
	"math"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/time/rate"
)

// The numbers these tests charge are chosen so that every delay the rate
// package computes is exact: it divides tokens by the rate in floating point
// and truncates to nanoseconds, so a rate and a burst that are powers of two
// give delays that are whole nanoseconds, and an exact `waited` can be asserted
// rather than a band.
const (
	// testAddrRate is 1 MiB/s.
	testAddrRate = 1 << 20

	// testAddrBurst is 64 KiB, the floor of every per-address burst.
	testAddrBurst = 64 << 10

	// testAddrPiece is what one drained burst costs at testAddrRate: 62.5 ms.
	testAddrPiece = time.Second / 16
)

// fakeAddrClockBase is where every fake clock starts: 2001, years before any
// real now. A limiter that is handed time.Now behind the fake clock's back
// therefore sees years pass, refills to a full bucket, and the next exact delay
// a test asserts comes out wrong. A base near the real now would hide that.
var fakeAddrClockBase = time.Unix(1_000_000_000, 0)

// fakeAddrClock is a clock the test moves. Its sleep never blocks: it moves the
// time on by what was asked, unless the context has ended, in which case no
// time passes and the context's error comes back -- the sleep was cut short.
//
// hook, when set, runs inside every sleep with the 1-based call number and the
// duration asked for, before the sleep decides. That is the window of a wait in
// flight, and the tests use it to re-rate, replace or cancel in exactly that
// window, on the waiting goroutine, without a race in the test itself.
type fakeAddrClock struct {
	mu    sync.Mutex
	now   time.Time
	slept []time.Duration
	calls int
	hook  func(call int, d time.Duration)
}

func newFakeAddrClock() *fakeAddrClock {
	return &fakeAddrClock{now: fakeAddrClockBase}
}

func (f *fakeAddrClock) clock() addrClock {
	return addrClock{now: f.read, sleep: f.sleep}
}

func (f *fakeAddrClock) read() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()

	return f.now
}

func (f *fakeAddrClock) sleep(ctx context.Context, d time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	f.mu.Lock()
	f.calls++
	call, hook := f.calls, f.hook
	f.mu.Unlock()

	if hook != nil {
		hook(call, d)
	}

	if err := ctx.Err(); err != nil {
		return err
	}

	f.mu.Lock()
	f.now = f.now.Add(d)
	f.slept = append(f.slept, d)
	f.mu.Unlock()

	return nil
}

// advance moves the time on outside any wait, as the world does between two.
func (f *fakeAddrClock) advance(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.now = f.now.Add(d)
}

// sleeps is every sleep that ran to its end, in order.
func (f *fakeAddrClock) sleeps() []time.Duration {
	f.mu.Lock()
	defer f.mu.Unlock()

	return append([]time.Duration(nil), f.slept...)
}

// elapsed is how far the clock has moved since it started.
func (f *fakeAddrClock) elapsed() time.Duration {
	return f.read().Sub(fakeAddrClockBase)
}

// installedLimiter is the rate.Limiter l holds, failing the test cleanly when
// there is none instead of letting a nil dereference end the binary.
func installedLimiter(t *testing.T, l *addrLimiter) *rate.Limiter {
	t.Helper()

	current := l.limiter.Load()
	require.NotNil(t, current, "a limiter must be installed")

	return current
}

// drainAddrLimiter takes the full bucket a new limiter starts with, so that the
// next wait has to sleep for every byte it asks for.
func drainAddrLimiter(t *testing.T, l *addrLimiter) {
	t.Helper()

	waited, err := l.wait(t.Context(), installedLimiter(t, l).Burst())
	require.NoError(t, err)
	require.Zero(t, waited, "a new limiter starts with a full bucket")
}

// An address with no limit installed is the common case, and it must cost the
// data path nothing: no cut, so an unlimited user still writes once, and no
// wait, whatever the context.
func TestAnUnlimitedAddrLimiterNeitherCutsNorWaits(t *testing.T) {
	t.Parallel()

	check := func(t *testing.T, l *addrLimiter) {
		t.Helper()

		assert.Nil(t, l.limiter.Load())
		assert.Equal(t, 1<<30, l.chunk(1<<30), "unlimited must not cut a write")
		assert.Equal(t, 1, l.chunk(1))
		assert.Equal(t, 0, l.chunk(0))
		assert.Zero(t, l.bytesPerSecond())

		waited, err := l.wait(t.Context(), 1<<30)
		require.NoError(t, err, "unlimited never fails a wait")
		assert.Zero(t, waited)

		done, cancel := context.WithCancel(t.Context())
		cancel()

		waited, err = l.wait(done, 1<<30)
		require.NoError(t, err, "unlimited never fails a wait, even on a context that is done")
		assert.Zero(t, waited)
	}

	// The spec embeds the limiter by value in a table entry, so the zero value
	// is the one most of them will be.
	t.Run("the zero value", func(t *testing.T) {
		t.Parallel()

		var l addrLimiter

		check(t, &l)
	})

	t.Run("never installed", func(t *testing.T) {
		t.Parallel()

		clock := newFakeAddrClock()
		l := newAddrLimiter(clock.clock())

		check(t, l)
		assert.Empty(t, clock.sleeps())
	})

	for _, tc := range []struct {
		name      string
		unlimited int64
	}{
		{name: "installed and then lifted by zero", unlimited: 0},
		{name: "installed and then lifted by a negative", unlimited: -1},
		{name: "installed and then lifted by the smallest int64", unlimited: math.MinInt64},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			clock := newFakeAddrClock()
			l := newAddrLimiter(clock.clock())

			l.install(testAddrRate, testAddrBurst)
			drainAddrLimiter(t, l)
			l.install(tc.unlimited, testAddrBurst)

			check(t, l)
			assert.Empty(t, clock.sleeps())
		})
	}
}

// A wait sleeps for exactly the delay its reservations were given, on the
// injected clock, and reports what it slept. The bucket starts full, refills
// at the rate while the clock moves, and is paid in pieces of at most the
// burst.
func TestWaitSleepsTheReservationDelay(t *testing.T) {
	t.Parallel()

	setup := func() (*fakeAddrClock, *addrLimiter) {
		clock := newFakeAddrClock()
		l := newAddrLimiter(clock.clock())
		l.install(testAddrRate, testAddrBurst)

		return clock, l
	}

	t.Run("the first burst is in the bucket", func(t *testing.T) {
		t.Parallel()

		clock, l := setup()

		waited, err := l.wait(t.Context(), testAddrBurst)
		require.NoError(t, err)
		assert.Zero(t, waited)
		assert.Empty(t, clock.sleeps())
	})

	t.Run("a drained bucket", func(t *testing.T) {
		t.Parallel()

		clock, l := setup()
		drainAddrLimiter(t, l)

		waited, err := l.wait(t.Context(), testAddrBurst/2)
		require.NoError(t, err)
		assert.Equal(t, testAddrPiece/2, waited, "32 KiB at 1 MiB/s is 31.25 ms")
		assert.Equal(t, []time.Duration{testAddrPiece / 2}, clock.sleeps())
		assert.Equal(t, waited, clock.elapsed(), "waited is what the clock was asked to sleep")
	})

	// Two and a half bursts: two full pieces and a half one, each slept for in
	// turn, and the time each sleep moved the clock refills nothing extra.
	t.Run("paid in pieces of the burst", func(t *testing.T) {
		t.Parallel()

		clock, l := setup()
		drainAddrLimiter(t, l)

		waited, err := l.wait(t.Context(), 2*testAddrBurst+testAddrBurst/2)
		require.NoError(t, err)
		assert.Equal(t, []time.Duration{testAddrPiece, testAddrPiece, testAddrPiece / 2}, clock.sleeps())
		assert.Equal(t, 2*testAddrPiece+testAddrPiece/2, waited)
		assert.Equal(t, waited, clock.elapsed())
	})

	// Time that passed between two waits is in the bucket: half a burst's time
	// refilled half the burst, so a full burst costs only the other half.
	t.Run("time between waits refills the bucket", func(t *testing.T) {
		t.Parallel()

		clock, l := setup()
		drainAddrLimiter(t, l)
		clock.advance(testAddrPiece / 2)

		waited, err := l.wait(t.Context(), testAddrBurst)
		require.NoError(t, err)
		assert.Equal(t, testAddrPiece/2, waited)
	})
}

// setRate re-rates a limiter that exists and does nothing else: it never makes
// an unlimited address limited, it never turns a limited one unlimited by
// handing the bucket a zero, and it never touches the burst a wait in flight
// sized its pieces by.
func TestSetRateNeverCreatesNorZeroes(t *testing.T) {
	t.Parallel()

	t.Run("nil stays nil", func(t *testing.T) {
		t.Parallel()

		var zero addrLimiter

		clock := newFakeAddrClock()
		never := newAddrLimiter(clock.clock())

		lifted := newAddrLimiter(clock.clock())
		lifted.install(testAddrRate, testAddrBurst)
		lifted.install(0, testAddrBurst)

		for _, l := range []*addrLimiter{&zero, never, lifted} {
			l.setRate(testAddrRate)

			assert.Nil(t, l.limiter.Load(), "setRate must never create a limiter")
			assert.Zero(t, l.bytesPerSecond())
			assert.Equal(t, 1<<20, l.chunk(1<<20))
		}
	})

	// A zero rate handed to the rate package is a bucket that never refills,
	// and a zero read back means unlimited everywhere else in this package: the
	// floor is one byte a second, a rate that is still a limit.
	t.Run("zero and below become one byte a second", func(t *testing.T) {
		t.Parallel()

		for _, bytesPerSecond := range []int64{0, -1, math.MinInt64} {
			clock := newFakeAddrClock()
			l := newAddrLimiter(clock.clock())
			l.install(testAddrRate, testAddrBurst)

			l.setRate(bytesPerSecond)

			installedLimiter(t, l)
			assert.Equal(t, int64(1), l.bytesPerSecond(), "setRate(%d)", bytesPerSecond)
			assert.Equal(t, rate.Limit(1), l.limiter.Load().Limit(), "setRate(%d)", bytesPerSecond)
		}
	})

	t.Run("the object and its burst are kept", func(t *testing.T) {
		t.Parallel()

		clock := newFakeAddrClock()
		l := newAddrLimiter(clock.clock())
		l.install(testAddrRate, testAddrBurst)

		installed := installedLimiter(t, l)

		for _, bytesPerSecond := range []int64{1, 8_000, testAddrRate, 100 << 20, 1 << 30} {
			l.setRate(bytesPerSecond)

			assert.Same(t, installed, l.limiter.Load(), "setRate re-rates in place: setRate(%d)", bytesPerSecond)
			assert.Equal(t, testAddrBurst, installed.Burst(), "the burst is fixed: setRate(%d)", bytesPerSecond)
			assert.Equal(t, bytesPerSecond, l.bytesPerSecond())
		}
	})
}

// A re-rate takes effect at the injected clock's now. The time before it is
// charged at the old rate and the time after it at the new one; a re-rate that
// reads time.Now instead sees years pass behind the fake clock and hands the
// address a full bucket it never earned.
func TestSetRateReratesOnTheInjectedClock(t *testing.T) {
	t.Parallel()

	clock := newFakeAddrClock()
	l := newAddrLimiter(clock.clock())
	l.install(testAddrRate, testAddrBurst)
	drainAddrLimiter(t, l)

	// Half a burst refills at 1 MiB/s, then the rate halves.
	clock.advance(testAddrPiece / 2)
	l.setRate(testAddrRate / 2)

	assert.InDelta(t, float64(testAddrBurst/2), installedLimiter(t, l).TokensAt(clock.read()), 0,
		"the time before the re-rate is charged at the old rate, and only that")

	// The other half burst at 512 KiB/s: 62.5 ms.
	waited, err := l.wait(t.Context(), testAddrBurst)
	require.NoError(t, err)
	assert.Equal(t, testAddrPiece, waited)
}

// The burst is chosen when the limiter object is made and never changed after:
// a wait sizes its pieces by it, and a burst lowered under a piece makes the
// rate package refuse the piece, which ends the stream. setRate changes the
// rate only; a burst that must change gets a new object from install.
func TestTheBurstNeverShrinksUnderAWaiter(t *testing.T) {
	// Deterministic: the re-rate lands on the waiting goroutine, in the sleep
	// between the wait's first piece and its second, to a rate whose one-second
	// or one-twentieth burst would both be below the piece.
	t.Run("a re-rate between two pieces", func(t *testing.T) {
		t.Parallel()

		const (
			burst = 256 << 10
			slow  = 64 << 10
		)

		clock := newFakeAddrClock()
		l := newAddrLimiter(clock.clock())
		l.install(testAddrRate, burst)
		drainAddrLimiter(t, l)

		clock.hook = func(call int, _ time.Duration) {
			if call == 1 {
				l.setRate(slow)
			}
		}

		waited, err := l.wait(t.Context(), 2*burst)
		require.NoError(t, err, "a re-rate under a wait must not end the stream")
		assert.Equal(t, burst, installedLimiter(t, l).Burst())

		// The first piece was reserved at 1 MiB/s: 256 KiB is 250 ms. The re-rate
		// came at the start of that sleep, so the debt was repaid at 64 KiB/s:
		// 16 KiB came back in the 250 ms, and the second piece found 496 KiB
		// owed, which is 7.75 s at 64 KiB/s.
		assert.Equal(t, []time.Duration{250 * time.Millisecond, 7750 * time.Millisecond}, clock.sleeps())
		assert.Equal(t, 8*time.Second, waited)
	})

	// The net: real clock, many waiters, a goroutine re-rating as fast as it
	// can. The rates stay high so that the test is bounded by bytes, not by a
	// reservation made at a crawl (a reservation keeps the delay it was given).
	t.Run("many waiters while the rate is hammered", func(t *testing.T) {
		const (
			burst   = 128 << 10
			waiters = 16
			waits   = 8
			slow    = 32 << 20
			fast    = 128 << 20
		)

		var l addrLimiter

		l.install(fast, burst)

		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()

		var (
			stop    atomic.Bool
			rerates atomic.Int64
			changed atomic.Int64
			hammer  sync.WaitGroup
			waiting sync.WaitGroup
		)

		hammer.Go(func() {
			for i := 0; !stop.Load(); i++ {
				bytesPerSecond := int64(slow)
				if i%2 == 1 {
					bytesPerSecond = fast
				}

				l.setRate(bytesPerSecond)
				rerates.Add(1)

				if current := l.limiter.Load(); current == nil || current.Burst() != burst {
					changed.Add(1)
				}
			}
		})

		errs := make(chan error, waiters)

		for w := range waiters {
			waiting.Go(func() {
				for i := range waits {
					// A full burst, and two bursts and a byte: one piece and three.
					n := burst
					if (w+i)%2 == 1 {
						n = 2*burst + 1
					}

					if _, err := l.wait(ctx, n); err != nil {
						errs <- err

						return
					}
				}
			})
		}

		finished := make(chan struct{})

		go func() {
			waiting.Wait()
			close(finished)
		}()

		started := time.Now()

		select {
		case <-finished:
		case <-time.After(10 * time.Second):
			// Release every sleeper so that nothing outlives the test.
			cancel()
			<-finished
			t.Error("the waiters did not finish in 10 s")
		}

		elapsed := time.Since(started)

		stop.Store(true)
		hammer.Wait()
		close(errs)

		for err := range errs {
			t.Errorf("a waiter failed under a re-rate: %v", err)
		}

		assert.Positive(t, rerates.Load(), "the rate must have been hammered during the waits")
		assert.Zero(t, changed.Load(), "the burst must never change under a re-rate")
		assert.Equal(t, burst, installedLimiter(t, &l).Burst())
		t.Logf("%d waits of up to %d bytes in %v under %d re-rates", waiters*waits, 2*burst+1, elapsed, rerates.Load())
	})
}

// A burst that must change gets a new limiter object, and a wait that is in
// flight keeps the one it loaded: it finishes on the old rate and the old
// burst, and the new object is not charged for it.
func TestInstallReplacesTheObjectAndAnInFlightWaitFinishes(t *testing.T) {
	t.Parallel()

	const (
		oldBurst = 128 << 10
		newRate  = 64 << 10
		newBurst = 64 << 10
	)

	t.Run("replaced by a smaller burst", func(t *testing.T) {
		t.Parallel()

		clock := newFakeAddrClock()
		l := newAddrLimiter(clock.clock())
		l.install(testAddrRate, oldBurst)
		drainAddrLimiter(t, l)

		old := installedLimiter(t, l)

		var replacement *rate.Limiter

		clock.hook = func(call int, _ time.Duration) {
			if call == 1 {
				l.install(newRate, newBurst)
				replacement = l.limiter.Load()
			}
		}

		waited, err := l.wait(t.Context(), 2*oldBurst)
		require.NoError(t, err, "a wait in flight must finish on the limiter it loaded")

		// Two pieces of 128 KiB at the old 1 MiB/s: 125 ms each. On the new
		// limiter the second piece would not even fit the burst.
		assert.Equal(t, 250*time.Millisecond, waited)

		require.NotNil(t, replacement)
		assert.NotSame(t, old, replacement, "install must make a new object, never change the old one")
		assert.Same(t, replacement, l.limiter.Load())
		assert.Equal(t, oldBurst, old.Burst())
		assert.Equal(t, newBurst, replacement.Burst())
		assert.Equal(t, int64(newRate), l.bytesPerSecond())
		assert.InDelta(t, float64(newBurst), replacement.TokensAt(clock.read()), 0,
			"the new limiter starts full and was never charged for the old wait")
	})

	t.Run("replaced by unlimited", func(t *testing.T) {
		t.Parallel()

		clock := newFakeAddrClock()
		l := newAddrLimiter(clock.clock())
		l.install(testAddrRate, oldBurst)
		drainAddrLimiter(t, l)

		clock.hook = func(call int, _ time.Duration) {
			if call == 1 {
				l.install(0, 0)
			}
		}

		waited, err := l.wait(t.Context(), 2*oldBurst)
		require.NoError(t, err)
		assert.Equal(t, 250*time.Millisecond, waited)
		assert.Nil(t, l.limiter.Load())
	})
}

// A wait that its context ends in the middle of a sleep gives back the tokens
// it reserved and did not use, so the address is not charged for bytes it never
// moved, and reports only the sleeps that ran to their end.
func TestCancelledSleepRefundsItsReservation(t *testing.T) {
	t.Parallel()

	t.Run("the second piece is refunded", func(t *testing.T) {
		t.Parallel()

		clock := newFakeAddrClock()
		l := newAddrLimiter(clock.clock())
		l.install(testAddrRate, testAddrBurst)
		drainAddrLimiter(t, l)

		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()

		clock.hook = func(call int, _ time.Duration) {
			if call == 2 {
				cancel()
			}
		}

		waited, err := l.wait(ctx, 2*testAddrBurst)
		require.ErrorIs(t, err, context.Canceled)
		assert.Equal(t, testAddrPiece, waited, "only the first piece's sleep ran to its end")

		// The first piece was paid; the second was reserved and refunded, so the
		// bucket is empty, not a burst in debt.
		assert.InDelta(t, 0, installedLimiter(t, l).TokensAt(clock.read()), 0)

		clock.hook = nil

		waited, err = l.wait(t.Context(), testAddrBurst)
		require.NoError(t, err)
		assert.Equal(t, testAddrPiece, waited, "the next wait must not pay for the refunded piece")
	})

	// A full bucket would grant the bytes without a sleep, so a wait that
	// reserved first would never notice the context. It must not reserve at all.
	t.Run("a context done before the wait reserves nothing", func(t *testing.T) {
		t.Parallel()

		clock := newFakeAddrClock()
		l := newAddrLimiter(clock.clock())
		l.install(testAddrRate, testAddrBurst)

		ctx, cancel := context.WithCancel(t.Context())
		cancel()

		waited, err := l.wait(ctx, testAddrBurst)
		require.ErrorIs(t, err, context.Canceled)
		assert.Zero(t, waited)
		assert.InDelta(t, float64(testAddrBurst), installedLimiter(t, l).TokensAt(clock.read()), 0)
	})
}

// One read or write is never larger than the burst, so it is never refused for
// being larger than the bucket; and the cut is the burst the object was made
// with, whatever the rate does.
func TestChunkCutsToTheBurst(t *testing.T) {
	t.Parallel()

	clock := newFakeAddrClock()
	l := newAddrLimiter(clock.clock())
	l.install(testAddrRate, testAddrBurst)

	for _, tc := range []struct{ n, want int }{
		{n: 0, want: 0},
		{n: 100, want: 100},
		{n: testAddrBurst, want: testAddrBurst},
		{n: testAddrBurst + 1, want: testAddrBurst},
		{n: 1 << 30, want: testAddrBurst},
	} {
		assert.Equal(t, tc.want, l.chunk(tc.n), "chunk(%d)", tc.n)
	}

	l.setRate(1)
	assert.Equal(t, testAddrBurst, l.chunk(1<<30), "a re-rate must not change the cut")

	l.setRate(1 << 30)
	assert.Equal(t, testAddrBurst, l.chunk(1<<30), "a re-rate must not change the cut")

	l.install(testAddrRate, maxAddrBurst)
	assert.Equal(t, maxAddrBurst, l.chunk(1<<30), "a new object cuts at its own burst")

	l.install(0, maxAddrBurst)
	assert.Equal(t, 1<<30, l.chunk(1<<30), "unlimited does not cut")
}

// A limiter whose burst is nothing cannot be paid in pieces: pieces of nothing
// never add up to n. install never builds one, but wait must return rather
// than go round for ever if one is ever stored.
func TestAnAddrLimiterWithNoBurstReturnsInsteadOfSpinning(t *testing.T) {
	t.Parallel()

	for _, burst := range []int{0, -1} {
		clock := newFakeAddrClock()
		l := newAddrLimiter(clock.clock())
		l.limiter.Store(rate.NewLimiter(rate.Limit(1000), burst))

		returned := make(chan error, 1)

		go func() {
			_, err := l.wait(t.Context(), 10)
			returned <- err
		}()

		select {
		case err := <-returned:
			require.Error(t, err, "burst %d", burst)
		case <-time.After(5 * time.Second):
			t.Fatalf("wait spun on a limiter with burst %d", burst)
		}
	}
}

// The zero clock is the real one: time.Now and a timer that the context can
// cut short. This is the clock every limiter outside a test runs on.
func TestTheZeroAddrClockIsTheRealClock(t *testing.T) {
	t.Parallel()

	// 64 KiB at 256 KiB/s: 250 ms to refill, so a slow runner has room before
	// the bucket would be full again between the two waits.
	const (
		slowRate = 256 << 10
		refill   = 250 * time.Millisecond
	)

	var l addrLimiter

	l.install(slowRate, testAddrBurst)
	drainAddrLimiter(t, &l)

	started := time.Now()
	waited, err := l.wait(t.Context(), testAddrBurst)
	elapsed := time.Since(started)

	require.NoError(t, err)
	assert.Positive(t, waited, "a drained bucket must be slept for")
	assert.LessOrEqual(t, waited, refill)
	assert.GreaterOrEqual(t, elapsed, waited, "the real sleep lasts at least what it was asked")

	// The bucket is empty again; a context that ends long before the next refill
	// cuts the real sleep short and reports nothing slept.
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Millisecond)
	defer cancel()

	started = time.Now()
	waited, err = l.wait(ctx, testAddrBurst)
	elapsed = time.Since(started)

	require.ErrorIs(t, err, context.DeadlineExceeded)
	assert.Zero(t, waited)
	assert.Less(t, elapsed, refill*4/5, "the context must cut the sleep short")
}

// The bursts: a twentieth of a second of the rate, never under 64 KiB and
// never over 4 MiB, and the floor for anything that is not a positive rate.
func TestFairBurstAndCeilingBurstClamps(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name  string
		input int64
		want  int
	}{
		{name: "the smallest int64", input: math.MinInt64, want: 64 << 10},
		{name: "negative", input: -1, want: 64 << 10},
		{name: "zero", input: 0, want: 64 << 10},
		{name: "one", input: 1, want: 64 << 10},
		{name: "the minimum speed", input: MinSpeedBytesPerSecond, want: 64 << 10},
		{name: "just under the floor", input: 20 * (64<<10 - 1), want: 64 << 10},
		{name: "at the floor", input: 20 * 64 << 10, want: 64 << 10},
		{name: "just over the floor", input: 20 * (64<<10 + 1), want: 64<<10 + 1},
		{name: "between", input: 2_000_000, want: 100_000},
		{name: "a twentieth is floored", input: 2_000_019, want: 100_000},
		{name: "just under the cap", input: 20 * (4<<20 - 1), want: 4<<20 - 1},
		{name: "at the cap", input: 20 * 4 << 20, want: 4 << 20},
		{name: "just over the cap", input: 20 * (4<<20 + 1), want: 4 << 20},
		{name: "the largest int64", input: math.MaxInt64, want: 4 << 20},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tc.want, fairBurst(tc.input), "fairBurst(%d)", tc.input)
			assert.Equal(t, tc.want, ceilingBurst(tc.input), "ceilingBurst(%d)", tc.input)
		})
	}

	assert.Equal(t, 64<<10, minAddrBurst)
	assert.Equal(t, 4<<20, maxAddrBurst)
}
