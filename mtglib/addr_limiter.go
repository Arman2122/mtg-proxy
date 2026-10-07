package mtglib

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"
)

const (
	// minAddrBurst is the smallest burst a per-address limiter is made with.
	// Below it a slow limit would cut the relay's reads and writes into slivers
	// that each pay a lock and a reservation, for no fairness anyone can see.
	minAddrBurst = 64 << 10

	// maxAddrBurst is the largest. The burst is what a limiter hands out before
	// it starts to delay, and a new or replaced limiter starts full, so this is
	// also the most one address can take at once past its share.
	maxAddrBurst = 4 << 20

	// addrBurstDivisor makes a burst a twentieth of a second of the rate it is
	// made for, between the two bounds above: enough to keep a fast address
	// moving in whole reads, small enough that a re-rate is felt within 50 ms.
	addrBurstDivisor = 20
)

// addrClock is the time a per-address limiter runs on. The zero value is the
// real clock: time.Now, and a timer that the context can cut short. A test
// injects its own, so that a reservation's delay is a number it can assert
// rather than a band it has to hope a busy runner stays inside.
//
// One clock serves every call on the limiter. The rate package's shorthands
// (SetLimit, Reserve, Allow, Wait) read time.Now behind the caller's back, and
// a bucket that is charged on one clock and re-rated on another refills or
// starves by however far apart the two clocks are.
type addrClock struct {
	now   func() time.Time
	sleep func(ctx context.Context, d time.Duration) error
}

// read is the clock's now.
func (c addrClock) read() time.Time {
	if c.now != nil {
		return c.now()
	}

	return time.Now()
}

// pause sleeps for d, or returns the context's error if the context ends first.
func (c addrClock) pause(ctx context.Context, d time.Duration) error {
	if c.sleep != nil {
		return c.sleep(ctx, d)
	}

	timer := time.NewTimer(d)
	defer timer.Stop()

	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err() //nolint: wrapcheck // the caller reports it as the connection's own error
	}
}

// addrLimiter is one source address's allowance inside a secret: a token
// bucket beside the user's speedLimiter, which it leaves alone. It is built so
// that the race speedLimiter.wait had to be hardened against cannot happen
// here: the burst is fixed when the bucket object is made, a re-rate changes
// the rate and nothing else, and a burst that must change gets a new object.
// A wait loads the object once and finishes on it, so the burst it sized its
// pieces by is the burst it is charged against, to the end.
//
// Like speedLimiter it only ever delays, never buffers, and nil means
// unlimited: the data path pays one atomic load to find out. The zero value is
// unlimited on the real clock, because the table embeds these by value.
type addrLimiter struct {
	limiter atomic.Pointer[rate.Limiter]

	// clock is set when the limiter is made and never changed, so reading it
	// needs no lock.
	clock addrClock
}

// newAddrLimiter makes an unlimited limiter on the given clock. The zero clock
// is the real one.
func newAddrLimiter(clock addrClock) *addrLimiter {
	return &addrLimiter{clock: clock}
}

// install puts a new bucket in place, or none -- unlimited -- for a rate that
// is not positive. It always makes a new object rather than changing the one
// there: a wait in flight holds the old one and finishes on it, at the old
// rate and against the old burst, and the new one starts full and uncharged.
// This is the only way a burst changes.
func (l *addrLimiter) install(bytesPerSecond int64, burst int) {
	if bytesPerSecond <= 0 {
		l.limiter.Store(nil)

		return
	}

	l.limiter.Store(rate.NewLimiter(rate.Limit(bytesPerSecond), burst))
}

// setRate re-rates the bucket in place, at the clock's now, so the streams
// drawing from it slow down or speed up without being dropped. It never makes
// a bucket: an address that is unlimited stays so until install says
// otherwise. It never hands the bucket a zero either -- a rate of nothing would
// read back as unlimited -- so anything below one byte a second is one. And it
// never touches the burst.
//
// Nothing orders a setRate against an install -- the fair-share ticker
// re-rates and a reload installs, each when it runs -- so a setRate can land on
// an object install has just replaced. It is lost, which is harmless: the new
// object runs at the rate install gave it until the next tick re-rates it, a
// second later at most.
func (l *addrLimiter) setRate(bytesPerSecond int64) {
	current := l.limiter.Load()
	if current == nil {
		return
	}

	current.SetLimitAt(l.clock.read(), rate.Limit(max(bytesPerSecond, 1)))
}

// chunk bounds one read or write to the burst, so that a wait for it is never
// refused for being larger than the bucket. Unlimited passes n through
// untouched: an unlimited user still writes once. One load and one read of a
// burst that cannot change, so the answer is never more than n.
func (l *addrLimiter) chunk(n int) int {
	if current := l.limiter.Load(); current != nil {
		return clampChunk(n, current.Burst())
	}

	return n
}

// wait charges n bytes to the bucket and sleeps until they are covered, and
// says how long it slept: the sum of the delays its reservations were given,
// which on an injected clock is exact. n above the burst is paid in pieces of
// the burst, each reserved at the clock's now and slept for before the next.
//
// The context ends the wait. A context already done reserves nothing -- a full
// bucket would otherwise grant the bytes without a sleep and never notice. A
// context that ends during a sleep gives the reservation back, so the address
// is not charged for bytes it never moved, and the wait reports only the
// sleeps that ran to their end.
func (l *addrLimiter) wait(ctx context.Context, n int) (waited time.Duration, err error) {
	current := l.limiter.Load()
	if current == nil || n <= 0 {
		return 0, nil
	}

	if err := ctx.Err(); err != nil {
		return 0, err //nolint: wrapcheck // the caller reports it as the connection's own error
	}

	// The burst is fixed for the object's life, so it is read once. A burst of
	// nothing cannot be paid in pieces: fairBurst and ceilingBurst never make
	// one, but a wait must not go round for ever if one is ever installed.
	burst := current.Burst()
	if burst <= 0 {
		return 0, fmt.Errorf("address limiter has no burst to pay %d bytes from", n)
	}

	for n > 0 {
		piece := min(n, burst)
		now := l.clock.read()

		reservation := current.ReserveN(now, piece)
		if !reservation.OK() {
			// Cannot happen while the burst is fixed and a piece is at most the
			// burst; refused rather than retried, so that nothing makes this spin.
			return waited, fmt.Errorf("address limiter refused %d bytes against a burst of %d", piece, burst)
		}

		if delay := reservation.DelayFrom(now); delay > 0 {
			if err := l.clock.pause(ctx, delay); err != nil {
				reservation.CancelAt(l.clock.read())

				return waited, err
			}

			waited += delay
		}

		n -= piece
	}

	return waited, nil
}

// bytesPerSecond reports the current rate, 0 for unlimited. setRate never
// stores a zero, so a 0 here always means no bucket.
func (l *addrLimiter) bytesPerSecond() int64 {
	if current := l.limiter.Load(); current != nil {
		return int64(current.Limit())
	}

	return 0
}

// fairBurst is the burst of a fair-share limiter, from the secret's configured
// total: the limiter is re-rated every tick, from a byte a second to the whole
// total, so its burst is sized by the one number that does not move.
func fairBurst(total int64) int {
	return addrBurst(total)
}

// ceilingBurst is the burst of a static per-address ceiling, from its rate.
func ceilingBurst(bytesPerSecond int64) int {
	return addrBurst(bytesPerSecond)
}

// addrBurst is a twentieth of bytesPerSecond, clamped to the per-address
// bounds. Anything that is not a positive rate gets the floor.
func addrBurst(bytesPerSecond int64) int {
	return int(min(max(bytesPerSecond/addrBurstDivisor, minAddrBurst), maxAddrBurst))
}
