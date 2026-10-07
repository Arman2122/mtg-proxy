package mtglib

import (
	"context"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"
)

// maxSpeedBurst caps the bucket's burst, and with it the largest single read
// or write, at 64 MiB. The burst is otherwise one second of the rate, and one
// second of a very fast rate does not fit in an int on the 32-bit builds.
const maxSpeedBurst = 64 << 20

// speedLimiter is one user's allowance: a token bucket every connection of
// that user, on every door, draws from. It lives in the user's runtime stats,
// beside the byte counters, because that is the one thing that survives a
// reload -- the secret set is swapped whole, and a bucket that was replaced
// with it would hand every user a fresh burst on every reload.
//
// The bucket only ever delays. It never buffers a byte: a read is held until
// what it read has been paid for, a write is held until what it is about to
// write has been. Backpressure therefore lands in the client's TCP window and
// the kernel does the rest, and the memory cost of throttling a user is zero.
//
// nil means unlimited, and the data path pays one atomic load to find out.
type speedLimiter struct {
	limiter atomic.Pointer[rate.Limiter]

	// throttledNanos is the time this user's connections have spent waiting
	// for the bucket. It is the honest measure of a cap: a cap nobody ever
	// waits for is not doing anything, and a user who waits most of the time
	// is one whose cap is the thing they are experiencing.
	throttledNanos atomic.Int64
}

// set installs a rate, or unlimited for zero. A bucket that already exists is
// re-rated in place, so the connections drawing from it slow down or speed up
// without being dropped. SetLimit and SetBurst are safe against a WaitN in
// flight for the bucket's own state, but not for a caller that sized a request
// from the burst before the re-rate: a lowered burst refuses a request above
// it, and wait is what re-asks in smaller pieces.
func (s *speedLimiter) set(bytesPerSecond int64) {
	if bytesPerSecond <= 0 {
		s.limiter.Store(nil)

		return
	}

	burst := int(min(bytesPerSecond, maxSpeedBurst))

	if current := s.limiter.Load(); current != nil {
		current.SetLimit(rate.Limit(bytesPerSecond))
		current.SetBurst(burst)

		return
	}

	s.limiter.Store(rate.NewLimiter(rate.Limit(bytesPerSecond), burst))
}

// chunk bounds one read or write to what the bucket can ever grant at once.
// Unlimited passes n through untouched, so the unthrottled path is one load
// and one comparison.
func (s *speedLimiter) chunk(n int) int {
	if current := s.limiter.Load(); current != nil && n > current.Burst() {
		return current.Burst()
	}

	return n
}

// beforeWaitN runs between wait reading the bucket's burst and asking the
// bucket for that many tokens, which is the one window in which a re-rate can
// shrink the burst under a wait. A no-op: a test uses it to re-rate the bucket
// in exactly that window. A variable so it can be replaced; a test that does
// must restore it and must not run in parallel.
var beforeWaitN = func() {}

// wait charges n bytes to the bucket, blocking until they are covered. The
// context ends the wait: the proxy shutting down must not leave a connection
// sleeping on a bucket, and neither must a user being disabled.
//
// n can exceed the burst when the bucket was re-rated smaller under a read
// already in flight; it is then paid in pieces rather than refused.
//
// The burst can also shrink between the read of it below and the request for
// that many tokens. The rate package refuses a request above the burst, and an
// error out of here ends the stream, so a re-rate must not become one: a piece
// that no longer fits is asked for again, smaller, from the burst as it is now.
// Nothing was charged for the refused piece, so nothing is paid twice.
func (s *speedLimiter) wait(ctx context.Context, n int) error {
	current := s.limiter.Load()
	if current == nil || n <= 0 {
		return nil
	}

	started := time.Now()
	defer func() { s.throttledNanos.Add(int64(time.Since(started))) }()

	for n > 0 {
		burst := current.Burst()
		if burst <= 0 {
			// Pieces of nothing never add up to n. Say so now, as the bucket does:
			// an error for a finite rate that can never grant a token, nothing for
			// an unbounded one that never delays. set builds neither.
			return current.WaitN(ctx, n) //nolint: wrapcheck // the caller reports it as the connection's own error
		}

		piece := min(n, burst)

		beforeWaitN()

		err := current.WaitN(ctx, piece)
		if err == nil {
			n -= piece

			continue
		}

		// A burst that shrank under this piece is the one error that is not the
		// caller's: the piece is too big for the bucket as it is now, so ask again
		// from the burst as it is now. It is told apart by the burst itself and
		// never by the error's text -- the rate package words this refusal two
		// ways -- and a done context is always the caller's. Each retry needs the
		// burst to be lower than what it read, so a retry loop does not spin.
		if ctx.Err() == nil && piece > current.Burst() {
			continue
		}

		return err //nolint: wrapcheck // the caller reports it as the connection's own error
	}

	return nil
}

// bytesPerSecond reports the current rate, 0 for unlimited. It is how the
// stats and the tests read the bucket back.
func (s *speedLimiter) bytesPerSecond() int64 {
	if current := s.limiter.Load(); current != nil {
		return int64(current.Limit())
	}

	return 0
}
