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
// and one comparison. The burst is read once: the callers slice a buffer by what
// this returns, and a re-rate between two reads could hand back more than n.
func (s *speedLimiter) chunk(n int) int {
	if current := s.limiter.Load(); current != nil {
		return clampChunk(n, current.Burst())
	}

	return n
}

// beforeWaitN runs between wait reading the bucket's burst and asking the
// bucket for that many tokens, which is the one window in which a re-rate can
// shrink the burst under a wait. A no-op: a test uses it to re-rate the bucket
// in exactly that window. A variable so it can be replaced; a test that does
// must restore it and must not run in parallel.
var beforeWaitN = func() {}

// afterWaitN runs right after a WaitN that failed, before wait decides whether
// to ask again. A no-op, for the same reason and under the same rules as
// beforeWaitN: a test uses it to re-rate the bucket a second time, in the
// window between the refusal and the decision.
var afterWaitN = func(error) {}

// maxWaitRetries is how many times one wait asks again after a refusal. A
// re-rate that lowers the burst under a piece costs one retry, and it takes a
// re-rate in the microseconds of every attempt to cost sixteen, so the bound
// only ever ends a wait that cannot be explained by re-rating: a backstop
// against a loop, not a limit anyone should meet.
const maxWaitRetries = 16

// clampChunk is chunk's decision, apart from the bucket it reads: n, or the
// burst when n is more than the burst. The burst is a parameter, read once by
// the caller, because two reads of a burst that a re-rate can change between
// them can disagree and hand back more than n. A burst of nothing bounds
// nothing; wait is what says so.
func clampChunk(n, burst int) int {
	if burst > 0 && n > burst {
		return burst
	}

	return n
}

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

	// WaitN refuses a request for one of three reasons: it is above the burst,
	// the context is done, or the context has a deadline that the reservation
	// would pass. A context with no deadline has only the first two, so while it
	// is live every refusal is a burst, and the burst is not read again to find
	// out: a second re-rate can have put it back.
	_, deadlined := ctx.Deadline()
	retries := 0

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

		afterWaitN(err)

		// A burst that shrank under this piece is the one refusal that is not the
		// caller's: the piece is too big for the bucket as it is now, so ask again
		// from the burst as it is now. It is told apart by the context and never
		// by the error's text -- the rate package words this refusal two ways --
		// and a done context is always the caller's. Under a deadline the refusal
		// may be the deadline's, so the burst is compared as a last resort there.
		// The retries are bounded, so that nothing makes this loop spin.
		if ctx.Err() == nil && retries < maxWaitRetries && (!deadlined || piece > current.Burst()) {
			retries++

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
