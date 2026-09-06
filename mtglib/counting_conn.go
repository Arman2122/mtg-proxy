package mtglib

import (
	"context"
	"errors"
	"sync/atomic"

	"github.com/Arman2122/mtg-proxy/essentials"
)

// errQuotaExhausted ends a stream at the byte that reaches the user's quota.
// The relay treats it like any other end of the connection.
var errQuotaExhausted = errors.New("quota exhausted")

// countingConn wraps the client side of a stream and is where a user's bytes
// become that user's: it counts them, charges them to the quota, holds them to
// the user's speed limit, and ends the stream at the quota's ceiling. The
// *secretStats pointer is resolved once at construction so the data path never
// takes a lock; the speed bucket and the ceiling are fields of the same
// struct, so both cost one atomic load when there is no limit.
type countingConn struct {
	essentials.Conn

	// ctx ends a wait for the bucket. It is the stream's own context, so the
	// proxy stopping, or the stream being torn down, never leaves a
	// connection asleep on a rate limiter.
	ctx context.Context
	st  *secretStats

	// stop ends the whole stream. The relay waits for both of its directions
	// to finish, and the direction that did not hit the ceiling is blocked
	// in a read that may never return, so ending one direction at the cap
	// would leave the stream open until the idle timeout. Nil in tests that
	// exercise the wrapper on its own.
	stop func()

	// cut records that this stream has been ended by the ceiling, so the
	// cutoff is counted once however many reads and writes -- from both
	// pumps of the relay -- find the quota gone.
	cut atomic.Bool
}

func newCountingConn(
	ctx context.Context, stop func(), conn essentials.Conn, stats *ProxyStats, secretName string,
) *countingConn {
	return &countingConn{Conn: conn, ctx: ctx, stop: stop, st: stats.getOrCreate(secretName)}
}

// allowance cuts a transfer of n bytes down to what the quota still permits.
// It is false when nothing is permitted. Cutting the transfer, rather than
// checking after it, is what makes the ceiling exact: the stream ends at the
// byte that reaches the quota, not a buffer past it.
func (c *countingConn) allowance(n int) (int, bool) {
	ceiling := c.st.quotaCeiling.Load()
	if ceiling <= 0 {
		return n, true
	}

	left := ceiling - c.st.quotaUsed.Load()
	if left <= 0 {
		return 0, false
	}

	if int64(n) > left {
		return int(left), true
	}

	return n, true
}

// charge bills n bytes and reports whether the quota is now reached.
func (c *countingConn) charge(n int) bool {
	used := c.st.quotaUsed.Add(int64(n))
	ceiling := c.st.quotaCeiling.Load()

	return ceiling > 0 && used >= ceiling
}

// exhausted is the exit at the ceiling: counted once per stream, and the
// stream is ended in both directions the first time.
func (c *countingConn) exhausted() error {
	if c.cut.CompareAndSwap(false, true) {
		c.st.quotaCutoffs.Add(1)

		if c.stop != nil {
			c.stop()
		}
	}

	return errQuotaExhausted
}

// Read is paid for after the fact. The bytes are already ours by the time we
// know how many there are; holding them until the bucket covers them is what
// shapes the sustained rate, and reading no more than the bucket can ever
// grant at once is what makes a single read always payable. The read is also
// cut to the quota's allowance, so what reaches the cap is delivered and
// nothing past it is read.
func (c *countingConn) Read(p []byte) (int, error) {
	limit, ok := c.allowance(c.st.speed.chunk(len(p)))
	if !ok {
		return 0, c.exhausted()
	}

	n, err := c.Conn.Read(p[:limit])
	if n > 0 {
		c.st.bytesIn.Add(int64(n))

		if c.charge(n) {
			return n, c.exhausted()
		}

		if waitErr := c.st.speed.wait(c.ctx, n); waitErr != nil && err == nil {
			err = waitErr
		}
	}

	return n, err
}

// Write is paid for in advance, one bucket-sized piece at a time, so a large
// write from Telegram reaches a capped user as a steady stream rather than a
// block followed by a stall. Unlimited is a single pass with a single write,
// exactly as before there was a limit. Each piece is cut to the quota's
// allowance, so the last piece ends exactly at the cap.
func (c *countingConn) Write(p []byte) (int, error) {
	var written int

	for len(p) > 0 {
		piece, ok := c.allowance(c.st.speed.chunk(len(p)))
		if !ok {
			return written, c.exhausted()
		}

		if err := c.st.speed.wait(c.ctx, piece); err != nil {
			return written, err
		}

		n, err := c.Conn.Write(p[:piece])
		if n > 0 {
			c.st.bytesOut.Add(int64(n))
		}

		written += n

		if err != nil {
			return written, err //nolint: wrapcheck // the underlying connection's own error
		}

		if c.charge(n) {
			return written, c.exhausted()
		}

		p = p[piece:]
	}

	return written, nil
}
