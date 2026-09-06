package mtglib

import (
	"context"

	"github.com/Arman2122/mtg-proxy/essentials"
)

// countingConn wraps the client side of a stream and is where a user's bytes
// become that user's: it counts them, charges them to the quota, and holds
// them to the user's speed limit. The *secretStats pointer is resolved once at
// construction so the data path never takes a lock, and the speed bucket is a
// field of the same struct, so throttling costs one atomic load when there is
// no limit.
type countingConn struct {
	essentials.Conn

	// ctx ends a wait for the bucket. It is the stream's own context, so the
	// proxy stopping, or the stream being torn down, never leaves a
	// connection asleep on a rate limiter.
	ctx context.Context
	st  *secretStats
}

func newCountingConn(ctx context.Context, conn essentials.Conn, stats *ProxyStats, secretName string) *countingConn {
	return &countingConn{Conn: conn, ctx: ctx, st: stats.getOrCreate(secretName)}
}

// Read is paid for after the fact. The bytes are already ours by the time we
// know how many there are; holding them until the bucket covers them is what
// shapes the sustained rate, and reading no more than the bucket can ever
// grant at once is what makes a single read always payable.
func (c *countingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p[:c.st.speed.chunk(len(p))])
	if n > 0 {
		c.st.bytesIn.Add(int64(n))
		c.st.quotaUsed.Add(int64(n))

		if waitErr := c.st.speed.wait(c.ctx, n); waitErr != nil && err == nil {
			err = waitErr
		}
	}

	return n, err
}

// Write is paid for in advance, one bucket-sized piece at a time, so a large
// write from Telegram reaches a capped user as a steady stream rather than a
// block followed by a stall. Unlimited is a single pass with a single write,
// exactly as before there was a limit.
func (c *countingConn) Write(p []byte) (int, error) {
	var written int

	for len(p) > 0 {
		piece := c.st.speed.chunk(len(p))

		if err := c.st.speed.wait(c.ctx, piece); err != nil {
			return written, err
		}

		n, err := c.Conn.Write(p[:piece])
		if n > 0 {
			c.st.bytesOut.Add(int64(n))
			c.st.quotaUsed.Add(int64(n))
		}

		written += n

		if err != nil {
			return written, err //nolint: wrapcheck // the underlying connection's own error
		}

		p = p[piece:]
	}

	return written, nil
}
