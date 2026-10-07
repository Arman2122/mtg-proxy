package mtglib

import (
	"context"
	"errors"
	"sync/atomic"
	"time"

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
//
// A stream whose address has an entry in the per-address table is also where
// that address's bytes become the address's: they are counted on the entry,
// and the address's own limiters are paid before the user's.
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

	// active, when set, is stamped with the second of the stream's latest
	// byte, for the per-address activity report. Nil in tests that exercise
	// the wrapper on its own.
	active *atomic.Int64

	// client is where the stream's per-address entry is kept. It is read on
	// every call rather than once: a reload's backfill can store an entry after
	// the wrapper is built. Nil, or holding nil, for a stream whose secret keeps
	// no entries, which costs the data path one load. Nil in tests that
	// exercise the wrapper on its own.
	client *atomic.Pointer[clientEntry]
}

func newCountingConn(
	ctx context.Context, stop func(), conn essentials.Conn, stats *ProxyStats, secretName string,
) *countingConn {
	return &countingConn{Conn: conn, ctx: ctx, stop: stop, st: stats.getOrCreate(secretName)}
}

// withActivity points the wrapper at the stamp it keeps current.
func (c *countingConn) withActivity(active *atomic.Int64) *countingConn {
	c.active = active

	return c
}

// withClient points the wrapper at where the stream's per-address entry is
// kept.
func (c *countingConn) withClient(client *atomic.Pointer[clientEntry]) *countingConn {
	c.client = client

	return c
}

// entry is the stream's per-address entry as it is now, or nil.
func (c *countingConn) entry() *clientEntry {
	if c.client == nil {
		return nil
	}

	return c.client.Load()
}

// markActive stamps the stream's latest byte to the second. The store is
// skipped while the second is unchanged, so the data path pays a clock read
// and a load per call, and a write once a second.
func (c *countingConn) markActive() {
	if c.active == nil {
		return
	}

	if now := time.Now().Unix(); c.active.Load() != now {
		c.active.Store(now)
	}
}

// markSeen is markActive for a stream with a per-address entry: the entry's
// lastSeen is stamped as well, and one clock reading serves both. It is the
// entry's clock -- the table's, the real one outside tests -- so that lastSeen
// agrees with the sweep that reads it, and production still reads the time
// once per call.
func (c *countingConn) markSeen(entry *clientEntry) {
	now := entry.clock.read()
	entry.seen(now)

	if c.active == nil {
		return
	}

	if second := now.Unix(); c.active.Load() != second {
		c.active.Store(second)
	}
}

// waitBoth charges n bytes to the combined bucket and then to the direction's
// own, so a byte is paid for under every cap that applies to it.
func (c *countingConn) waitBoth(combined, direction *speedLimiter, n int) error {
	if err := combined.wait(c.ctx, n); err != nil {
		return err
	}

	return direction.wait(c.ctx, n)
}

// payAddress charges n bytes to everything a transfer from an address with a
// limiter of its own pays, in this order: the address's ceiling, its combined
// fair share and then the direction's, and then the user's combined bucket and
// the direction's, exactly as a stream with no entry pays those. The address's
// own limiters come first. Bytes the address may not move yet must not sit in
// the user's shared bucket while it waits: the user's other streams, from other
// addresses, would be the ones held back for them.
//
// The waits at a fair share, and at a user's bucket a fair share divides, are
// what fair share's duty is made of, and each is bracketed by the tracker of
// that share. The ceiling's are not: an address its own ceiling holds back is
// not short of its share, and saying it was would hand it a bigger one at
// everyone else's cost.
func (c *countingConn) payAddress(
	entry *clientEntry, fair *addrLimiter, blocked *blockedTracker, direction *speedLimiter, n int,
) error {
	if err := c.waitAddress(entry, &entry.ceiling, nil, n); err != nil {
		return err
	}

	if err := c.waitAddress(entry, &entry.fairSpeed, &entry.blockedSpeed, n); err != nil {
		return err
	}

	if err := c.waitAddress(entry, fair, blocked, n); err != nil {
		return err
	}

	if err := c.waitShared(entry, &c.st.speed, &entry.fairSpeed, &entry.blockedSpeed, n); err != nil {
		return err
	}

	return c.waitShared(entry, direction, fair, blocked, n)
}

// waitAddress pays n bytes at one of the address's limiters, and adds what it
// slept to the user's throttled time and to the address's: the user's is a
// counter of its own, not a sum over entries, so the sweep forgetting an address
// never takes time back out of it. A wait that feeds the duty is bracketed by
// blocked, which is nil for the ceiling. Every way out of the wait leaves the
// tracker: a stream left counted as blocked would make its address look held
// back for ever after.
func (c *countingConn) waitAddress(entry *clientEntry, limiter *addrLimiter, blocked *blockedTracker, n int) error {
	if !limiter.installed() {
		return nil
	}

	if blocked != nil {
		blocked.enter(entry.clock.read())
	}

	waited, err := limiter.wait(c.ctx, n)

	if blocked != nil {
		blocked.leave(entry.clock.read())
	}

	if waited > 0 {
		c.st.clientThrottledNanos.Add(int64(waited))
		entry.throttledNanos.Add(int64(waited))
	}

	return err
}

// waitShared pays n bytes at one of the user's buckets, as a stream with no
// entry does. A wait there is part of the address's duty when the address has a
// fair share of that bucket: an address starved at the shared bucket, which
// divides its tokens per connection and not per address, is never held at its
// own share, which sits at or above what it gets, so without it a
// four-connection address would keep four shares to a one-connection address's
// one. The bucket's wait reports no time of its own, so it is bracketed here.
// Where the address has no fair share of the bucket there is no duty to feed,
// and nothing is bracketed.
func (c *countingConn) waitShared(
	entry *clientEntry, bucket *speedLimiter, fair *addrLimiter, blocked *blockedTracker, n int,
) error {
	if !fair.installed() || bucket.limiter.Load() == nil {
		return bucket.wait(c.ctx, n)
	}

	blocked.enter(entry.clock.read())
	err := bucket.wait(c.ctx, n)
	blocked.leave(entry.clock.read())

	return err
}

// pacesUpload says whether a read from this address pays a limiter of the
// address's own: the ceiling, or the combined or upload fair share. False for no
// entry, and for an entry with none installed -- an entry kept for its counts
// alone, which is a panel's case -- which then costs three loads and nothing
// more.
func (e *clientEntry) pacesUpload() bool {
	return e != nil && (e.ceiling.installed() || e.fairSpeed.installed() || e.fairUp.installed())
}

// pacesDownload is pacesUpload for a write.
func (e *clientEntry) pacesDownload() bool {
	return e != nil && (e.ceiling.installed() || e.fairSpeed.installed() || e.fairDown.installed())
}

// cutUpload bounds a read of n bytes to the bursts of the address's limiters a
// read pays, so that each wait is payable whole. A limiter with nothing
// installed cuts nothing.
func (e *clientEntry) cutUpload(n int) int {
	return e.fairUp.chunk(e.fairSpeed.chunk(e.ceiling.chunk(n)))
}

// cutDownload is cutUpload for a write.
func (e *clientEntry) cutDownload(n int) int {
	return e.fairDown.chunk(e.fairSpeed.chunk(e.ceiling.chunk(n)))
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
//
// A stream with a per-address entry reads through readAddress. A stream with
// none -- the common case -- runs the wrapper exactly as it was before entries
// existed, after the one load that finds no entry.
func (c *countingConn) Read(p []byte) (int, error) {
	if entry := c.entry(); entry != nil {
		return c.readAddress(entry, p)
	}

	limit, ok := c.allowance(c.st.speedUp.chunk(c.st.speed.chunk(len(p))))
	if !ok {
		return 0, c.exhausted()
	}

	n, err := c.Conn.Read(p[:limit])
	if n > 0 {
		c.st.bytesIn.Add(int64(n))
		c.markActive()

		if c.charge(n) {
			return n, c.exhausted()
		}

		if waitErr := c.waitBoth(&c.st.speed, &c.st.speedUp, n); waitErr != nil && err == nil {
			err = waitErr
		}
	}

	return n, err
}

// readAddress is Read for a stream with a per-address entry. The bytes are
// counted on the entry where they are counted on the user, before the quota can
// end the stream. An entry with no limiter installed -- one kept for its counts
// alone -- neither cuts the read nor adds a wait.
func (c *countingConn) readAddress(entry *clientEntry, p []byte) (int, error) {
	paced := entry.pacesUpload()

	limit := c.st.speedUp.chunk(c.st.speed.chunk(len(p)))
	if paced {
		limit = entry.cutUpload(limit)
	}

	limit, ok := c.allowance(limit)
	if !ok {
		return 0, c.exhausted()
	}

	n, err := c.Conn.Read(p[:limit])
	if n > 0 {
		c.st.bytesIn.Add(int64(n))
		entry.bytesIn.Add(int64(n))
		c.markSeen(entry)

		if c.charge(n) {
			return n, c.exhausted()
		}

		var waitErr error

		if paced {
			waitErr = c.payAddress(entry, &entry.fairUp, &entry.blockedUp, &c.st.speedUp, n)
		} else {
			waitErr = c.waitBoth(&c.st.speed, &c.st.speedUp, n)
		}

		if waitErr != nil && err == nil {
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
//
// A stream with a per-address entry writes through writeAddress; a stream with
// none runs the wrapper as it was, after the one load that finds no entry.
func (c *countingConn) Write(p []byte) (int, error) {
	if entry := c.entry(); entry != nil {
		return c.writeAddress(entry, p)
	}

	var written int

	for len(p) > 0 {
		piece, ok := c.allowance(c.st.speedDown.chunk(c.st.speed.chunk(len(p))))
		if !ok {
			return written, c.exhausted()
		}

		if err := c.waitBoth(&c.st.speed, &c.st.speedDown, piece); err != nil {
			return written, err
		}

		n, err := c.Conn.Write(p[:piece])
		if n > 0 {
			c.st.bytesOut.Add(int64(n))
			c.markActive()
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

// writeAddress is Write for a stream with a per-address entry, which is read
// once per call, not once per piece. Each piece is cut to the address's
// limiters as well and paid for at them first; an entry with no limiter
// installed neither cuts nor waits, so an unlimited user still writes once.
func (c *countingConn) writeAddress(entry *clientEntry, p []byte) (int, error) {
	paced := entry.pacesDownload()

	var written int

	for len(p) > 0 {
		limit := c.st.speedDown.chunk(c.st.speed.chunk(len(p)))
		if paced {
			limit = entry.cutDownload(limit)
		}

		piece, ok := c.allowance(limit)
		if !ok {
			return written, c.exhausted()
		}

		var waitErr error

		if paced {
			waitErr = c.payAddress(entry, &entry.fairDown, &entry.blockedDown, &c.st.speedDown, piece)
		} else {
			waitErr = c.waitBoth(&c.st.speed, &c.st.speedDown, piece)
		}

		if waitErr != nil {
			return written, waitErr
		}

		n, err := c.Conn.Write(p[:piece])
		if n > 0 {
			c.st.bytesOut.Add(int64(n))
			entry.bytesOut.Add(int64(n))
			c.markSeen(entry)
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
