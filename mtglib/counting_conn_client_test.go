package mtglib

import (
	"context"
	"io"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The per-address step of the data path: a stream whose address has an entry
// in the per-address table counts its bytes there, stamps the entry's last-seen
// second, pays the address's own limiters before the user's shared buckets, and
// records how long the address was held back for fair share to read. The
// entries here run on a fake clock, so every delay, every stamp and every
// blocked interval is a number to compare, not a band.

// testClientChunk is what one read or write moves in these tests: a quarter of
// testAddrBurst, so a drained limiter at testAddrRate holds it for
// testClientDelay.
const testClientChunk = 16 << 10

// testClientDelay is testClientChunk at testAddrRate: 15.625 ms.
const testClientDelay = testAddrPiece / 4

// fakeClientEntry is a keyed entry of alice's in a table on a fake clock, with
// no limiter installed.
func fakeClientEntry(t *testing.T) (*clientTable, *clientEntry, *fakeAddrClock) {
	t.Helper()

	table, clock := newTestClientTable(t)

	return table, table.acquire("alice", "203.0.113.9", true, entryInit{}), clock
}

// clientStream is a wrapper over alice's stats, built as ServeConn builds it,
// whose stream is governed by entry (nil for a stream with none), and the far
// end behind it. The pointer is the stream's own, as streamContext.addrEntry is.
func clientStream(
	ctx context.Context, stats *ProxyStats, entry *clientEntry,
) (*countingConn, *farEnd, *atomic.Pointer[clientEntry]) {
	far := &farEnd{}
	held := new(atomic.Pointer[clientEntry])
	held.Store(entry)

	return newCountingConn(ctx, nil, far, stats, "alice").withClient(held), far, held
}

// readChunk reads one testClientChunk through conn.
func readChunk(t *testing.T, conn *countingConn) {
	t.Helper()

	n, err := conn.Read(make([]byte, testClientChunk))
	require.NoError(t, err)
	require.Equal(t, testClientChunk, n)
}

// writeChunk writes one testClientChunk through conn.
func writeChunk(t *testing.T, conn *countingConn) {
	t.Helper()

	n, err := conn.Write(make([]byte, testClientChunk))
	require.NoError(t, err)
	require.Equal(t, testClientChunk, n)
}

// transferChunk reads one chunk through conn for an upload and writes one for a
// download.
func transferChunk(t *testing.T, conn *countingConn, upload bool) {
	t.Helper()

	if upload {
		readChunk(t, conn)
	} else {
		writeChunk(t, conn)
	}
}

// drainedLimiter installs a limiter at bytesPerSecond with testAddrBurst on l,
// on the clock l already has, and takes the full bucket it starts with, so the
// next wait sleeps for every byte it asks for.
func drainedLimiter(t *testing.T, l *addrLimiter, bytesPerSecond int64) {
	t.Helper()

	l.install(bytesPerSecond, testAddrBurst)
	drainAddrLimiter(t, l)
}

// The limiters and trackers of an entry, by the names the cases below use.
func entryCeiling(e *clientEntry) *addrLimiter   { return &e.ceiling }
func entryFairSpeed(e *clientEntry) *addrLimiter { return &e.fairSpeed }
func entryFairUp(e *clientEntry) *addrLimiter    { return &e.fairUp }
func entryFairDown(e *clientEntry) *addrLimiter  { return &e.fairDown }

func entryBlockedSpeed(e *clientEntry) *blockedTracker { return &e.blockedSpeed }
func entryBlockedUp(e *clientEntry) *blockedTracker    { return &e.blockedUp }
func entryBlockedDown(e *clientEntry) *blockedTracker  { return &e.blockedDown }

// requireBlocked takes a snapshot of each of the entry's three trackers at now
// and requires want from the one that blocked names and nothing from the
// others. A nil blocked requires nothing from any of them.
func requireBlocked(
	t *testing.T, entry *clientEntry, now time.Time, blocked func(*clientEntry) *blockedTracker, want time.Duration,
) {
	t.Helper()

	for name, tracker := range map[string]*blockedTracker{
		"combined": &entry.blockedSpeed,
		"upload":   &entry.blockedUp,
		"download": &entry.blockedDown,
	} {
		expected := time.Duration(0)
		if blocked != nil && tracker == blocked(entry) {
			expected = want
		}

		assert.Equal(t, expected, tracker.snapshot(now), "the %s tracker", name)
	}
}

// Bytes land on the entry as they land on the user, in on a read and out on a
// write, once each. The user's own counters are what they were before entries
// existed.
func TestCountingConnCountsBytesOnTheEntry(t *testing.T) {
	t.Parallel()

	stats := NewProxyStats()
	_, entry, _ := fakeClientEntry(t)
	conn, far, _ := clientStream(t.Context(), stats, entry)

	n, err := conn.Read(make([]byte, 1000))
	require.NoError(t, err)
	require.Equal(t, 1000, n)

	n, err = conn.Write(make([]byte, 3000))
	require.NoError(t, err)
	require.Equal(t, 3000, n)

	st := stats.getOrCreate("alice")

	assert.EqualValues(t, 1000, entry.bytesIn.Load(), "a read is counted on the entry, once")
	assert.EqualValues(t, 3000, entry.bytesOut.Load(), "a write is counted on the entry, once")
	assert.EqualValues(t, 1000, st.bytesIn.Load(), "and on the user, as before")
	assert.EqualValues(t, 3000, st.bytesOut.Load())
	assert.EqualValues(t, 4000, st.quotaUsed.Load())
	assert.EqualValues(t, 1000, far.bytesRead)
	assert.EqualValues(t, 3000, far.bytesWritten)
}

// A read the quota cuts short still read what it read, and the address moved
// it: the entry counts it as the user does, before the quota ends the stream.
func TestCountingConnCountsAQuotaCutReadOnTheEntry(t *testing.T) {
	t.Parallel()

	stats := NewProxyStats()
	st := stats.getOrCreate("alice")
	st.quotaCeiling.Store(500)

	_, entry, _ := fakeClientEntry(t)
	conn, _, _ := clientStream(t.Context(), stats, entry)

	n, err := conn.Read(make([]byte, 1000))
	require.ErrorIs(t, err, errQuotaExhausted)
	require.Equal(t, 500, n)

	assert.EqualValues(t, 500, st.bytesIn.Load())
	assert.EqualValues(t, 500, entry.bytesIn.Load(), "the entry counts the bytes the quota let through")
}

// lastSeen is stamped from the table's clock, which is the clock the sweep
// measures idleness by. It is stamped to the second and forward: a store
// happens only when the second has moved on past the stamp, and a stream whose
// reading is a little older than a sibling's never takes the stamp back. One
// reading of that clock serves the stream's own activity stamp too, so
// production reads the time once per call, as it did before there were entries.
// The fake clock starts in 2001, so a stamp taken from time.Now instead shows at
// once.
func TestCountingConnStampsLastSeenOnTheTablesClock(t *testing.T) {
	t.Parallel()

	_, entry, clock := fakeClientEntry(t)
	start := clock.read().Unix()
	require.Equal(t, start, entry.lastSeen.Load(), "acquire stamped the entry")

	var active atomic.Int64

	conn, _, _ := clientStream(t.Context(), NewProxyStats(), entry)
	conn.withActivity(&active)

	clock.advance(1500 * time.Millisecond)
	writeChunk(t, conn)
	assert.Equal(t, start+1, entry.lastSeen.Load(), "a write stamps the second it happened, on the table's clock")
	assert.Equal(t, start+1, active.Load(), "and the stream's own stamp is the same reading")

	clock.advance(400 * time.Millisecond)
	readChunk(t, conn)
	assert.Equal(t, start+1, entry.lastSeen.Load(), "within the same second there is nothing to store")

	// A sibling stream of the address read the clock later and stored first.
	// This stream's slightly earlier second never replaces it.
	entry.lastSeen.Store(start + 2)
	writeChunk(t, conn)
	assert.Equal(t, start+2, entry.lastSeen.Load(), "an earlier second never replaces a later one")

	clock.advance(time.Minute)
	readChunk(t, conn)
	assert.Equal(t, start+61, entry.lastSeen.Load(), "a later second does")
}

// The stamp holds against the small regressions of streams racing each other,
// but not against the clock itself. A wall clock stepped back -- a resumed
// machine's bad time put right -- would otherwise leave every entry stamped in
// between in the future, and the sweep would keep those addresses for the step
// plus ten minutes, filling a secret's entries with addresses long gone. A step
// back of a minute or more is the clock's, and the stamp follows it.
func TestLastSeenFollowsTheClockBackAfterAStep(t *testing.T) {
	t.Parallel()

	table, entry, clock := fakeClientEntry(t)
	start := clock.read().Unix()

	entry.seen(clock.read().Add(-time.Second))
	assert.Equal(t, start, entry.lastSeen.Load(), "a second back is two streams racing: the stamp stays")

	entry.seen(clock.read().Add(-59 * time.Second))
	assert.Equal(t, start, entry.lastSeen.Load(), "and so is anything short of a minute")

	entry.seen(clock.read().Add(-time.Minute))
	assert.Equal(t, start-60, entry.lastSeen.Load(), "a minute back is a step of the clock")

	clock.advance(-5 * time.Minute)

	conn, _, held := clientStream(t.Context(), NewProxyStats(), entry)
	writeChunk(t, conn)
	assert.Equal(t, start-300, entry.lastSeen.Load(), "the data path follows a step back of five minutes")

	// So the sweep forgets the address ten minutes after it left, by the clock
	// as it now is, and not ten minutes after a time that has not come yet.
	held.Store(nil)
	table.release(entry)
	clock.advance(clientIdleRetention)

	assert.Equal(t, 1, table.sweep(clock.read(), clientSweepChunk), "the entry is forgotten on time")
}

// An entry with no limiter installed does not cut a transfer: an unlimited user
// with an entry still writes once, as TestUnlimitedUserWritesOnce has it for a
// user with none.
func TestUnlimitedUserWithAnEntryWritesOnce(t *testing.T) {
	t.Parallel()

	_, entry, _ := fakeClientEntry(t)
	held := new(atomic.Pointer[clientEntry])
	held.Store(entry)

	counter := &writeCounter{}
	conn := newCountingConn(t.Context(), nil, counter, NewProxyStats(), "alice").withClient(held)

	n, err := conn.Write(make([]byte, 1<<20))
	require.NoError(t, err)
	assert.Equal(t, 1<<20, n)
	assert.Equal(t, 1, counter.calls, "an entry with no limiter must not cut a write")
	assert.EqualValues(t, 1<<20, entry.bytesOut.Load())
}

// An address limiter that is installed cuts a transfer to its burst, as the
// user's buckets cut it to theirs: a read takes no more than the burst, and a
// large write reaches the client a burst at a time, each paid for before it
// goes, rather than as one block after a long wait.
func TestAnAddressLimiterCutsATransferToItsBurst(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name    string
		limiter func(*clientEntry) *addrLimiter
	}{
		{"ceiling", entryCeiling},
		{"fair-combined", entryFairSpeed},
		{"fair", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, entry, clock := fakeClientEntry(t)

			// Every limiter a read or a write pays, by name; "fair" is the
			// direction's own, which differs between the two.
			install := func(l *addrLimiter) { l.install(testAddrRate, testAddrBurst) }

			if tc.limiter != nil {
				install(tc.limiter(entry))
			} else {
				install(&entry.fairUp)
				install(&entry.fairDown)
			}

			held := new(atomic.Pointer[clientEntry])
			held.Store(entry)

			reader := newCountingConn(t.Context(), nil, &farEnd{}, NewProxyStats(), "alice").withClient(held)

			n, err := reader.Read(make([]byte, 1<<20))
			require.NoError(t, err)
			assert.Equal(t, testAddrBurst, n, "a read takes no more than the burst")

			counter := &writeCounter{}
			writer := newCountingConn(t.Context(), nil, counter, NewProxyStats(), "alice").withClient(held)

			n, err = writer.Write(make([]byte, 1<<20))
			require.NoError(t, err)
			assert.Equal(t, 1<<20, n)
			assert.Equal(t, (1<<20)/testAddrBurst, counter.calls, "a write goes a burst at a time")
			assert.NotEmpty(t, clock.sleeps(), "each paid for at the address's limiter")
		})
	}
}

// No entry is the common case and it is the data path as it was: a wrapper
// with no pointer, and one whose pointer holds nothing, move and count bytes for
// the user alone. A reload's backfill can store an entry after the wrapper was
// built; the next call counts on it, and no call before it did.
func TestCountingConnWithoutAnEntry(t *testing.T) {
	t.Parallel()

	stats := NewProxyStats()
	st := stats.getOrCreate("alice")

	bare := newCountingConn(t.Context(), nil, &farEnd{}, stats, "alice").withClient(nil)
	readChunk(t, bare)
	writeChunk(t, bare)

	conn, _, held := clientStream(t.Context(), stats, nil)
	readChunk(t, conn)
	writeChunk(t, conn)

	assert.EqualValues(t, 2*testClientChunk, st.bytesIn.Load(), "both wrappers count for the user")
	assert.EqualValues(t, 2*testClientChunk, st.bytesOut.Load())

	_, entry, _ := fakeClientEntry(t)
	held.Store(entry)

	readChunk(t, conn)
	writeChunk(t, conn)

	assert.EqualValues(t, testClientChunk, entry.bytesIn.Load(), "only the call after the backfill counts on the entry")
	assert.EqualValues(t, testClientChunk, entry.bytesOut.Load())
	assert.EqualValues(t, 3*testClientChunk, st.bytesIn.Load())
}

// The address's own limiters are paid before the user's shared buckets. Bytes
// an address may not move yet must not sit in the user's bucket while it waits:
// the user's other streams, from other addresses, would be the ones held back
// for them. So while the address's wait is pending the user's buckets are
// untouched, and once the transfer is done they have been paid, in both
// directions and for every limiter of the address's.
func TestAddressWaitsComeBeforeTheUsersBuckets(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name    string
		upload  bool
		limiter func(*clientEntry) *addrLimiter
	}{
		{"read/ceiling", true, entryCeiling},
		{"read/fair", true, entryFairUp},
		{"read/fair-combined", true, entryFairSpeed},
		{"write/ceiling", false, entryCeiling},
		{"write/fair", false, entryFairDown},
		{"write/fair-combined", false, entryFairSpeed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Slow enough that a charge to the user's buckets is still visible a
			// quarter of a second later.
			const userRate = 64 << 10

			stats := NewProxyStats()
			stats.SetSpeedLimit("alice", userRate)
			stats.SetDirectionalSpeedLimits("alice", userRate, userRate)

			st := stats.getOrCreate("alice")
			combined := st.speed.limiter.Load()

			direction := st.speedDown.limiter.Load()
			if tc.upload {
				direction = st.speedUp.limiter.Load()
			}

			_, entry, clock := fakeClientEntry(t)
			drainedLimiter(t, tc.limiter(entry), testAddrRate)

			var during [2]float64

			clock.hook = func(call int, _ time.Duration) {
				if call == 1 {
					now := time.Now()
					during = [2]float64{combined.TokensAt(now), direction.TokensAt(now)}
				}
			}

			conn, _, _ := clientStream(t.Context(), stats, entry)
			transferChunk(t, conn, tc.upload)

			require.Equal(t, []time.Duration{testClientDelay}, clock.sleeps(), "the address's limiter held the transfer")
			assert.Equal(t, [2]float64{userRate, userRate}, during,
				"while the address waited, the user's buckets were untouched")

			now := time.Now()
			assert.Less(t, combined.TokensAt(now), float64(userRate), "and then the transfer paid the user's buckets")
			assert.Less(t, direction.TokensAt(now), float64(userRate))
		})
	}
}

// Of the address's own limiters the ceiling comes first, the fair share after
// it: while the ceiling holds a transfer, the fair share has not been asked.
func TestTheCeilingIsPaidBeforeTheFairShare(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name   string
		upload bool
		fair   func(*clientEntry) *addrLimiter
	}{
		{"read", true, entryFairUp},
		{"write", false, entryFairDown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, entry, clock := fakeClientEntry(t)
			fair := tc.fair(entry)

			drainedLimiter(t, &entry.ceiling, testAddrRate)
			// Half the ceiling's rate, so that the fair share still has to wait
			// once the ceiling's wait has let it refill.
			drainedLimiter(t, fair, testAddrRate/2)

			var ceilingDuring, fairDuring float64

			clock.hook = func(call int, _ time.Duration) {
				if call == 1 {
					now := clock.read()
					ceilingDuring = installedLimiter(t, &entry.ceiling).TokensAt(now)
					fairDuring = installedLimiter(t, fair).TokensAt(now)
				}
			}

			conn, _, _ := clientStream(t.Context(), NewProxyStats(), entry)
			transferChunk(t, conn, tc.upload)

			assert.InDelta(t, -float64(testClientChunk), ceilingDuring, 0,
				"the first wait is the ceiling's: it has reserved the transfer")
			assert.InDelta(t, 0, fairDuring, 0, "and the fair share has not been asked yet")
			assert.Len(t, clock.sleeps(), 2, "then the fair share held the transfer too")
		})
	}
}

// Every wait at an address's limiters is time the user's connections spent
// held to a limiter, the ceiling's included, and so is the address's own
// throttled time. The user's own buckets held nothing here and count nothing.
func TestAddressWaitsAreThrottledTime(t *testing.T) {
	t.Parallel()

	stats := NewProxyStats()
	st := stats.getOrCreate("alice")

	_, entry, clock := fakeClientEntry(t)
	drainedLimiter(t, &entry.ceiling, testAddrRate)
	drainedLimiter(t, &entry.fairDown, testAddrRate/2)

	conn, _, _ := clientStream(t.Context(), stats, entry)
	writeChunk(t, conn)

	sleeps := clock.sleeps()
	require.Len(t, sleeps, 2, "the ceiling and the fair share each held the write")

	var slept time.Duration
	for _, d := range sleeps {
		slept += d
	}

	assert.EqualValues(t, slept, st.clientThrottledNanos.Load(),
		"the user's throttled time has every address wait, the ceiling's included")
	assert.EqualValues(t, slept, entry.throttledNanos.Load(), "and so has the address's own")
	assert.Zero(t, st.speed.throttledNanos.Load()+st.speedUp.throttledNanos.Load()+st.speedDown.throttledNanos.Load())
}

// Review Focus 6: throttled_ms, as /stats reports it, includes the address
// waits and never goes back. The table forgets an address ten minutes after its
// last stream; if the user's figure were summed from the entries, the sweep
// would take that address's waits out of it.
func TestThrottledMillisKeepsAddressWaitsAcrossTheSweep(t *testing.T) {
	t.Parallel()

	clock := newFakeAddrClock()

	p := newLimitTestProxy(map[string]Secret{"alice": GenerateSecret("alice.example.com")}, nil)
	p.clients = newClientTable(clock.clock())

	entry := p.clients.acquire("alice", "203.0.113.9", true, entryInit{})
	drainedLimiter(t, &entry.ceiling, testAddrRate)

	conn, _, held := clientStream(t.Context(), p.stats, entry)

	n, err := conn.Write(make([]byte, 2*testAddrBurst))
	require.NoError(t, err)
	require.Equal(t, 2*testAddrBurst, n)
	require.Equal(t, []time.Duration{testAddrPiece, testAddrPiece}, clock.sleeps(),
		"two bursts at the ceiling's rate: 125 ms")

	before := statsFor(t, p).Users["alice"].ThrottledMillis
	assert.EqualValues(t, 125, before, "throttled_ms includes the address's waits")

	// The stream ends, the address stays away ten minutes, and the sweep
	// forgets its entry.
	held.Store(nil)
	p.clients.release(entry)
	clock.advance(clientIdleRetention)

	require.Equal(t, 1, p.sweepClients())
	require.Zero(t, p.clients.clients("alice"))

	assert.Equal(t, before, statsFor(t, p).Users["alice"].ThrottledMillis,
		"the user's throttled time outlives the entry it was spent through")
}

// The duty fair share reads is the time an address spent waiting at its own
// fair share, in the direction of the share: never at its ceiling. An address
// its own ceiling holds back is not short of its share, and saying it was would
// hand it a bigger one at everyone else's cost.
func TestTheDutyCountsTheFairShareAndNotTheCeiling(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name    string
		upload  bool
		limiter func(*clientEntry) *addrLimiter
		blocked func(*clientEntry) *blockedTracker
	}{
		{"read/ceiling", true, entryCeiling, nil},
		{"write/ceiling", false, entryCeiling, nil},
		{"read/fair", true, entryFairUp, entryBlockedUp},
		{"write/fair", false, entryFairDown, entryBlockedDown},
		{"read/fair-combined", true, entryFairSpeed, entryBlockedSpeed},
		{"write/fair-combined", false, entryFairSpeed, entryBlockedSpeed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, entry, clock := fakeClientEntry(t)
			drainedLimiter(t, tc.limiter(entry), testAddrRate)

			conn, _, _ := clientStream(t.Context(), NewProxyStats(), entry)
			transferChunk(t, conn, tc.upload)

			require.Equal(t, []time.Duration{testClientDelay}, clock.sleeps())
			requireBlocked(t, entry, clock.read(), tc.blocked, testClientDelay)
		})
	}
}

// A wait at the user's shared bucket is part of the duty too, in the bucket's
// direction, when the address has a fair share there. An address starved at the
// shared bucket -- which divides its tokens per connection, not per address -- is
// never held at its own share, which sits at or above what it gets, so without
// this a four-connection address would keep four shares to a one-connection
// address's one. Where the address has no fair share there is no duty to feed,
// and the shared bucket's waits are not bracketed at all.
//
// Not parallel: it replaces beforeWaitN, which runs inside the shared bucket's
// wait, to move the entry's clock on there.
func TestTheDutyCountsTheUsersBucketBehindAFairShare(t *testing.T) { //nolint: paralleltest // swaps a package variable
	// Far above anything a test moves: the user's buckets and the address's
	// limiters never sleep, and only beforeWaitN moves the clock.
	const unbounded = 1 << 40

	const heldFor = 100 * time.Millisecond

	for _, tc := range []struct {
		name    string
		upload  bool
		limit   func(stats *ProxyStats)
		limiter func(*clientEntry) *addrLimiter
		blocked func(*clientEntry) *blockedTracker
	}{
		{
			"read", true,
			func(stats *ProxyStats) { stats.SetDirectionalSpeedLimits("alice", unbounded, 0) },
			entryFairUp, entryBlockedUp,
		},
		{
			"write", false,
			func(stats *ProxyStats) { stats.SetDirectionalSpeedLimits("alice", 0, unbounded) },
			entryFairDown, entryBlockedDown,
		},
		{
			"read/combined", true,
			func(stats *ProxyStats) { stats.SetSpeedLimit("alice", unbounded) },
			entryFairSpeed, entryBlockedSpeed,
		},
		{
			"write/combined", false,
			func(stats *ProxyStats) { stats.SetSpeedLimit("alice", unbounded) },
			entryFairSpeed, entryBlockedSpeed,
		},
		{
			"write/no-fair-share", false,
			func(stats *ProxyStats) { stats.SetDirectionalSpeedLimits("alice", 0, unbounded) },
			entryCeiling, nil,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stats := NewProxyStats()
			tc.limit(stats)

			_, entry, clock := fakeClientEntry(t)
			tc.limiter(entry).install(unbounded, testAddrBurst)

			previous := beforeWaitN
			beforeWaitN = func() { clock.advance(heldFor) }

			t.Cleanup(func() { beforeWaitN = previous })

			conn, _, _ := clientStream(t.Context(), stats, entry)
			transferChunk(t, conn, tc.upload)

			require.Empty(t, clock.sleeps(), "the address's limiter never slept: the time passed in the user's bucket")
			requireBlocked(t, entry, clock.read(), tc.blocked, heldFor)
		})
	}
}

// A wait that outlasts a tick is credited to the tick it is in, while it lasts.
// Credited only when it ended, the ticks during a long wait -- a chunk held for
// seconds at a small share -- would see an address with no duty and next to no
// rate, and fair share would release it as if it had paused.
func TestADutyWaitIsCreditedWhileItLasts(t *testing.T) {
	t.Parallel()

	_, entry, clock := fakeClientEntry(t)
	drainedLimiter(t, &entry.fairDown, testAddrRate)

	var during time.Duration

	clock.hook = func(call int, _ time.Duration) {
		if call == 1 {
			// A tick lands 10 ms into the wait.
			clock.advance(10 * time.Millisecond)
			during = entry.blockedDown.snapshot(clock.read())
		}
	}

	conn, _, _ := clientStream(t.Context(), NewProxyStats(), entry)
	writeChunk(t, conn)

	assert.Equal(t, 10*time.Millisecond, during, "the tick during the wait is credited with the wait so far")
	assert.Equal(t, testClientDelay, entry.blockedDown.snapshot(clock.read()),
		"and the next tick with the rest of it, from where the last one stopped")
}

// Two streams of one address blocked at once are one address blocked: the
// second stream's write starts while the first one sleeps, and waits behind it
// at the address's shared fair share. The address was blocked from the first
// wait's start to its end, once.
func TestTwoStreamsBlockedAtOnceCountOnce(t *testing.T) {
	t.Parallel()

	stats := NewProxyStats()

	_, entry, clock := fakeClientEntry(t)
	drainedLimiter(t, &entry.fairDown, testAddrRate)

	first, _, _ := clientStream(t.Context(), stats, entry)
	second, _, _ := clientStream(t.Context(), stats, entry)

	clock.hook = func(call int, _ time.Duration) {
		if call == 1 {
			writeChunk(t, second)
		}
	}

	writeChunk(t, first)

	// The first stream reserved a chunk and sleeps for it; the second reserved
	// one behind it and sleeps for both, and finishes first.
	require.Equal(t, []time.Duration{2 * testClientDelay, testClientDelay}, clock.sleeps())

	assert.Equal(t, 3*testClientDelay, entry.blockedDown.snapshot(clock.read()),
		"the span of the two overlapping waits, once: a sum would count the overlap twice")
}

// A wait the stream's end cuts short lets go of the tracker as surely as one
// that ran its course. A stream that stayed counted as blocked would make its
// address look held back for ever after.
func TestACancelledWaitLetsGoOfTheTracker(t *testing.T) {
	t.Parallel()

	_, entry, clock := fakeClientEntry(t)
	drainedLimiter(t, &entry.fairDown, testAddrRate)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	clock.hook = func(call int, _ time.Duration) {
		if call == 1 {
			cancel()
		}
	}

	conn, _, _ := clientStream(ctx, NewProxyStats(), entry)

	_, err := conn.Write(make([]byte, testClientChunk))
	require.ErrorIs(t, err, context.Canceled)

	clock.advance(time.Second)
	assert.Zero(t, entry.blockedDown.snapshot(clock.read()), "the second after the wait is nobody's")
}

// ServeConn hands the relay's wrapper the stream's entry: a keyed stream on a
// proxy that keeps addresses counts its bytes on its address, both ways, and
// exactly what its user counts -- it is the user's only stream.
func TestTheRelayCountsAKeyedStreamOnItsEntry(t *testing.T) {
	t.Parallel()

	ec := govEntryCases()[1]
	secret := ec.secret(t)

	h := ec.harness(t, map[string]Secret{"alice": secret}, nil)
	h.proxy.trackClientIPs = true

	client, done := dialProxyFrom(t, h, ec.policy, tcpFrom("203.0.113.21", 50001))
	upstream := connectThrough(t, ec, h, client, "alice", secret.Key)

	t.Cleanup(func() { endStream(client, upstream, done) })

	deadline := time.Now().Add(5 * time.Second)
	require.NoError(t, client.SetDeadline(deadline))
	require.NoError(t, upstream.SetDeadline(deadline))

	entry := h.liveStream(t, "alice").addrEntry.Load()
	require.NotNil(t, entry, "a keyed stream on a tracking proxy has an entry")
	require.False(t, entry.rest)

	_, err := client.Write(make([]byte, 1000))
	require.NoError(t, err)

	_, err = io.ReadFull(upstream, make([]byte, 1000))
	require.NoError(t, err)

	_, err = upstream.Write(make([]byte, 3000))
	require.NoError(t, err)

	_, err = io.ReadFull(client, make([]byte, 3000))
	require.NoError(t, err)

	st := h.proxy.stats.getOrCreate("alice")

	// The wrapper counts a write after the socket write returns, which can be
	// after the client has read it.
	require.Eventually(t, func() bool {
		return st.bytesIn.Load() == 1000 && st.bytesOut.Load() == 3000
	}, 5*time.Second, time.Millisecond, "the user's counters")

	assert.EqualValues(t, 1000, entry.bytesIn.Load(), "the relay counts the upload on the entry")
	assert.EqualValues(t, 3000, entry.bytesOut.Load(), "and the download")
}
