package mtglib

import (
	"context"
	"math"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Arman2122/mtg-proxy/essentials"
	"github.com/Arman2122/mtg-proxy/mtglib/internal/tls"
	"github.com/stretchr/testify/require"
)

// countingChunk is what one Read or one Write hands countingConn in these
// benchmarks: tls.MaxRecordPayloadSize, 16,379 bytes. The relay moves a stream
// with io.CopyBuffer over one buffer of its bufPoolSize, which is that constant
// on every target but the constrained MIPS ones (half of it there), so a
// transfer that fills the buffer -- any large one -- hands the wrapper exactly
// this much per Read and per Write. A benchmark that moved 64 KiB at a time
// would time a call the relay never makes.
const countingChunk = tls.MaxRecordPayloadSize

// farEnd is the other end of a countingConn in a benchmark: an in-memory
// essentials.Conn that does nothing a benchmark could mistake for the
// wrapper's own work. A net.Pipe pair is synchronous and costs a goroutine
// switch per call, which would be most of what the benchmark measured.
//
// Read reports len(p) bytes without touching p. The buffer the benchmark hands
// in is a zero-filled slice nobody ever writes to, so it already is the zero
// payload a filling Read would produce -- and copying a whole chunk per call
// would cost more than everything countingConn does, hiding exactly the
// per-call work the A/B is about. Write discards. Both keep their own tally,
// kept apart from what countingConn counts so the two can be compared: the
// wrapper faithfully counts whatever its far end returns, so a far end that
// dropped a byte would otherwise agree with it.
//
// One goroutine uses each, so the tallies are plain integers; the parallel
// benchmark gives every goroutine a far end of its own.
type farEnd struct {
	reads, writes           int64
	bytesRead, bytesWritten int64
}

func (f *farEnd) Read(p []byte) (int, error) {
	f.reads++
	f.bytesRead += int64(len(p))

	return len(p), nil
}

func (f *farEnd) Write(p []byte) (int, error) {
	f.writes++
	f.bytesWritten += int64(len(p))

	return len(p), nil
}

func (f *farEnd) Close() error                       { return nil }
func (f *farEnd) CloseRead() error                   { return nil }
func (f *farEnd) CloseWrite() error                  { return nil }
func (f *farEnd) LocalAddr() net.Addr                { return nil }
func (f *farEnd) RemoteAddr() net.Addr               { return nil }
func (f *farEnd) SetDeadline(_ time.Time) error      { return nil }
func (f *farEnd) SetReadDeadline(_ time.Time) error  { return nil }
func (f *farEnd) SetWriteDeadline(_ time.Time) error { return nil }

var _ essentials.Conn = (*farEnd)(nil)

// benchUser makes a row's user and the stats the wrappers of its streams count
// into.
type benchUser func(b *testing.B) (*ProxyStats, *secretStats)

// unlimitedUser is a user with no limit of any kind, and the stats the wrappers
// of its streams count into.
//
// The rows are named by what a connection has besides the user: noentry is
// nothing, and the rows that add a per-address entry, a ceiling and a fair share
// take the same parents and the same chunk, so a figure for one is a figure for
// the other.
func unlimitedUser(b *testing.B) (*ProxyStats, *secretStats) {
	b.Helper()

	stats := NewProxyStats()
	st := stats.getOrCreate("alice")

	// The row is about an unlimited user: a limiter, a direction cap or a quota
	// in place would time the paced path under the unpaced name.
	require.Nil(b, st.speed.limiter.Load(), "the user must have no speed limit")
	require.Nil(b, st.speedUp.limiter.Load(), "the user must have no upload limit")
	require.Nil(b, st.speedDown.limiter.Load(), "the user must have no download limit")
	require.Zero(b, st.quotaCeiling.Load(), "the user must have no quota ceiling")

	return stats, st
}

// speedUser is unlimitedUser with one limit, the combined speed, set at the
// rate the ceiling rows use: the secret client-fair divides, with a speed that
// never holds anything back. The wrapper then pays the user's bucket on every
// call, and for an address with a fair share of it, brackets that wait with the
// share's tracker as well -- which a user with no bucket does not make it do.
//
// It cannot be shown to have never slept, only to be unable to: the bucket's own
// throttled time counts every call that went through it, sleeping or not, so it
// is no detector. At this rate whatever the bucket is short by is due in less
// than a nanosecond (see benchCeiling), and a bucket that is not due a delay
// returns without making a timer.
func speedUser(b *testing.B) (*ProxyStats, *secretStats) {
	b.Helper()

	stats := NewProxyStats()
	stats.SetSpeedLimit("alice", benchCeiling)

	st := stats.getOrCreate("alice")

	// The row is about a user with a combined speed and nothing else: a direction
	// cap or a quota in place would time more than the fair+user name says.
	bucket := st.speed.limiter.Load()
	require.NotNil(b, bucket, "the user must have a combined speed")
	require.Greater(b, bucket.Burst(), countingChunk, "a chunk must never be cut")
	require.Nil(b, st.speedUp.limiter.Load(), "the user must have no upload limit")
	require.Nil(b, st.speedDown.limiter.Load(), "the user must have no download limit")
	require.Zero(b, st.quotaCeiling.Load(), "the user must have no quota ceiling")

	return stats, st
}

// benchClientEntry is a keyed entry of alice's with no limiter installed: what a
// proxy that keeps client addresses (track-client-ips, which a panel always
// sets) gives every keyed stream. Its table runs on the real clock, as
// NewProxy's does.
func benchClientEntry(b *testing.B) *clientEntry {
	b.Helper()

	entry := newClientTable(addrClock{}).acquire("alice", benchSharedAddr, true, entryInit{})

	// The row is about an entry kept for its counts alone: a limiter in place
	// would time the paced path under the panel's name.
	require.False(b, entry.rest, "the entry must be the address's own")
	require.Nil(b, entry.ceiling.limiter.Load(), "the entry must have no ceiling")
	require.Nil(b, entry.fairSpeed.limiter.Load(), "the entry must have no fair share")
	require.Nil(b, entry.fairUp.limiter.Load(), "the entry must have no upload fair share")
	require.Nil(b, entry.fairDown.limiter.Load(), "the entry must have no download fair share")

	return entry
}

// benchCeiling is the client-speed of the ceiling rows: the largest rate a
// bucket can be given, so that the row times the ceiling's wait without ever
// sleeping in it. Not merely above link speed: the far end here hands over a
// chunk in tens of nanoseconds, close to a terabyte a second, and the clock
// the bucket refills by can stand still for half a millisecond on some hosts,
// so a row at any rate a link could have drains the bucket and sleeps. At this
// one whatever the bucket is short by is due in less than a nanosecond, which
// is no delay at all.
const benchCeiling = math.MaxInt64

// benchCeilingEntry is a keyed entry of alice's whose only limiter is a
// ceiling that never holds anything back: what a secret with client-speed set
// above link speed gives every keyed stream. It is made with its ceiling, as
// admission makes one, on the real clock.
func benchCeilingEntry(b *testing.B) *clientEntry {
	b.Helper()

	entry := newClientTable(addrClock{}).acquire("alice", benchSharedAddr, true, entryInit{CeilingRate: benchCeiling})

	// The row is about the ceiling alone: a fair share in place would time
	// fair share's brackets under the ceiling's name.
	require.False(b, entry.rest, "the entry must be the address's own")
	require.NotNil(b, entry.ceiling.limiter.Load(), "the entry must have its ceiling")
	require.Greater(b, entry.ceiling.limiter.Load().Burst(), countingChunk, "a chunk must never be cut")
	require.Nil(b, entry.fairSpeed.limiter.Load(), "the entry must have no fair share")
	require.Nil(b, entry.fairUp.limiter.Load(), "the entry must have no upload fair share")
	require.Nil(b, entry.fairDown.limiter.Load(), "the entry must have no download fair share")

	b.Cleanup(func() {
		if waited := entry.throttledNanos.Load(); waited != 0 {
			b.Errorf("the ceiling held the row back for %s: it timed a sleep, not the ceiling", time.Duration(waited))
		}
	})

	return entry
}

// benchFairEntry is a keyed entry of alice's whose only limiter is a combined
// fair share that never holds anything back: what a secret with client-fair on
// and a speed above link speed gives every keyed stream, before its first tick
// has moved the share. It is made with its fair limiter, as admission makes one,
// on the real clock, from a combined total at benchCeiling's rate, for the reason
// that rate has. No ticker runs here: the rows time the data path, and a tick
// only moves the rate the limiter runs at, which the door rows include.
//
// It is the combined bucket, speed, and not speed-up or speed-down, because the
// wrapper brackets a wait at the user's bucket with the tracker of the share
// that divides it: the combined speed pairs with fairSpeed, the direction caps
// with fairUp and fairDown. With a speed-down share the fair+user rows would
// bracket nothing at the user's bucket.
func benchFairEntry(b *testing.B) *clientEntry {
	b.Helper()

	entry := newClientTable(addrClock{}).acquire("alice", benchSharedAddr, true,
		entryInit{FairTotals: fairTotals{Speed: benchCeiling}})

	// The row is about the combined fair share alone: a ceiling in place would
	// time the ceiling's wait under fair share's name.
	require.False(b, entry.rest, "the entry must be the address's own")
	require.Nil(b, entry.ceiling.limiter.Load(), "the entry must have no ceiling")
	require.NotNil(b, entry.fairSpeed.limiter.Load(), "the entry must have its combined fair share")
	require.Greater(b, entry.fairSpeed.limiter.Load().Burst(), countingChunk, "a chunk must never be cut")
	require.Nil(b, entry.fairUp.limiter.Load(), "the entry must have no upload fair share")
	require.Nil(b, entry.fairDown.limiter.Load(), "the entry must have no download fair share")

	b.Cleanup(func() {
		if waited := entry.throttledNanos.Load(); waited != 0 {
			b.Errorf("the fair share held the row back for %s: it timed a sleep, not the share", time.Duration(waited))
		}
	})

	return entry
}

// trackerOf is what a blocked tracker holds: whether it was ever left, and how
// many streams it counts as blocked now.
func trackerOf(t *blockedTracker) (left bool, blocked int) {
	t.mu.Lock()
	defer t.mu.Unlock()

	return !t.edge.IsZero(), t.blocked
}

// requireFairPaid checks what a fair row did that the byte counts cannot show:
// the wrapper bracketed its waits with the combined share's tracker -- the
// tracker was entered and left, every enter was left, and the directions'
// trackers, whose shares the entry does not have, were never touched -- and no
// address's limiter held a stream back, as the user's tally of the time its
// streams slept at them says. The entry's tally is checked when the row ends, by
// benchFairEntry.
func requireFairPaid(b *testing.B, st *secretStats, entry *clientEntry) {
	b.Helper()

	left, blocked := trackerOf(&entry.blockedSpeed)
	require.True(b, left, "the combined tracker must have been entered and left: the fair path was not taken")
	require.Zero(b, blocked, "every enter of the tracker must have been left")

	left, _ = trackerOf(&entry.blockedUp)
	require.False(b, left, "the upload tracker belongs to a share the entry does not have")

	left, _ = trackerOf(&entry.blockedDown)
	require.False(b, left, "the download tracker belongs to a share the entry does not have")

	require.Zero(b, st.clientThrottledNanos.Load(), "an address's limiter held the row back: it timed a sleep")
}

// countingStream is one stream's wrapper as ServeConn builds it -- over the
// user's stats, with the activity stamp and the entry pointer ServeConn points
// it at, both the stream's own -- and the far end behind it. The pointer holds
// entry: nil for a stream whose secret keeps no entries, which is what the
// relay's wrapper finds then, so a noentry row times the load that finds
// nothing, as production pays it.
func countingStream(
	ctx context.Context, stats *ProxyStats, entry *clientEntry,
) (*countingConn, *farEnd, *atomic.Int64) {
	far := &farEnd{}
	active := new(atomic.Int64)
	held := new(atomic.Pointer[clientEntry])
	held.Store(entry)

	return newCountingConn(ctx, nil, far, stats, "alice").withActivity(active).withClient(held), far, active
}

// countingBench is one user with one stream, governed by entry, or by none when
// it is nil.
func countingBench(
	b *testing.B, entry *clientEntry, user benchUser,
) (*countingConn, *farEnd, *secretStats, *atomic.Int64) {
	b.Helper()

	stats, st := user(b)
	conn, far, active := countingStream(b.Context(), stats, entry)

	return conn, far, st, active
}

// requireEntryCounted checks what an entry row timed on the entry: want bytes
// in the row's direction, counted once, and none in the other.
func requireEntryCounted(b *testing.B, entry *clientEntry, want int64, write bool) {
	b.Helper()

	counted, other := &entry.bytesIn, &entry.bytesOut
	if write {
		counted, other = other, counted
	}

	require.Equal(b, want, counted.Load(), "every byte moved must be counted on the entry, once")
	require.Zero(b, other.Load(), "and nothing in the other direction")
}

// BenchmarkCountingConn is countingConn's own cost per call, and nothing else:
// the per-user counters, the quota charge, the activity stamp and the loads that
// find no limiter. It is the hot path every byte of every connection goes
// through, which is why a per-address step added to it is measured against these
// rows with the same names, in one session, old binary against new.
//
// noentry is a stream whose secret keeps no per-address entries: the wrapper
// finds its entry pointer empty. entry is a stream of a keyed address with an
// entry and no limiter installed -- every keyed stream of a proxy that keeps
// client addresses, which a panel always has it do -- so the bytes are counted
// on the entry as well and its last-seen stamp is kept. entry over noentry, in
// one binary, is what the panel's case costs a call. ceiling is entry with a
// client-speed far above link speed: the address's bucket is paid before the
// user's on every call and never holds anything back, so ceiling over entry is
// what a ceiling costs a call that it does not slow.
//
// fair is entry with a combined fair share that never holds anything back
// (client-fair, in a secret whose speed is above link speed), for a user with no
// speed of its own: the call pays the share and brackets that wait with the
// share's tracker -- two clock reads and two lock pairs -- and finds no bucket
// of the user's to pay. That is not a configuration a proxy runs, since
// client-fair with no speed divides nothing, and it is there to separate the
// share's own cost from the user's bucket's. fair+user is the configuration:
// the same entry and a user whose combined speed is set, never binding, so that
// the call also pays the user's bucket and brackets that wait with the same
// tracker. fair over entry is what a fair share costs a call that it does not
// slow, and fair+user over fair what the user's bucket adds to it.
//
// Every row verifies what it timed, from the wrapper's counters and from the far
// end's own tally, which do not share a source.
func BenchmarkCountingConn(b *testing.B) {
	b.Run("read", func(b *testing.B) {
		b.Run("noentry", func(b *testing.B) { benchCountingRead(b, nil, unlimitedUser) })
		b.Run("entry", func(b *testing.B) { benchCountingRead(b, benchClientEntry(b), unlimitedUser) })
		b.Run("ceiling", func(b *testing.B) { benchCountingRead(b, benchCeilingEntry(b), unlimitedUser) })
		b.Run("fair", func(b *testing.B) { benchCountingRead(b, benchFairEntry(b), unlimitedUser) })
		b.Run("fair+user", func(b *testing.B) { benchCountingRead(b, benchFairEntry(b), speedUser) })
	})
	b.Run("write", func(b *testing.B) {
		b.Run("noentry", func(b *testing.B) { benchCountingWrite(b, nil, unlimitedUser) })
		b.Run("entry", func(b *testing.B) { benchCountingWrite(b, benchClientEntry(b), unlimitedUser) })
		b.Run("ceiling", func(b *testing.B) { benchCountingWrite(b, benchCeilingEntry(b), unlimitedUser) })
		b.Run("fair", func(b *testing.B) { benchCountingWrite(b, benchFairEntry(b), unlimitedUser) })
		b.Run("fair+user", func(b *testing.B) { benchCountingWrite(b, benchFairEntry(b), speedUser) })
	})
}

func benchCountingRead(b *testing.B, entry *clientEntry, user benchUser) {
	b.Helper()

	conn, far, st, active := countingBench(b, entry, user)
	buf := make([]byte, countingChunk)

	b.SetBytes(countingChunk)
	b.ReportAllocs()

	iterations := 0

	for b.Loop() {
		n, err := conn.Read(buf)
		if err != nil || n != countingChunk {
			b.Fatalf("Read = %d, %v; want %d, nil", n, err, countingChunk)
		}

		iterations++
	}

	want := int64(iterations) * countingChunk

	require.Equal(b, want, st.bytesIn.Load(), "every byte read must be counted, once")
	require.Equal(b, want, st.quotaUsed.Load(), "every byte read must be charged, once")
	require.Equal(b, want, far.bytesRead, "the far end must have served every byte")
	require.EqualValues(b, iterations, far.reads, "one Read of the far end per Read of the wrapper")
	require.Zero(b, st.bytesOut.Load(), "a read benchmark writes nothing")
	require.Zero(b, far.writes)
	require.NotZero(b, active.Load(), "the activity stamp must have been kept")

	if entry != nil {
		requireEntryCounted(b, entry, want, false)
		require.Equal(b, active.Load(), entry.lastSeen.Load(),
			"the entry's last-seen stamp must have been kept, from the stream's own reading")

		if entry.fairSpeed.installed() {
			requireFairPaid(b, st, entry)
		}
	}
}

func benchCountingWrite(b *testing.B, entry *clientEntry, user benchUser) {
	b.Helper()

	conn, far, st, active := countingBench(b, entry, user)
	buf := make([]byte, countingChunk)

	b.SetBytes(countingChunk)
	b.ReportAllocs()

	iterations := 0

	for b.Loop() {
		n, err := conn.Write(buf)
		if err != nil || n != countingChunk {
			b.Fatalf("Write = %d, %v; want %d, nil", n, err, countingChunk)
		}

		iterations++
	}

	want := int64(iterations) * countingChunk

	require.Equal(b, want, st.bytesOut.Load(), "every byte written must be counted, once")
	require.Equal(b, want, st.quotaUsed.Load(), "every byte written must be charged, once")
	require.Equal(b, want, far.bytesWritten, "the far end must have received every byte")
	require.EqualValues(b, iterations, far.writes,
		"an unlimited user writes once: one Write of the far end per Write of the wrapper")
	require.Zero(b, st.bytesIn.Load(), "a write benchmark reads nothing")
	require.Zero(b, far.reads)
	require.NotZero(b, active.Load(), "the activity stamp must have been kept")

	if entry != nil {
		requireEntryCounted(b, entry, want, true)
		require.Equal(b, active.Load(), entry.lastSeen.Load(),
			"the entry's last-seen stamp must have been kept, from the stream's own reading")

		if entry.fairSpeed.installed() {
			requireFairPaid(b, st, entry)
		}
	}
}

// BenchmarkCountingConnParallel is BenchmarkCountingConn with every goroutine a
// stream of its own, all of them one user's: a wrapper and a far end each, over
// the one *secretStats. In the noentry rows the goroutines share nothing but the
// user's counters (bytes in and out, the quota charge), so whatever they cost
// each other is the contention on state shared by streams. In the entry rows
// every stream is at the one address and holds the one entry, as the streams of
// a client that opens several do, or a carrier's NAT's: they share the entry's
// counters and its last-seen stamp as well, and the rise over noentry is what
// that sharing costs. The ceiling rows share the address's bucket too, whose
// lock every call of every stream takes. The fair rows share the combined fair
// share's bucket and its blocked tracker, whose lock every call of every stream
// takes twice; the fair+user rows share the user's bucket as well, with a
// second pair of tracker locks. The serial rows cannot show it, and a door row
// resolves only a few percent of it behind its socket work.
//
// Run it with -cpu 1,2 (or as many as the box has): at one the rows are the
// serial ones plus RunParallel's own overhead, and the rise from there is the
// contention.
//
// The goroutines count their own iterations in a local and hand them over once,
// after their loop, so the verification adds nothing to the timed work. It is the
// serial rows' verification summed over the goroutines: every byte they moved was
// counted by the user, once, by the entry when there is one, once, and received
// by a far end, once. A goroutine's failure is reported and ends only that
// goroutine, because Fatal may not be called from any but the benchmark's own.
func BenchmarkCountingConnParallel(b *testing.B) {
	b.Run("read", func(b *testing.B) {
		b.Run("noentry", func(b *testing.B) { benchCountingParallel(b, false, nil, unlimitedUser) })
		b.Run("entry", func(b *testing.B) { benchCountingParallel(b, false, benchClientEntry(b), unlimitedUser) })
		b.Run("ceiling", func(b *testing.B) { benchCountingParallel(b, false, benchCeilingEntry(b), unlimitedUser) })
		b.Run("fair", func(b *testing.B) { benchCountingParallel(b, false, benchFairEntry(b), unlimitedUser) })
		b.Run("fair+user", func(b *testing.B) { benchCountingParallel(b, false, benchFairEntry(b), speedUser) })
	})
	b.Run("write", func(b *testing.B) {
		b.Run("noentry", func(b *testing.B) { benchCountingParallel(b, true, nil, unlimitedUser) })
		b.Run("entry", func(b *testing.B) { benchCountingParallel(b, true, benchClientEntry(b), unlimitedUser) })
		b.Run("ceiling", func(b *testing.B) { benchCountingParallel(b, true, benchCeilingEntry(b), unlimitedUser) })
		b.Run("fair", func(b *testing.B) { benchCountingParallel(b, true, benchFairEntry(b), unlimitedUser) })
		b.Run("fair+user", func(b *testing.B) { benchCountingParallel(b, true, benchFairEntry(b), speedUser) })
	})
}

func benchCountingParallel(b *testing.B, write bool, entry *clientEntry, user benchUser) {
	b.Helper()

	stats, st := user(b)

	// What the goroutines hand over, summed: their iterations, and what their far
	// ends tallied of their own.
	var iterations, farReads, farWrites, farBytesRead, farBytesWritten atomic.Int64

	b.SetBytes(countingChunk)
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		conn, far, active := countingStream(b.Context(), stats, entry)
		buf := make([]byte, countingChunk)
		moved := 0

		if write {
			for pb.Next() {
				n, err := conn.Write(buf)
				if err != nil || n != countingChunk {
					b.Errorf("Write = %d, %v; want %d, nil", n, err, countingChunk)

					return
				}

				moved++
			}
		} else {
			for pb.Next() {
				n, err := conn.Read(buf)
				if err != nil || n != countingChunk {
					b.Errorf("Read = %d, %v; want %d, nil", n, err, countingChunk)

					return
				}

				moved++
			}
		}

		// A goroutine that was given no iterations has nothing to have stamped.
		if moved > 0 && active.Load() == 0 {
			b.Errorf("a stream that moved %d chunks kept no activity stamp", moved)
		}

		// The entry's stamp is shared and only moves forward: it is at least the
		// second this stream last stamped.
		if moved > 0 && entry != nil && entry.lastSeen.Load() < active.Load() {
			b.Errorf("the entry's last-seen stamp %d is behind a stream that stamped %d",
				entry.lastSeen.Load(), active.Load())
		}

		iterations.Add(int64(moved))
		farReads.Add(far.reads)
		farWrites.Add(far.writes)
		farBytesRead.Add(far.bytesRead)
		farBytesWritten.Add(far.bytesWritten)
	})

	total := iterations.Load()
	want := total * countingChunk

	require.NotZero(b, total, "no goroutine moved anything")
	require.Equal(b, want, st.quotaUsed.Load(), "every byte moved must be charged, once")

	if entry != nil {
		requireEntryCounted(b, entry, want, write)

		if entry.fairSpeed.installed() {
			requireFairPaid(b, st, entry)
		}
	}

	if write {
		require.Equal(b, want, st.bytesOut.Load(), "every byte written must be counted, once")
		require.Equal(b, want, farBytesWritten.Load(), "the far ends must have received every byte")
		require.Equal(b, total, farWrites.Load(), "an unlimited user writes once, on every stream")
		require.Zero(b, st.bytesIn.Load(), "a write benchmark reads nothing")
		require.Zero(b, farReads.Load())

		return
	}

	require.Equal(b, want, st.bytesIn.Load(), "every byte read must be counted, once")
	require.Equal(b, want, farBytesRead.Load(), "the far ends must have served every byte")
	require.Equal(b, total, farReads.Load(), "one Read of a far end per Read of its wrapper")
	require.Zero(b, st.bytesOut.Load(), "a read benchmark writes nothing")
	require.Zero(b, farWrites.Load())
}
