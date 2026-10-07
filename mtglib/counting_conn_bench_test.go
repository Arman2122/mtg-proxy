package mtglib

import (
	"context"
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

// countingStream is one stream's wrapper as the relay builds it -- over the
// user's stats, with the activity stamp ServeConn points it at -- and the far end
// behind it. The stamp is the stream's own, as in ServeConn.
func countingStream(ctx context.Context, stats *ProxyStats) (*countingConn, *farEnd, *atomic.Int64) {
	far := &farEnd{}
	active := new(atomic.Int64)

	return newCountingConn(ctx, nil, far, stats, "alice").withActivity(active), far, active
}

// countingBench is one unlimited user with one stream.
func countingBench(b *testing.B) (*countingConn, *farEnd, *secretStats, *atomic.Int64) {
	b.Helper()

	stats, st := unlimitedUser(b)
	conn, far, active := countingStream(b.Context(), stats)

	return conn, far, st, active
}

// BenchmarkCountingConn is countingConn's own cost per call, and nothing else:
// the per-user counters, the quota charge, the activity stamp and the loads that
// find no limiter. It is the hot path every byte of every connection goes
// through, which is why a per-address step added to it is measured against these
// rows with the same names, in one session, old binary against new.
//
// Every row verifies what it timed, from the wrapper's counters and from the far
// end's own tally, which do not share a source.
func BenchmarkCountingConn(b *testing.B) {
	b.Run("read", func(b *testing.B) {
		b.Run("noentry", benchCountingRead)
	})
	b.Run("write", func(b *testing.B) {
		b.Run("noentry", benchCountingWrite)
	})
}

func benchCountingRead(b *testing.B) {
	conn, far, st, active := countingBench(b)
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
}

func benchCountingWrite(b *testing.B) {
	conn, far, st, active := countingBench(b)
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
}

// BenchmarkCountingConnParallel is BenchmarkCountingConn with every goroutine a
// stream of its own, all of them one user's: a wrapper and a far end each, over
// the one *secretStats. The goroutines share nothing but the user's counters
// (bytes in and out, the quota charge), so whatever they cost each other is the
// contention on state shared by streams -- which is what a per-address entry
// adds to, for the streams of one address. The serial rows cannot show it, and a
// door row resolves only a few percent of it behind its socket work.
//
// Run it with -cpu 1,2 (or as many as the box has): at one the rows are the
// serial ones plus RunParallel's own overhead, and the rise from there is the
// contention.
//
// The goroutines count their own iterations in a local and hand them over once,
// after their loop, so the verification adds nothing to the timed work. It is the
// serial rows' verification summed over the goroutines: every byte they moved was
// counted by the user, once, and received by a far end, once. A goroutine's
// failure is reported and ends only that goroutine, because Fatal may not be
// called from any but the benchmark's own.
func BenchmarkCountingConnParallel(b *testing.B) {
	b.Run("read", func(b *testing.B) {
		b.Run("noentry", func(b *testing.B) { benchCountingParallel(b, false) })
	})
	b.Run("write", func(b *testing.B) {
		b.Run("noentry", func(b *testing.B) { benchCountingParallel(b, true) })
	})
}

func benchCountingParallel(b *testing.B, write bool) {
	b.Helper()

	stats, st := unlimitedUser(b)

	// What the goroutines hand over, summed: their iterations, and what their far
	// ends tallied of their own.
	var iterations, farReads, farWrites, farBytesRead, farBytesWritten atomic.Int64

	b.SetBytes(countingChunk)
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		conn, far, active := countingStream(b.Context(), stats)
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
