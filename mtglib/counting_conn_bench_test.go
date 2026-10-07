package mtglib

import (
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Arman2122/mtg-proxy/essentials"
	"github.com/stretchr/testify/require"
)

// countingChunk is what one Read or one Write hands countingConn in these
// benchmarks: 16 KiB. The relay's buffer is tls.MaxRecordPayloadSize (relay's
// bufPoolSize, on every target but the constrained MIPS ones), so a 16 KiB
// chunk is exactly what each relay Read and Write gives the wrapper in
// production, and a benchmark that moved 64 KiB at a time would time a call the
// relay never makes.
const countingChunk = 16 << 10

// farEnd is the other end of a countingConn in a benchmark: an in-memory
// essentials.Conn that does nothing a benchmark could mistake for the
// wrapper's own work. A net.Pipe pair is synchronous and costs a goroutine
// switch per call, which would be most of what the benchmark measured.
//
// Read reports len(p) bytes without touching p. The buffer the benchmark hands
// in is a zero-filled slice nobody ever writes to, so it already is the zero
// payload a filling Read would produce -- and a 16 KiB copy per call would cost
// more than everything countingConn does, hiding exactly the per-call work the
// A/B is about. Write discards. Both keep their own tally, kept apart from
// what countingConn counts so the two can be compared: the wrapper faithfully
// counts whatever its far end returns, so a far end that dropped a byte would
// otherwise agree with it.
//
// One goroutine uses it, so the tallies are plain integers.
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

// countingBench is the wrapper under test as the relay builds it -- over the
// user's stats, with the activity stamp ServeConn points it at -- for a user
// with no limit of any kind, and the far end behind it.
//
// The rows are named by what the connection has besides the user: noentry is
// nothing, and the rows that add a per-address entry, a ceiling and a fair share
// take the same parents and the same chunk, so a figure for one is a figure for
// the other.
func countingBench(b *testing.B) (*countingConn, *farEnd, *secretStats, *atomic.Int64) {
	b.Helper()

	stats := NewProxyStats()
	far := &farEnd{}
	active := new(atomic.Int64)
	conn := newCountingConn(b.Context(), nil, far, stats, "alice").withActivity(active)
	st := stats.getOrCreate("alice")

	// The row is about an unlimited user: a limiter, a direction cap or a quota
	// in place would time the paced path under the unpaced name.
	require.Nil(b, st.speed.limiter.Load(), "the user must have no speed limit")
	require.Nil(b, st.speedUp.limiter.Load(), "the user must have no upload limit")
	require.Nil(b, st.speedDown.limiter.Load(), "the user must have no download limit")
	require.Zero(b, st.quotaCeiling.Load(), "the user must have no quota ceiling")

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
