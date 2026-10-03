package main

import (
	"context"
	"encoding/binary"
	"io"
	"math"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Arman2122/mtg-proxy/essentials"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// echoPipe is a client whose far end is a data centre that answers echo
// commands, in memory.
func echoPipe(t *testing.T) *Client {
	t.Helper()

	near, far := net.Pipe()

	go func() {
		defer far.Close() //nolint: errcheck

		var command [commandSize]byte

		for {
			if _, err := io.ReadFull(far, command[:]); err != nil {
				return
			}

			message := make([]byte, binary.BigEndian.Uint64(command[1:]))
			if _, err := io.ReadFull(far, message); err != nil {
				return
			}

			if _, err := far.Write(message); err != nil {
				return
			}
		}
	}()

	return &Client{Conn: essentials.WrapNetConn(near), close: near.Close}
}

// A hello the proxy fronts -- an anti-replay false positive, about one in a
// thousand at a high handshake rate -- is the proxy working as designed. The
// handshake scenario counts it as fronted, apart from failures.
func TestHandshakeScenarioCountsFrontingSeparately(t *testing.T) {
	t.Parallel()

	var calls, fronted atomic.Int64

	dial := func(context.Context) (*Client, error) {
		if calls.Add(1)%10 == 0 {
			fronted.Add(1)

			return nil, errFronted
		}

		return echoPipe(t), nil
	}

	h := runHandshakes(t.Context(), 4, 300*time.Millisecond, dial)

	require.Positive(t, fronted.Load(), "the test injected no fronting")
	assert.Equal(t, fronted.Load(), h.fronted)
	assert.Zero(t, h.failed, "a fronted hello is not a failure: %v", h.err)
	assert.Equal(t, calls.Load()-fronted.Load(), h.connected)
	assert.Len(t, h.firstByte, int(h.connected))

	s := h.sample(300 * time.Millisecond)
	assert.InDelta(t, float64(fronted.Load()), s["fronted"], 0)
	assert.Zero(t, s["failed"])
}

// shortDC answers download commands, but its last byte never comes: it hangs
// up one byte short.
type shortDC struct{ pending int64 }

func (d *shortDC) Write(p []byte) (int, error) {
	for rest := p; len(rest) >= commandSize; rest = rest[commandSize:] {
		d.pending += int64(binary.BigEndian.Uint64(rest[1:commandSize])) //nolint: gosec // test counts
	}

	return len(p), nil
}

func (d *shortDC) Read(p []byte) (int, error) {
	if d.pending <= 1 {
		return 0, io.EOF
	}

	n := min(int64(len(p)), d.pending-1)
	clear(p[:n])
	d.pending -= n

	return int(n), nil
}

// A bulk run that loses a byte has no result: it fails, however fast it was.
func TestBulkScenarioFailsOnAShortCount(t *testing.T) {
	t.Parallel()

	_, err := runBulk(t.Context(), []io.ReadWriter{&shortDC{}}, true, Options{Measure: 50 * time.Millisecond}, nil)
	require.ErrorIs(t, err, io.ErrUnexpectedEOF)
}

// lyingDC takes uploads and acknowledges one byte fewer than each chunk. It
// closes stop as soon as the first chunk is in, so the only acknowledgement is
// the one collected after the stop.
type lyingDC struct {
	chunk, got int64
	stop       chan struct{}
	once       sync.Once
}

func (d *lyingDC) Write(p []byte) (int, error) {
	if d.got += int64(len(p)); d.got >= commandSize+d.chunk {
		d.once.Do(func() { close(d.stop) })
	}

	return len(p), nil
}

func (d *lyingDC) Read(p []byte) (int, error) {
	binary.BigEndian.PutUint64(p, uint64(d.chunk-1)) //nolint: gosec // a test count

	return 8, nil
}

// An upload is proven to the last chunk: the ones still in flight when the run
// stops are acknowledged too, and a short count there fails the run.
func TestAnUploadIsAcknowledgedToTheLastChunk(t *testing.T) {
	t.Parallel()

	stop := make(chan struct{})

	err := pump(&lyingDC{chunk: 1 << 10, stop: stop}, false, 1<<10, stop, new(atomic.Int64))
	require.ErrorIs(t, err, errShortAck)
}

// Bulk transfers keep commands in flight, so the pipe does not drain between
// chunks, and still account for every byte: what the client counts is what
// the data centre counts, both ways.
func TestBulkMovesEveryChunkThroughTheDataCentre(t *testing.T) {
	t.Parallel()

	for _, download := range []bool{true, false} {
		dc := startTestDC(t)

		conns := make([]io.ReadWriter, 2)
		for i := range conns {
			conn, err := dialAsProxy(t, dc, "149.154.167.51:443")
			require.NoError(t, err)

			conns[i] = conn
		}

		w, err := runBulk(t.Context(), conns, download, Options{Warmup: 50 * time.Millisecond, Measure: 200 * time.Millisecond}, nil)
		require.NoError(t, err)
		assert.Positive(t, w.bytes)
		assert.Positive(t, w.rate())

		counted := dc.BytesReceived
		if download {
			counted = dc.BytesSent
		}

		assert.Eventually(t, func() bool { return counted() == w.total }, 5*time.Second, time.Millisecond,
			"download=%v: the client moved %d, the data centre %d", download, w.total, counted())
		assert.Zero(t, w.total%bulkChunk, "only whole chunks are moved")
	}
}

// A connection the proxy fronts reaches the cover site, which mtgbench's cover
// listener answers by hanging up. The ee client names that, rather than
// reporting a broken handshake.
func TestAFrontedHelloIsNamedAsSuch(t *testing.T) {
	t.Parallel()

	for _, answer := range []string{"", "HTTP/1.1 400 Bad Request\r\n\r\n"} {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		t.Cleanup(func() { listener.Close() }) //nolint: errcheck

		go func() {
			c, err := listener.Accept()
			if err != nil {
				return
			}

			c.Read(make([]byte, 4096)) //nolint: errcheck
			io.WriteString(c, answer)  //nolint: errcheck
			c.Close()                  //nolint: errcheck
		}()

		s := Setup{BasePort: listener.Addr().(*net.TCPAddr).Port} //nolint: forcetypeassert

		_, err = Dial(t.Context(), s, DoorEE, NewUser("alice"), "")
		if answer == "" {
			require.ErrorIs(t, err, errFronted, "a hang-up before any byte is fronting")
		} else {
			require.Error(t, err)
			require.NotErrorIs(t, err, errFronted, "an answer that is not TLS is a failure")
		}
	}
}

// Only the run's own sockets count: TIME_WAIT (state 06) with one of the run's
// ports at either end.
func TestTimeWaitsCountOnlyTheRunsPorts(t *testing.T) {
	t.Parallel()

	table := "  sl  local_address rem_address   st tx_queue rx_queue\n" +
		"   0: 0100007F:B798 0100007F:D431 06 00000000:00000000\n" + // 47000 here
		"   1: 0100007F:D432 0100007F:B7A2 06 00000000:00000000\n" + // 47010 there
		"   2: 0100007F:B798 0100007F:D433 01 00000000:00000000\n" + // established
		"   3: 0100007F:1F90 0100007F:D434 06 00000000:00000000\n" // someone else's

	assert.Equal(t, 2, countTimeWaits(table, 47000, 47032))
}

// A figure this machine cannot read (CPU and memory off Linux) is null in the
// JSON report, not a report that cannot be written.
func TestTheReportWritesUnreadableFiguresAsNull(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	report := Report{Tables: []Table{{
		Scenario: "bulk",
		Rows:     []Row{{Label: "dd", Samples: []Sample{{"mbps": 100, "cpu-s/gb": math.NaN()}}}},
	}}}

	require.NoError(t, report.write(dir))

	raw, err := os.ReadFile(filepath.Join(dir, "tierB.json"))
	require.NoError(t, err)
	assert.Contains(t, string(raw), `"cpu-s/gb": null`)
	assert.Contains(t, string(raw), `"mbps": 100`)
}

// The tables show the median of the runs with their spread, and a failed row
// says why instead of showing numbers.
func TestTablesShowTheMedianAndSpread(t *testing.T) {
	t.Parallel()

	table := Table{
		Scenario: "bulk",
		Metrics:  []Metric{{Key: "mbps", Title: "MB/s"}},
		Rows: []Row{
			{Label: "dd, 1 conn, download", Samples: []Sample{{"mbps": 300}, {"mbps": 100}, {"mbps": 200}}},
			{Label: "web, 1 conn, download", Err: "short count"},
		},
	}

	var b strings.Builder

	require.NoError(t, table.markdown(&b))

	assert.Contains(t, b.String(), "| dd, 1 conn, download | 200 (100–300) |")
	assert.Contains(t, b.String(), "| web, 1 conn, download | failed: short count |")
}
