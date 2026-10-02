package doppel

import (
	"io"
	"net"
	"testing"
	"time"

	"github.com/Arman2122/mtg-proxy/mtglib/internal/tls"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// seenRecord is one TLS record as the client received it.
type seenRecord struct {
	size int
	at   time.Time
}

// recordsFrom reads TLS records off far as they arrive and reports each one's
// payload size and arrival time; the channel closes at EOF.
func recordsFrom(t *testing.T, far net.Conn) <-chan seenRecord {
	t.Helper()

	records := make(chan seenRecord, 1024)

	go func() {
		defer close(records)

		far.SetReadDeadline(time.Now().Add(30 * time.Second)) //nolint: errcheck

		for {
			_, n, err := tls.ReadRecord(far, io.Discard)
			if err != nil {
				return
			}

			records <- seenRecord{size: int(n), at: time.Now()}
		}
	}()

	return records
}

func sizesOf(records <-chan seenRecord) []int {
	var sizes []int

	for r := range records {
		sizes = append(sizes, r.size)
	}

	return sizes
}

func sum(values []int) int {
	total := 0
	for _, v := range values {
		total += v
	}

	return total
}

// Inside a burst records go back to back. With ~300 ms between records a
// megabyte paced record by record would take ~19 s; in a burst it is one wait
// and then the wire.
func TestBurstSendsRecordsBackToBack(t *testing.T) {
	t.Parallel()

	conn, far := doppelPair(t, Stats{k: 50, lambda: 300}, ShapingBurst)
	records := recordsFrom(t, far)
	started := time.Now()

	go func() {
		conn.Write(make([]byte, 1<<20)) //nolint: errcheck
		conn.CloseWrite()               //nolint: errcheck
	}()

	sizes := sizesOf(records)

	assert.Less(t, time.Since(started), 2*time.Second, "a burst waits once, not once per record")
	require.Equal(t, 1<<20, sum(sizes), "every byte must arrive")

	for i, size := range sizes[:len(sizes)-1] {
		require.Equal(t, TLSRecordSizeMax, size, "record %d must be full-size, exactly as Stats.Size draws it", i)
	}
}

// One website-like wait when the connection wakes from idle, none while it is
// busy, and one again after a second of quiet.
func TestBurstWaitsOnceAfterIdle(t *testing.T) {
	t.Parallel()

	conn, far := doppelPair(t, Stats{k: 50, lambda: 300}, ShapingBurst)
	records := recordsFrom(t, far)

	send := func() time.Time {
		at := time.Now()

		_, err := conn.Write(make([]byte, 1000))
		require.NoError(t, err)

		return at
	}

	first := send()
	assert.GreaterOrEqual(t, (<-records).at.Sub(first), 250*time.Millisecond,
		"a connection waking from idle waits once before its first record")

	time.Sleep(200 * time.Millisecond)

	second := send()
	assert.Less(t, (<-records).at.Sub(second), 50*time.Millisecond,
		"a write within a second of the last one is the same burst: no wait")

	time.Sleep(1200 * time.Millisecond)

	third := send()
	assert.GreaterOrEqual(t, (<-records).at.Sub(third), 250*time.Millisecond,
		"after a second of quiet the next burst waits once again")
}

// Dynamic record sizing survives batching: the records are exactly what
// Stats.Size draws, ramp included.
func TestBurstKeepsDRSRecordSizes(t *testing.T) {
	t.Parallel()

	conn, far := doppelPair(t, Stats{k: 1, lambda: 0, drs: true}, ShapingBurst)
	records := recordsFrom(t, far)

	go func() {
		conn.Write(make([]byte, 600_000)) //nolint: errcheck
		conn.CloseWrite()                 //nolint: errcheck
	}()

	sizes := sizesOf(records)
	require.Equal(t, 600_000, sum(sizes))
	require.Greater(t, len(sizes), TLSCounterMaxAfter+1)

	for i, size := range sizes[:len(sizes)-1] {
		switch {
		case i < TLSCounterAccelAfter:
			assert.InDelta(t, TLSRecordSizeStart-DRSNoise/2, size, DRSNoise/2, "record %d is in the MTU-sized start", i)
		case i < TLSCounterMaxAfter:
			assert.InDelta(t, TLSRecordSizeAccel-DRSNoise/2, size, DRSNoise/2, "record %d is in the 4 KiB ramp", i)
		default:
			assert.Equal(t, TLSRecordSizeMax, size, "record %d is full-size", i)
		}
	}
}

// Record shaping stays what it was: a wait before every record.
func TestRecordShapingIsUnchanged(t *testing.T) {
	t.Parallel()

	conn, far := doppelPair(t, Stats{k: 50, lambda: 100}, ShapingRecord)
	records := recordsFrom(t, far)
	started := time.Now()

	_, err := conn.Write(make([]byte, 64<<10))
	require.NoError(t, err)

	var fourth seenRecord
	for range 4 {
		fourth = <-records
	}

	assert.GreaterOrEqual(t, fourth.at.Sub(started), 350*time.Millisecond,
		"four records under record shaping are four ~100 ms waits")
}
