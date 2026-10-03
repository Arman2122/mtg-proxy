package testclient

import (
	"bytes"
	"crypto/rand"
	"io"
	"net"
	"runtime"
	"testing"
	"time"

	"github.com/Arman2122/mtg-proxy/essentials"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// What goes through NewRecordConn arrives byte-exact, in records no larger than
// the proxy itself writes, and the reading side skips records that carry no
// application data.
func TestRecordConnRoundTrip(t *testing.T) {
	t.Parallel()

	near, far := net.Pipe()
	t.Cleanup(func() {
		near.Close() //nolint: errcheck
		far.Close()  //nolint: errcheck
	})

	conn := NewRecordConn(essentials.WrapNetConn(near))

	sent := make([]byte, 100<<10)
	_, err := rand.Read(sent)
	require.NoError(t, err)

	go func() {
		_, err := conn.Write(sent)
		assert.NoError(t, err)
	}()

	var got bytes.Buffer

	for got.Len() < len(sent) {
		record, err := ReadRecord(far)
		require.NoError(t, err)
		require.EqualValues(t, TypeApplicationData, record.Type)
		require.LessOrEqual(t, len(record.Payload), MaxRecordPayload)
		got.Write(record.Payload)
	}

	assert.Equal(t, sent, got.Bytes(), "what was written must arrive, in records")

	answer := []byte("the answer, after a change-cipher-spec record")

	go func() {
		_, err := far.Write(append([]byte{TypeChangeCipherSpec, 3, 3, 0, 1, 1}, ApplicationRecord(answer)...))
		assert.NoError(t, err)
	}()

	read := make([]byte, len(answer))
	_, err = io.ReadFull(conn, read)
	require.NoError(t, err)
	assert.Equal(t, answer, read, "a record with no application data is skipped")
}

// A record layer made for an idle connection costs little once it has carried
// a byte each way: its buffers grow to what the connection used, not to the
// most a bulk transfer could use.
func TestASmallRecordConnHoldsLittle(t *testing.T) { //nolint: paralleltest // reads the heap
	const conns = 64

	var before, after runtime.MemStats

	runtime.GC()
	runtime.ReadMemStats(&before)

	held := make([]essentials.Conn, 0, conns)

	for range conns {
		near, far := net.Pipe()
		t.Cleanup(func() {
			near.Close() //nolint: errcheck
			far.Close()  //nolint: errcheck
		})

		conn := NewRecordConnSize(essentials.WrapNetConn(near), 4<<10)

		go func() {
			ReadRecord(far)                         //nolint: errcheck
			far.Write(ApplicationRecord([]byte{1})) //nolint: errcheck
		}()

		_, err := conn.Write([]byte{1})
		require.NoError(t, err)

		_, err = io.ReadFull(conn, make([]byte, 1))
		require.NoError(t, err)

		held = append(held, conn)
	}

	runtime.GC()
	runtime.ReadMemStats(&after)

	perConn := (int64(after.HeapAlloc) - int64(before.HeapAlloc)) / conns //nolint: gosec // heap sizes
	assert.Less(t, perConn, int64(8<<10), "an idle record layer holds %d bytes", perConn)
	runtime.KeepAlive(held)
}

// failAfter takes n writes, then fails every one.
type failAfter struct {
	essentials.Conn

	n int
}

func (f *failAfter) Write(p []byte) (int, error) {
	if f.n == 0 {
		return 0, io.ErrClosedPipe
	}

	f.n--

	return len(p), nil
}

// A Write that fails partway reports what went out before the failure, as the
// io.Writer contract asks -- accounting after a dropped connection reads it.
func TestRecordConnCountsWhatWentOutBeforeAnError(t *testing.T) {
	t.Parallel()

	conn := NewRecordConn(&failAfter{n: 1})

	n, err := conn.Write(make([]byte, 200<<10))
	require.ErrorIs(t, err, io.ErrClosedPipe)
	assert.Equal(t, recordsPerWrite*MaxRecordPayload, n, "one whole batch went out")
}

// A TLS alert ends the stream with an error, rather than being skipped like a
// record that carries no data.
func TestRecordConnRefusesAnAlert(t *testing.T) {
	t.Parallel()

	near, far := net.Pipe()
	t.Cleanup(func() {
		near.Close() //nolint: errcheck
		far.Close()  //nolint: errcheck
	})

	go far.Write([]byte{TypeAlert, 3, 3, 0, 2, 2, 40}) //nolint: errcheck

	// A reader that skipped the alert would wait for ever; the deadline turns
	// that into a failure.
	require.NoError(t, near.SetReadDeadline(time.Now().Add(5*time.Second)))

	_, err := NewRecordConn(essentials.WrapNetConn(near)).Read(make([]byte, 16))
	require.ErrorIs(t, err, errAlert)
}

func TestReadServerFlightNeedsThreeRecords(t *testing.T) {
	t.Parallel()

	two := append(ApplicationRecord([]byte("hello")), ApplicationRecord([]byte("ccs"))...)
	_, _, err := ReadServerFlight(bytes.NewReader(two))
	require.Error(t, err, "two records are not a flight")

	three := append(two, ApplicationRecord([]byte("noise"))...)
	records, flight, err := ReadServerFlight(bytes.NewReader(three))
	require.NoError(t, err)
	assert.Len(t, records, 3)
	assert.Equal(t, three, flight, "the flight is the records' bytes, in order")
}

// A header declaring more than a record may carry is named, not read: it is how
// a stream that is not a TLS record layer shows up.
func TestReadRecordRefusesAnImpossibleLength(t *testing.T) {
	t.Parallel()

	_, err := ReadRecord(bytes.NewReader([]byte{TypeApplicationData, 3, 3, 0xff, 0xff}))
	require.ErrorContains(t, err, "not a TLS record layer")
}
