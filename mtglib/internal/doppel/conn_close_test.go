package doppel

import (
	"io"
	"net"
	"testing"
	"time"

	"github.com/Arman2122/mtg-proxy/essentials"
	"github.com/Arman2122/mtg-proxy/mtglib/internal/tls"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// doppelPair is a doppelganger conn over the near end of a loopback pair, and
// the far end the client reads.
func doppelPair(t *testing.T, stats Stats, shaping Shaping) (Conn, net.Conn) {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	defer listener.Close() //nolint: errcheck

	far, err := net.Dial("tcp", listener.Addr().String())
	require.NoError(t, err)

	near, err := listener.Accept()
	require.NoError(t, err)

	t.Cleanup(func() {
		far.Close()  //nolint: errcheck
		near.Close() //nolint: errcheck
	})

	conn := NewConn(t.Context(), essentials.WrapNetConn(near), stats, shaping)
	t.Cleanup(conn.Stop)

	return conn, far
}

// recordPayloadToEOF reads TLS records off far until EOF and returns how many
// payload bytes they carried. Anything but a clean EOF fails the test.
func recordPayloadToEOF(t *testing.T, far net.Conn) <-chan int {
	t.Helper()

	total := make(chan int, 1)

	go func() {
		defer close(total)

		far.SetReadDeadline(time.Now().Add(10 * time.Second)) //nolint: errcheck

		sum := 0

		for {
			_, n, err := tls.ReadRecord(far, io.Discard)
			if err == io.EOF { //nolint: errorlint // ReadRecord returns io.ReadFull's bare EOF at a record boundary
				total <- sum

				return
			}

			if err != nil {
				t.Errorf("the client must see whole records and then a clean EOF: %v", err)

				return
			}

			sum += int(n)
		}
	}()

	return total
}

// CloseWrite is the end of a response, not an abort. What the relay already
// handed over is still on its way to the client, at the pace it was going, and
// only then does the client see EOF.
func TestConnCloseWriteDeliversWhatIsBuffered(t *testing.T) {
	t.Parallel()

	// About a millisecond between records: paced, but quick to drain.
	conn, far := doppelPair(t, Stats{k: 2, lambda: 1}, ShapingRecord)
	total := recordPayloadToEOF(t, far)

	payload := make([]byte, 200_000)

	_, err := conn.Write(payload)
	require.NoError(t, err)
	require.NoError(t, conn.CloseWrite())

	assert.Equal(t, len(payload), <-total, "every buffered byte must reach the client before its EOF")
}

// A client that stops reading cannot hold the stream open: CloseWrite gives up
// after DrainTimeout, and what is still buffered is dropped.
func TestConnCloseWriteGivesUpAfterTheDrainTimeout(t *testing.T) {
	t.Parallel()

	// A minute between records on average: the buffer cannot drain in time.
	conn, _ := doppelPair(t, Stats{k: 1, lambda: 60_000}, ShapingRecord)

	_, err := conn.Write(make([]byte, 200_000))
	require.NoError(t, err)

	started := time.Now()

	conn.CloseWrite() //nolint: errcheck

	elapsed := time.Since(started)
	assert.GreaterOrEqual(t, elapsed, DrainTimeout, "CloseWrite must try for the whole drain timeout")
	assert.Less(t, elapsed, DrainTimeout+2*time.Second, "and not much longer")
}
