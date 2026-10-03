package webrelay

import (
	"bytes"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/Arman2122/mtg-proxy/essentials"
	"github.com/Arman2122/mtg-proxy/internal/testclient"
	"github.com/Arman2122/mtg-proxy/internal/webrelay/frame"
	"github.com/Arman2122/mtg-proxy/mtglib/obfuscation"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// pattern is stream id's byte at offset k: different for every stream and
// every position, so a byte from the wrong stream, the wrong place or a
// poisoned buffer cannot pass for the right one.
func pattern(id uint32, k int) byte { return byte((k*7 + int(id)*13) % 251) }

func fillPattern(dst []byte, id uint32, from int) {
	for i := range dst {
		dst[i] = pattern(id, from+i)
	}
}

// sendPattern writes n pattern bytes, in pieces, from a fresh buffer each
// time: the obfuscated2 writer encrypts what it is given in place.
func sendPattern(conn io.Writer, id uint32, from, n int) error {
	buf := make([]byte, 64<<10)

	for at := from; at < from+n; {
		piece := buf[:min(len(buf), from+n-at)]
		fillPattern(piece, id, at)

		if _, err := conn.Write(piece); err != nil {
			return err //nolint: wrapcheck
		}

		at += len(piece)
	}

	return nil
}

// expectPattern reads n bytes and checks each is the pattern's.
func expectPattern(conn io.Reader, id uint32, from, n int) error {
	buf := make([]byte, 64<<10)
	want := make([]byte, len(buf))

	for at := from; at < from+n; {
		got, err := io.ReadFull(conn, buf[:min(len(buf), from+n-at)])
		fillPattern(want[:got], id, at)

		if !bytes.Equal(buf[:got], want[:got]) {
			return errors.New("a byte arrived wrong") //nolint: err113
		}

		if err != nil {
			return err //nolint: wrapcheck
		}

		at += got
	}

	return nil
}

// echoTrip sends n pattern bytes through the echo Telegram and reads them
// back, both at once.
func echoTrip(t *testing.T, conn io.ReadWriter, id uint32, from, n int) {
	t.Helper()

	wrote := make(chan error, 1)

	go func() { wrote <- sendPattern(conn, id, from, n) }()

	require.NoError(t, expectPattern(conn, id, from, n), "%d bytes from %d", n, from)
	require.NoError(t, <-wrote)
}

// The relay reads a backend that sends a byte, then megabytes, then a few
// bytes, then megabytes, switching its read buffer between the small and the
// large size as it goes. Every byte arrives in order, and the stream's credit
// is still exact afterwards: a 16 MiB transfer, four times the window, still
// completes.
func TestABurstyBackendIsRelayedExactly(t *testing.T) {
	t.Parallel()

	c := newChain(t)
	conn, _ := c.openStream(t, 5)
	require.NoError(t, conn.SetDeadline(time.Now().Add(30*time.Second)))

	at := 0

	for _, n := range []int{1, 3 << 20, 10, 3 << 20, 1} {
		echoTrip(t, conn, 5, at, n)
		at += n

		time.Sleep(50 * time.Millisecond)
	}

	echoTrip(t, conn, 5, at, 16<<20)
}

// Streams sharing one session pass pooled buffers through one write loop.
// Half of them are closed mid-transfer; the other half still receive every
// byte exactly -- which a buffer released while still in use, poisoned by the
// tests, would break.
func TestStreamsClosingMidTransferNeverCorruptOthers(t *testing.T) {
	t.Parallel()

	const (
		streams = 32
		size    = 2 << 20
	)

	c := newChain(t)

	session, err := testclient.OpenWebSession(t.Context(), c.server.URL, c.capability.String(),
		testclient.WebOptions{Origin: originHost})
	require.NoError(t, err)

	t.Cleanup(func() { session.Close() }) //nolint: errcheck

	var wg sync.WaitGroup

	for i := range streams {
		id := uint32(i + 1) //nolint: gosec // a small stream id

		stream, err := session.OpenStream(id)
		require.NoError(t, err)

		conn, err := obfuscation.Obfuscator{Secret: c.key[:]}.SendHandshake(stream, 2, obfuscation.TagPaddedIntermediate)
		require.NoError(t, err)
		require.NoError(t, conn.SetDeadline(time.Now().Add(60*time.Second)))

		wg.Go(func() {
			if id%2 == 0 {
				// Half way, the client drops the stream.
				go sendPattern(conn, id, 0, size) //nolint: errcheck // cut off by the close

				assert.NoError(t, expectPattern(conn, id, 0, size/2), "stream %d before its close", id)
				conn.Close() //nolint: errcheck

				return
			}

			wrote := make(chan error, 1)

			go func() { wrote <- sendPattern(conn, id, 0, size) }()

			assert.NoError(t, expectPattern(conn, id, 0, size), "stream %d", id)
			assert.NoError(t, <-wrote, "stream %d", id)
		})
	}

	wg.Wait()
}

// A carrier write that fails ends the session: a message half on the wire
// cannot be continued. No pooled buffer is released twice on the way out --
// a second release panics in the tests.
func TestAFailedCarrierWriteEndsTheSession(t *testing.T) {
	t.Parallel()

	carrier := newTestCarrier()
	carrier.failWrites.Store(true)

	h := newHarnessOn(t, carrier, SessionOptions{})
	h.send(frame.NewOpen(1))

	backend := h.backend.accept(t)

	go func() {
		chunk := bytes.Repeat([]byte{7}, 64<<10)

		for range 16 {
			if _, err := backend.Write(chunk); err != nil {
				return
			}
		}
	}()

	require.Error(t, h.fatal(), "the session must end when its carrier cannot be written")
}

var _ essentials.Conn = (*testclient.WebStream)(nil)
