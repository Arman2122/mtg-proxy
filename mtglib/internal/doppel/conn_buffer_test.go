package doppel

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/Arman2122/mtg-proxy/essentials"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// boundPair is a doppelganger conn over a loopback pair whose socket buffers
// are small, so the kernel cannot quietly absorb megabytes a slow client never
// reads -- the queue is what has to hold the line. The sockets close before
// the conn stops: a writer blocked in a socket write only returns when its
// socket closes, and Stop waits for the writer.
func boundPair(t *testing.T, ctx context.Context, stats Stats) (Conn, net.Conn) {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	defer listener.Close() //nolint: errcheck

	far, err := net.Dial("tcp", listener.Addr().String())
	require.NoError(t, err)

	near, err := listener.Accept()
	require.NoError(t, err)

	require.NoError(t, near.(*net.TCPConn).SetWriteBuffer(64<<10)) //nolint: forcetypeassert
	require.NoError(t, far.(*net.TCPConn).SetReadBuffer(64<<10))   //nolint: forcetypeassert

	conn := NewConn(ctx, essentials.WrapNetConn(near), stats, ShapingRecord)

	t.Cleanup(conn.Stop)
	t.Cleanup(func() {
		far.Close()  //nolint: errcheck
		near.Close() //nolint: errcheck
	})

	return conn, far
}

func (c Conn) queued() int {
	c.p.writtenCond.L.Lock()
	defer c.p.writtenCond.L.Unlock()

	return c.p.writeStream.Len()
}

// writeAll writes total bytes in 16 KiB pieces and reports how it ended.
func writeAll(conn Conn, total int) <-chan error {
	done := make(chan error, 1)

	go func() {
		piece := make([]byte, 16<<10)

		for written := 0; written < total; written += len(piece) {
			if _, err := conn.Write(piece); err != nil {
				done <- err

				return
			}
		}

		done <- nil
	}()

	return done
}

// A client that stops reading stops the relay, not the heap: the queue holds
// at most MaxBuffered plus one write, and the writer waits. When the client
// reads again every byte arrives.
func TestConnWriteBlocksAtTheBufferBound(t *testing.T) {
	t.Parallel()

	const total = 8 << 20

	conn, far := boundPair(t, t.Context(), Stats{k: 2, lambda: 1})
	done := writeAll(conn, total)

	time.Sleep(500 * time.Millisecond)

	assert.LessOrEqual(t, conn.queued(), MaxBuffered+16<<10, "the queue must stop at the bound")

	select {
	case err := <-done:
		t.Fatalf("the write finished against a client that reads nothing: %v", err)
	default:
	}

	received := recordPayloadToEOF(t, far)

	require.NoError(t, <-done)
	require.NoError(t, conn.CloseWrite())
	assert.Equal(t, total, <-received, "every byte must arrive once the client reads again")
}

// Stop releases a Write blocked on the bound, as it must for a kick or a
// shutdown to end the stream at once.
func TestConnStopReleasesABlockedWrite(t *testing.T) {
	t.Parallel()

	conn, _ := boundPair(t, t.Context(), Stats{k: 2, lambda: 1})
	done := writeAll(conn, 1<<30)

	time.Sleep(300 * time.Millisecond)

	go conn.Stop()

	select {
	case err := <-done:
		require.Error(t, err)
	case <-time.After(time.Second):
		t.Fatal("Stop left a Write blocked on the full queue")
	}
}

// The conn's context ending releases a blocked Write too: the stream's context
// is what a quota cut or the proxy stopping cancels.
func TestConnCancelReleasesABlockedWrite(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	conn, _ := boundPair(t, ctx, Stats{k: 2, lambda: 1})
	done := writeAll(conn, 1<<30)

	time.Sleep(300 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		require.Error(t, err)
	case <-time.After(time.Second):
		t.Fatal("cancelling the context left a Write blocked on the full queue")
	}
}
