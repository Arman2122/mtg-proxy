package doppel

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/Arman2122/mtg-proxy/essentials"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Every test here runs in both shapings: the queue, its bound and every way
// out of a blocked Write belong to the conn, not to one way of pacing it.
var shapings = []struct {
	name    string
	shaping Shaping
}{
	{"record", ShapingRecord},
	{"burst", ShapingBurst},
}

// boundPair is a doppelganger conn over a loopback pair whose socket buffers
// are small, so the kernel cannot quietly absorb megabytes a slow client never
// reads -- the queue is what has to hold the line. It returns the conn, the
// client's end and the conn's own socket. The sockets close before the conn
// stops: a writer blocked in a socket write only returns when its socket
// closes, and Stop waits for the writer.
func boundPair(t *testing.T, ctx context.Context, stats Stats, shaping Shaping) (Conn, net.Conn, net.Conn) {
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

	conn := NewConn(ctx, essentials.WrapNetConn(near), stats, shaping)

	t.Cleanup(conn.Stop)
	t.Cleanup(func() {
		far.Close()  //nolint: errcheck
		near.Close() //nolint: errcheck
	})

	return conn, far, near
}

func (c Conn) queued() int {
	c.p.writtenCond.L.Lock()
	defer c.p.writtenCond.L.Unlock()

	return c.p.writeStream.Len()
}

func (c Conn) queueCap() int {
	c.p.writtenCond.L.Lock()
	defer c.p.writtenCond.L.Unlock()

	return c.p.writeStream.Cap()
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

// expectReleased waits for a Write blocked on the full queue to come back
// with an error.
func expectReleased(t *testing.T, done <-chan error, how string) {
	t.Helper()

	select {
	case err := <-done:
		require.Error(t, err)
	case <-time.After(time.Second):
		t.Fatalf("%s left a Write blocked on the full queue", how)
	}
}

// A client that stops reading stops the relay, not the heap: the queue holds
// at most MaxBuffered plus one write, and the writer waits. When the client
// reads again every byte arrives.
func TestConnWriteBlocksAtTheBufferBound(t *testing.T) {
	t.Parallel()

	for _, s := range shapings {
		t.Run(s.name, func(t *testing.T) {
			t.Parallel()

			const total = 8 << 20

			conn, far, _ := boundPair(t, t.Context(), Stats{k: 2, lambda: 1}, s.shaping)
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
		})
	}
}

// Stop releases a Write blocked on the bound: the proxy shutting down.
func TestConnStopReleasesABlockedWrite(t *testing.T) {
	t.Parallel()

	for _, s := range shapings {
		t.Run(s.name, func(t *testing.T) {
			t.Parallel()

			conn, _, _ := boundPair(t, t.Context(), Stats{k: 2, lambda: 1}, s.shaping)
			done := writeAll(conn, 1<<30)

			time.Sleep(300 * time.Millisecond)

			go conn.Stop()

			expectReleased(t, done, "Stop")
		})
	}
}

// The conn's context ending releases a blocked Write too. That context is the
// ganger's, so this is the proxy stopping; a kick or a quota cut closes the
// socket instead, which the next test covers.
func TestConnCancelReleasesABlockedWrite(t *testing.T) {
	t.Parallel()

	for _, s := range shapings {
		t.Run(s.name, func(t *testing.T) {
			t.Parallel()

			ctx, cancel := context.WithCancel(t.Context())
			conn, _, _ := boundPair(t, ctx, Stats{k: 2, lambda: 1}, s.shaping)
			done := writeAll(conn, 1<<30)

			time.Sleep(300 * time.Millisecond)
			cancel()

			expectReleased(t, done, "cancelling the context")
		})
	}
}

// A kick or a quota cut ends a stream by closing its socket: the writer's next
// socket write fails, and that must release a Write blocked on the bound.
func TestConnSocketCloseReleasesABlockedWrite(t *testing.T) {
	t.Parallel()

	for _, s := range shapings {
		t.Run(s.name, func(t *testing.T) {
			t.Parallel()

			conn, _, near := boundPair(t, t.Context(), Stats{k: 2, lambda: 1}, s.shaping)
			done := writeAll(conn, 1<<30)

			time.Sleep(300 * time.Millisecond)
			near.Close() //nolint: errcheck

			expectReleased(t, done, "closing the socket")
		})
	}
}

// Stop cuts at once even while the writer is busy sending to a slow client
// with its socket still open: the writer must not finish the queue first.
func TestConnStopIsPromptWhileSending(t *testing.T) {
	t.Parallel()

	for _, s := range shapings {
		t.Run(s.name, func(t *testing.T) {
			t.Parallel()

			conn, far, _ := boundPair(t, t.Context(), Stats{k: 2, lambda: 1}, s.shaping)

			// A client taking ~800 KiB/s: the queue stays full and the writer stays
			// busy.
			go func() {
				buf := make([]byte, 16<<10)

				for {
					if _, err := far.Read(buf); err != nil {
						return
					}

					time.Sleep(20 * time.Millisecond)
				}
			}()

			writeAll(conn, 1<<30)
			time.Sleep(500 * time.Millisecond)

			started := time.Now()

			conn.Stop()

			assert.Less(t, time.Since(started), 200*time.Millisecond,
				"Stop must not wait for the writer to send what is queued")
		})
	}
}

// The queue lets go of its peak once it has drained: a connection that once
// buffered a download does not keep that memory for the rest of its life.
func TestConnQueueLetsGoOfItsPeak(t *testing.T) {
	t.Parallel()

	for _, s := range shapings {
		t.Run(s.name, func(t *testing.T) {
			t.Parallel()

			const total = 4 << 20

			conn, far, _ := boundPair(t, t.Context(), Stats{k: 2, lambda: 1}, s.shaping)
			done := writeAll(conn, total)

			time.Sleep(300 * time.Millisecond) // the client reads nothing yet: the queue fills
			require.Greater(t, conn.queueCap(), keepQueueMax, "precondition: the queue grew past what it keeps")

			go io.Copy(io.Discard, far) //nolint: errcheck

			require.NoError(t, <-done)
			require.Eventually(t, func() bool { return conn.queued() == 0 }, 5*time.Second, 10*time.Millisecond)

			assert.LessOrEqual(t, conn.queueCap(), keepQueueMax, "a drained queue must let go of its peak")
		})
	}
}
