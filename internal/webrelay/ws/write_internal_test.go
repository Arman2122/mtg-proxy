package ws

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// A message is one write whatever the connection. Go's vectored write falls
// back to a write per vector on a connection that is not a bare TCP socket --
// the relay's own, behind a PROXY-protocol listener, is wrapped -- and nine
// small writes on a socket with Nagle off are nine segments.
func TestWriteBuffersIsOneWriteOnAnyConn(t *testing.T) {
	t.Parallel()

	bufs := make([][]byte, 17)
	for i := range bufs {
		bufs[i] = bytes.Repeat([]byte{byte(i)}, 8+i*100)
	}

	c, conn := connOver(nil, Options{})
	require.NoError(t, c.WriteBuffers(bufs))
	require.Equal(t, 1, conn.writes, "one message, one write")

	reference, joined := connOver(nil, Options{})
	require.NoError(t, reference.Write(bytes.Join(bufs, nil)))
	require.Equal(t, joined.out.Bytes(), conn.out.Bytes())
}

// tcpWrapper is a listener's wrapper around a TCP socket that, like the
// PROXY-protocol one, says what it wraps.
type tcpWrapper struct {
	net.Conn

	tcp *net.TCPConn
}

func (w tcpWrapper) TCPConn() (*net.TCPConn, bool) { return w.tcp, true }

// Behind a wrapper that names its TCP socket, the vectored write goes to that
// socket -- one writev -- and the bytes arrive exactly.
func TestWriteBuffersReachesTheTCPConnBehindAWrapper(t *testing.T) {
	t.Parallel()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { listener.Close() }) //nolint: errcheck

	accepted := make(chan net.Conn, 1)

	go func() {
		conn, err := listener.Accept()
		if err == nil {
			accepted <- conn
		}
	}()

	peer, err := net.Dial("tcp", listener.Addr().String())
	require.NoError(t, err)
	t.Cleanup(func() { peer.Close() }) //nolint: errcheck

	server := <-accepted
	t.Cleanup(func() { server.Close() }) //nolint: errcheck

	tcp, ok := server.(*net.TCPConn)
	require.True(t, ok)

	c := newConn(tcpWrapper{Conn: server, tcp: tcp}, bufio.NewReader(server), Options{}.withDefaults())
	require.Same(t, tcp, c.vectored, "the vectored write goes to the socket under the wrapper")

	bufs := [][]byte{bytes.Repeat([]byte{1}, 300), bytes.Repeat([]byte{2}, 70000)}
	require.NoError(t, c.WriteBuffers(bufs))

	want := appendHeader(nil, opBinary, 70300)
	want = append(want, bytes.Join(bufs, nil)...)

	got := make([]byte, len(want))
	require.NoError(t, peer.SetReadDeadline(time.Now().Add(5*time.Second)))
	_, err = io.ReadFull(peer, got)
	require.NoError(t, err)
	require.Equal(t, want, got)
}

// One message written as vectors is, on the wire, the message Write sends:
// the relay sends its batches this way, with no buffer joining them first.
func TestWriteBuffersSendsWhatWriteSends(t *testing.T) {
	t.Parallel()

	piece := func(n int, b byte) []byte { return bytes.Repeat([]byte{b}, n) }

	many := make([][]byte, 300)
	for i := range many {
		many[i] = piece(300, byte(i))
	}

	for name, bufs := range map[string][][]byte{
		"one short slice":                      {piece(10, 1)},
		"16-bit length, an empty slice inside": {piece(100, 2), {}, piece(200, 3)},
		"64-bit length, 300 slices":            many,
		"nothing at all":                       {},
	} {
		vectored, conn := connOver(nil, Options{})
		require.NoError(t, vectored.WriteBuffers(bufs), name)

		joined, reference := connOver(nil, Options{})
		require.NoError(t, joined.Write(bytes.Join(bufs, nil)), name)

		require.Equal(t, reference.out.Bytes(), conn.out.Bytes(), name)
	}
}
