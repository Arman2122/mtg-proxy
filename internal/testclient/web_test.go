package testclient

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Arman2122/mtg-proxy/internal/webrelay/frame"
	"github.com/Arman2122/mtg-proxy/internal/webrelay/ws"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The relay's own WebSocket server (internal/webrelay/ws) stands in for the
// relay here, so the client is checked against the parser it really meets.

const testSubprotocol = "tproxy-v1.test"

func relayStandIn(t *testing.T, opts ws.Options, serve func(*ws.Conn)) (net.Conn, *bufio.Reader) {
	t.Helper()

	opts.Subprotocol = testSubprotocol

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := ws.Upgrade(w, r, opts)
		if err != nil {
			t.Errorf("upgrade: %v", err)

			return
		}

		serve(conn)
	}))
	t.Cleanup(server.Close)

	conn, reader, err := dialWebSocket(t.Context(), strings.TrimPrefix(server.URL, "http://"), "/",
		testSubprotocol, "example.com", "", 5*time.Second, 256<<10)
	require.NoError(t, err)

	t.Cleanup(func() { conn.Close() }) //nolint: errcheck

	return conn, reader
}

func sessionOver(conn net.Conn, reader *bufio.Reader) *WebSession {
	s := &WebSession{conn: conn, r: reader, streams: make(map[uint32]*WebStream)}
	go s.readLoop()

	return s
}

func relayFrames(t *testing.T, frames ...frame.Frame) []byte {
	t.Helper()

	batch, err := frame.Limits{}.EncodeBatch(nil, frames, frame.RelayToClient)
	require.NoError(t, err)

	return batch
}

func TestMaskingMatchesTheDefinition(t *testing.T) {
	t.Parallel()

	mask := [4]byte{0xde, 0xad, 0xbe, 0xef}

	for n := range 70 {
		payload := make([]byte, n)
		rand.Read(payload) //nolint: errcheck

		fast := append([]byte(nil), payload...)
		maskBytes(fast, mask)

		for i := range payload {
			payload[i] ^= mask[i%4]
		}

		require.True(t, bytes.Equal(payload, fast), "length %d", n)
	}
}

// Every length form, at each boundary, through the relay's own strict parser:
// masking required, minimal lengths required.
func TestEveryLengthFormParsesOnTheRelaysParser(t *testing.T) {
	t.Parallel()

	got := make(chan []byte, 1)

	conn, _ := relayStandIn(t, ws.Options{MaxMessage: 2 << 20}, func(c *ws.Conn) {
		defer close(got)

		for {
			message, err := c.Read()
			if err != nil {
				return
			}

			got <- message
		}
	})

	for _, n := range []int{0, 1, 125, 126, 127, 0xFFFF, 0x10000, webDataChunk + frame.HeaderSize, 1 << 20} {
		payload := make([]byte, n)
		rand.Read(payload) //nolint: errcheck

		_, err := conn.Write(appendClientFrame(nil, opBinary, payload))
		require.NoError(t, err)

		message, ok := <-got
		require.True(t, ok, "length %d: the relay's parser refused the frame", n)
		require.True(t, bytes.Equal(message, payload), "length %d: the payload differs", n)
	}
}

// The relay pings after an idle period and drops the carrier after two. A
// client that answers keeps it; one that does not loses it -- so the test can
// tell the two apart.
func TestPongKeepsAnIdleCarrierAlive(t *testing.T) {
	t.Parallel()

	for _, answers := range []bool{true, false} {
		ended := make(chan error, 1)

		conn, reader := relayStandIn(t, ws.Options{IdleTimeout: 100 * time.Millisecond}, func(c *ws.Conn) {
			_, err := c.Read()
			ended <- err
		})

		if answers {
			sessionOver(conn, reader)
		}

		select {
		case err := <-ended:
			require.False(t, answers, "an answering client lost its carrier: %v", err)
		case <-time.After(1500 * time.Millisecond):
			require.True(t, answers, "a silent client kept its carrier: the test cannot tell")
		}
	}
}

// Writes stay within credit: with no WINDOW exactly the initial window goes
// out, a grant releases exactly that much more, and a Write blocked on credit
// honours its deadline.
func TestWritesStayWithinCredit(t *testing.T) {
	t.Parallel()

	var sent atomic.Int64

	relay := make(chan *ws.Conn, 1)

	conn, reader := relayStandIn(t, ws.Options{MaxMessage: 2 << 20}, func(c *ws.Conn) {
		relay <- c

		for {
			message, err := c.Read()
			if err != nil {
				return
			}

			frames, err := frame.Limits{}.DecodeBatch(message, frame.ClientToRelay)
			if err != nil {
				return
			}

			for _, f := range frames {
				if f.Type == frame.TypeData {
					sent.Add(int64(len(f.Payload)))
				}
			}
		}
	})

	s := sessionOver(conn, reader)
	r := <-relay

	stream, err := s.OpenStream(1)
	require.NoError(t, err)

	wrote := make(chan error, 1)

	go func() {
		_, err := stream.Write(make([]byte, 8<<20))
		wrote <- err
	}()

	require.Eventually(t, func() bool { return sent.Load() == webInitialWindow }, 5*time.Second, 5*time.Millisecond)
	time.Sleep(200 * time.Millisecond)
	require.EqualValues(t, webInitialWindow, sent.Load(), "no DATA beyond the initial window")

	require.NoError(t, r.Write(relayFrames(t, frame.NewWindow(1, 1<<20))))
	require.Eventually(t, func() bool { return sent.Load() == webInitialWindow+1<<20 }, 5*time.Second, 5*time.Millisecond)
	time.Sleep(200 * time.Millisecond)
	require.EqualValues(t, webInitialWindow+1<<20, sent.Load(), "exactly what was granted")

	require.NoError(t, stream.SetWriteDeadline(time.Now().Add(150*time.Millisecond)))

	select {
	case err := <-wrote:
		require.ErrorIs(t, err, os.ErrDeadlineExceeded)
	case <-time.After(3 * time.Second):
		t.Fatal("a Write blocked on credit ignored its deadline")
	}
}

// Close releases a Read and a Write blocked on the stream, on other goroutines.
func TestCloseReleasesABlockedReadAndWrite(t *testing.T) {
	t.Parallel()

	conn, reader := relayStandIn(t, ws.Options{MaxMessage: 2 << 20}, func(c *ws.Conn) {
		for {
			if _, err := c.Read(); err != nil {
				return
			}
		}
	})

	stream, err := sessionOver(conn, reader).OpenStream(1)
	require.NoError(t, err)

	done := make(chan error, 2)

	go func() { _, err := stream.Write(make([]byte, 6<<20)); done <- err }()
	go func() { _, err := stream.Read(make([]byte, 10)); done <- err }()

	time.Sleep(300 * time.Millisecond)
	require.NoError(t, stream.Close())

	for range 2 {
		select {
		case err := <-done:
			require.ErrorIs(t, err, errStreamClosed)
		case <-time.After(3 * time.Second):
			t.Fatal("Close did not release a blocked Read or Write")
		}
	}
}

// A stream the relay closed is the one clean end: Read gives io.EOF, and a
// Write after it fails rather than sending bytes the relay drops.
func TestARemotelyClosedStreamEndsCleanly(t *testing.T) {
	t.Parallel()

	opened := make(chan *ws.Conn, 1)

	conn, reader := relayStandIn(t, ws.Options{MaxMessage: 2 << 20}, func(c *ws.Conn) {
		if _, err := c.Read(); err != nil { // OPEN
			return
		}

		opened <- c

		for {
			if _, err := c.Read(); err != nil {
				return
			}
		}
	})

	stream, err := sessionOver(conn, reader).OpenStream(1)
	require.NoError(t, err)

	require.NoError(t, (<-opened).Write(relayFrames(t, frame.NewClose(1))))

	_, err = stream.Read(make([]byte, 1))
	require.ErrorIs(t, err, io.EOF)

	n, err := stream.Write([]byte("after the relay closed the stream"))
	require.Error(t, err, "a Write after a remote CLOSE must fail")
	assert.Zero(t, n)
}

// A carrier the relay ends -- with a close frame carrying a protocol error, or
// by dropping the socket -- is not a clean end for the streams on it. Neither
// reads as io.EOF, which io.Copy would take for success.
func TestABrokenCarrierIsNotACleanEnd(t *testing.T) {
	t.Parallel()

	t.Run("close frame", func(t *testing.T) {
		t.Parallel()

		opened := make(chan *ws.Conn, 1)

		conn, reader := relayStandIn(t, ws.Options{MaxMessage: 2 << 20}, func(c *ws.Conn) {
			c.Read() //nolint: errcheck // OPEN
			opened <- c
			c.Read() //nolint: errcheck // the client's close echo
		})

		stream, err := sessionOver(conn, reader).OpenStream(1)
		require.NoError(t, err)

		(<-opened).Close(ws.CloseProtocolError, "") //nolint: errcheck

		_, err = stream.Read(make([]byte, 1))
		require.ErrorIs(t, err, errCarrierClosed)
		require.NotErrorIs(t, err, io.EOF)
		require.ErrorContains(t, err, "1002")
	})

	t.Run("dropped socket", func(t *testing.T) {
		t.Parallel()

		server, client := net.Pipe()
		t.Cleanup(func() { client.Close() }) //nolint: errcheck

		// The relay takes the OPEN, whole, and then the socket is gone.
		open, err := frame.Limits{}.EncodeBatch(nil, []frame.Frame{frame.NewOpen(1)}, frame.ClientToRelay)
		require.NoError(t, err)

		openSize := int64(len(appendClientFrame(nil, opBinary, open)))

		go func() {
			io.CopyN(io.Discard, server, openSize) //nolint: errcheck
			server.Close()                         //nolint: errcheck
		}()

		stream, err := sessionOver(client, bufio.NewReader(client)).OpenStream(1)
		require.NoError(t, err)

		_, err = stream.Read(make([]byte, 1))
		require.Error(t, err)
		require.NotErrorIs(t, err, io.EOF)
	})
}

// The relay must not send more than the credit the client granted. One that
// does fails the session: every WEB test is then a check of the relay's
// downlink flow control too.
func TestARelayOverrunningItsCreditFailsTheSession(t *testing.T) {
	t.Parallel()

	opened := make(chan *ws.Conn, 1)

	conn, reader := relayStandIn(t, ws.Options{MaxMessage: 2 << 20}, func(c *ws.Conn) {
		c.Read() //nolint: errcheck // OPEN
		opened <- c

		for {
			if _, err := c.Read(); err != nil {
				return
			}
		}
	})

	session := sessionOver(conn, reader)

	stream, err := session.OpenStream(1)
	require.NoError(t, err)

	r := <-opened
	chunk := make([]byte, 1<<20)

	for range 4 {
		require.NoError(t, r.Write(relayFrames(t, frame.NewData(1, chunk))))
	}

	require.NoError(t, r.Write(relayFrames(t, frame.NewData(1, []byte{1}))), "one byte past the window")

	// Nothing is read until the client has judged the extra byte: reading 1 MiB
	// grants more credit, and the byte would then be within it.
	require.Eventually(t, func() bool {
		session.mu.Lock()
		defer session.mu.Unlock()

		return session.err != nil
	}, 5*time.Second, 5*time.Millisecond, "the overrun never failed the session")

	require.NoError(t, stream.SetReadDeadline(time.Now().Add(5*time.Second)))

	_, err = io.ReadAll(stream)
	require.ErrorIs(t, err, errDownlinkOverrun)
}

// A stream id already open is refused here, rather than letting the relay kill
// the whole carrier for it.
func TestAReusedStreamIDIsRefused(t *testing.T) {
	t.Parallel()

	conn, reader := relayStandIn(t, ws.Options{MaxMessage: 2 << 20}, func(c *ws.Conn) {
		for {
			if _, err := c.Read(); err != nil {
				return
			}
		}
	})

	s := sessionOver(conn, reader)

	_, err := s.OpenStream(5)
	require.NoError(t, err)

	_, err = s.OpenStream(5)
	require.ErrorIs(t, err, errStreamInUse)
}

// The upgrade's Sec-WebSocket-Accept is checked the way a browser checks it.
// RFC 6455 section 1.3 gives the vector.
func TestTheAcceptKeyIsTheRFCs(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", acceptKey("dGhlIHNhbXBsZSBub25jZQ=="))
}

func TestAWrongAcceptKeyIsRefused(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hijacker, _ := w.(http.Hijacker)
		conn, rw, err := hijacker.Hijack()
		if err != nil {
			return
		}
		defer conn.Close() //nolint: errcheck

		rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" + //nolint: errcheck
			"Sec-WebSocket-Accept: bm90IHRoZSBhbnN3ZXI=\r\nSec-WebSocket-Protocol: " + testSubprotocol + "\r\n\r\n")
		rw.Flush() //nolint: errcheck
	}))
	t.Cleanup(server.Close)

	_, _, err := dialWebSocket(context.Background(), strings.TrimPrefix(server.URL, "http://"), "/",
		testSubprotocol, "example.com", "", 5*time.Second, 256<<10)
	require.ErrorIs(t, err, errUpgradeRefused)
}

// A Write with credit to spare can still block, in the carrier's own socket,
// when the relay stops reading. The stream's deadline reaches that socket too:
// a load run is bounded however the relay misbehaves.
func TestAWriteToAStalledCarrierHonoursItsDeadline(t *testing.T) {
	t.Parallel()

	relay := make(chan *ws.Conn, 1)
	done := make(chan struct{})

	t.Cleanup(func() { close(done) })

	conn, reader := relayStandIn(t, ws.Options{MaxMessage: 2 << 20}, func(c *ws.Conn) {
		relay <- c
		<-done // and never read
	})

	stream, err := sessionOver(conn, reader).OpenStream(1)
	require.NoError(t, err)
	require.NoError(t, (<-relay).Write(relayFrames(t, frame.NewWindow(1, 1<<30))))
	require.NoError(t, stream.SetWriteDeadline(time.Now().Add(time.Second)))

	wrote := make(chan error, 1)

	go func() {
		chunk := make([]byte, 1<<20)

		for {
			if _, err := stream.Write(chunk); err != nil {
				wrote <- err

				return
			}
		}
	}()

	select {
	case err := <-wrote:
		require.ErrorIs(t, err, os.ErrDeadlineExceeded)
	case <-time.After(10 * time.Second):
		t.Fatal("a Write blocked in the carrier's socket ignored its deadline")
	}
}

// bareUpgrader answers a WebSocket upgrade by hand and then holds the socket
// without reading it, so a heap measurement counts the client's side alone.
func bareUpgrader(t *testing.T) string {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	var (
		mu   sync.Mutex
		held []net.Conn
	)

	t.Cleanup(func() {
		listener.Close() //nolint: errcheck

		mu.Lock()
		defer mu.Unlock()

		for _, c := range held {
			c.Close() //nolint: errcheck
		}
	})

	go func() {
		for {
			c, err := listener.Accept()
			if err != nil {
				return
			}

			request, err := http.ReadRequest(bufio.NewReader(c))
			if err != nil {
				c.Close() //nolint: errcheck

				continue
			}

			fmt.Fprintf(c, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"+
				"Sec-WebSocket-Accept: %s\r\nSec-WebSocket-Protocol: %s\r\n\r\n",
				acceptKey(request.Header.Get("Sec-WebSocket-Key")), testSubprotocol)

			mu.Lock()
			held = append(held, c)
			mu.Unlock()
		}
	}()

	return listener.Addr().String()
}

// An idle session with a small read buffer costs the client almost nothing.
// The idle benchmarks count every byte in the process, and a client that
// allocated its buffers up front would be measured as the relay's cost.
func TestAnIdleSessionHoldsLittleMemory(t *testing.T) { //nolint: paralleltest // reads the heap
	const sessions = 64

	addr := bareUpgrader(t)

	var before, after runtime.MemStats

	runtime.GC()
	runtime.ReadMemStats(&before)

	held := make([]*WebSession, 0, sessions)

	for range sessions {
		conn, reader, err := dialWebSocket(t.Context(), addr, "/", testSubprotocol, "example.com", "", 5*time.Second, 4<<10)
		require.NoError(t, err)

		held = append(held, sessionOver(conn, reader))
	}

	runtime.GC()
	runtime.ReadMemStats(&after)

	perSession := (int64(after.HeapAlloc) - int64(before.HeapAlloc)) / sessions //nolint: gosec // heap sizes
	assert.Less(t, perSession, int64(16<<10), "an idle session holds %d bytes", perSession)

	for _, s := range held {
		s.Close() //nolint: errcheck
	}
}

var _ = errors.New
