package relay_test

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"

	"github.com/Arman2122/mtg-proxy/essentials"
	"github.com/Arman2122/mtg-proxy/mtglib/internal/relay"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The end of a stream, on real sockets. Neither Telegram nor its clients keep
// one half of a connection open after closing the other, so when either side
// finishes, the relay delivers everything it has already read for that
// direction, tells the other peer with a FIN, and ends the whole stream. These
// tests pin the three parts: every byte arrives, the peer sees a clean EOF
// rather than a reset, and nothing is left open for the idle timeout to find.

// tcpPair is a connected loopback pair: the end the relay holds, wrapped the
// way the proxy wraps it, and the far end the test plays.
func tcpPair(t *testing.T) (essentials.Conn, *net.TCPConn) {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	defer listener.Close() //nolint: errcheck

	far, err := net.DialTCP("tcp", nil, listener.Addr().(*net.TCPAddr))
	require.NoError(t, err)

	near, err := listener.Accept()
	require.NoError(t, err)

	t.Cleanup(func() {
		far.Close()  //nolint: errcheck
		near.Close() //nolint: errcheck
	})

	return essentials.WrapNetConn(near), far
}

// startRelay runs the relay between the two near ends and reports when it
// returns.
func startRelay(t *testing.T, telegram, client essentials.Conn) <-chan struct{} {
	t.Helper()

	done := make(chan struct{})

	go func() {
		defer close(done)

		relay.Relay(t.Context(), loggerMock{}, telegram, client)
	}()

	return done
}

// readToEOF reads far until EOF and fails on anything else: a reset or a
// deadline means the end of the stream was not delivered as an end.
func readToEOF(t *testing.T, far *net.TCPConn) []byte {
	t.Helper()

	require.NoError(t, far.SetReadDeadline(time.Now().Add(5*time.Second)))

	got, err := io.ReadAll(far)
	require.NoError(t, err, "the peer must see a clean EOF, not a reset or a timeout")

	return got
}

func assertRelayEnds(t *testing.T, done <-chan struct{}, why string) {
	t.Helper()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal(why)
	}
}

// Telegram answers and hangs up: the answer reaches the client in full, then
// the client sees EOF.
func TestRelayTelegramHangsUp(t *testing.T) {
	t.Parallel()

	telegram, telegramFar := tcpPair(t)
	client, clientFar := tcpPair(t)
	done := startRelay(t, telegram, client)

	payload := bytes.Repeat([]byte{0x5a}, 1<<20)

	go func() {
		telegramFar.Write(payload) //nolint: errcheck
		telegramFar.CloseWrite()   //nolint: errcheck
	}()

	assert.Len(t, readToEOF(t, clientFar), len(payload), "every byte Telegram sent must reach the client")
	assertRelayEnds(t, done, "the stream stayed open after Telegram hung up")
}

// The client sends its last request and hangs up: the request reaches Telegram
// in full, then Telegram sees EOF.
func TestRelayClientHangsUp(t *testing.T) {
	t.Parallel()

	telegram, telegramFar := tcpPair(t)
	client, clientFar := tcpPair(t)
	done := startRelay(t, telegram, client)

	payload := bytes.Repeat([]byte{0xa5}, 1<<20)

	go func() {
		clientFar.Write(payload) //nolint: errcheck
		clientFar.CloseWrite()   //nolint: errcheck
	}()

	assert.Len(t, readToEOF(t, telegramFar), len(payload), "every byte the client sent must reach Telegram")
	assertRelayEnds(t, done, "the stream stayed open after the client hung up")
}
