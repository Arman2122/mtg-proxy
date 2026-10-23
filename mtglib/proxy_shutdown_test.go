package mtglib

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

// Shutdown waits for every accept loop and every stream through one
// WaitGroup, and both counted themselves into it from their own goroutine. A
// WaitGroup's Add from zero must happen before the Wait it is waited by; one
// that runs concurrently with Wait is a misuse the race detector reports, and
// one that lands just after Wait returned is a loop or a stream Shutdown never
// waited for. CI's race detector caught the first on Linux, in internal/cli's
// TestRunLoopExitsWhenThePublicSocketDies: the public socket dies, the run
// loop closes its sockets and calls Shutdown while an accept loop that had not
// yet started is still on its way in.

// An accept loop started after Shutdown has begun serves nothing and returns
// at once. Before, it counted itself in after the Wait and then sat in Accept
// on a live socket for as long as the socket lived.
func TestServeAfterShutdownReturnsAtOnce(t *testing.T) {
	t.Parallel()

	proxy, events := newServingProxy(t)
	proxy.Shutdown()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	defer listener.Close() //nolint: errcheck

	require.NoError(t, awaitReturn(t, serveInBackground(proxy, listener)))
	require.Zero(t, events.starts())
}

// An accept loop and a Shutdown that race end in order, every time: run under
// -race, this is the interleaving the run loop produces when its public socket
// dies on start.
func TestServeRacingShutdownIsOrdered(t *testing.T) {
	t.Parallel()

	for range 200 {
		opts, _ := servingOpts(t)

		proxy, err := NewProxy(opts)
		require.NoError(t, err)

		listener, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)

		done := serveInBackground(proxy, listener)

		listener.Close() //nolint: errcheck
		proxy.Shutdown()

		require.NoError(t, awaitReturn(t, done))
	}
}
