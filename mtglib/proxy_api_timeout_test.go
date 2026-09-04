package mtglib

import (
	"io"
	"net"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAPIServerHeaderDeadline is the slowloris regression test: a client that
// opens a connection and never terminates its headers must be cut loose, not
// hold a goroutine and a socket for as long as it likes.
func TestAPIServerHeaderDeadline(t *testing.T) {
	t.Parallel()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	p := newAPITestProxy(map[string]Secret{"alice": GenerateSecret("alice.example.com")})
	srv := newAPIServer("", p.buildAPIHandler(""))

	assert.NotZero(t, srv.ReadHeaderTimeout)
	assert.NotZero(t, srv.ReadTimeout)
	assert.NotZero(t, srv.WriteTimeout)
	assert.NotZero(t, srv.IdleTimeout)

	go srv.Serve(ln) //nolint: errcheck

	t.Cleanup(func() {
		srv.Close() //nolint: errcheck
		ln.Close()  //nolint: errcheck
	})

	conn, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)

	// Registered after the server cleanups so LIFO closes the client first.
	t.Cleanup(func() { conn.Close() }) //nolint: errcheck

	// A request line and one header, never terminated by the blank line.
	_, err = conn.Write([]byte("GET /stats HTTP/1.1\r\nHost: panel.example.com\r\n"))
	require.NoError(t, err)

	deadline := apiReadHeaderTimeout + 5*time.Second
	start := time.Now()

	require.NoError(t, conn.SetReadDeadline(time.Now().Add(deadline)))

	// The server closes without a response body on a header timeout, so this is
	// EOF (or a reset on Windows) -- what must not happen is our own deadline.
	_, err = io.ReadAll(conn)
	elapsed := time.Since(start)

	require.NotErrorIs(t, err, os.ErrDeadlineExceeded,
		"connection still open %s after partial headers", elapsed)
	assert.Less(t, elapsed, deadline)
}
