package stats

import (
	"io"
	"net"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPrometheusServerHeaderDeadline is the slowloris regression test for the
// scrape endpoint: a client that never terminates its headers must be cut
// loose, not hold a goroutine and a socket for as long as it likes. It is an
// internal test so it can tie its wait to the server's own constant.
func TestPrometheusServerHeaderDeadline(t *testing.T) {
	t.Parallel()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	factory := NewPrometheus("mtg", "/metrics")

	assert.NotZero(t, factory.httpServer.ReadHeaderTimeout)
	assert.NotZero(t, factory.httpServer.ReadTimeout)
	assert.NotZero(t, factory.httpServer.WriteTimeout)
	assert.NotZero(t, factory.httpServer.IdleTimeout)

	go factory.Serve(ln) //nolint: errcheck

	t.Cleanup(func() {
		factory.Close() //nolint: errcheck
		ln.Close()      //nolint: errcheck
	})

	conn, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)

	// Registered after the server cleanups so LIFO closes the client first.
	t.Cleanup(func() { conn.Close() }) //nolint: errcheck

	// A request line and one header, never terminated by the blank line.
	_, err = conn.Write([]byte("GET /metrics HTTP/1.1\r\nHost: scraper.example.com\r\n"))
	require.NoError(t, err)

	deadline := scrapeReadHeaderTimeout + 5*time.Second
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
