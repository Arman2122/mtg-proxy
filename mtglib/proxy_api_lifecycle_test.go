package mtglib

import (
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The management API is part of the proxy's lifetime in both directions. It
// used to be half of one: it started with the proxy, but Shutdown returned
// without waiting for it, so the port stayed bound for up to five seconds after
// the proxy said it was gone -- and a restart on the same address could lose
// the race to a server still winding down.

// getStats fetches /stats from a running API and returns the status code and
// body, or the error the client got.
func getStats(t *testing.T, addr string) (int, string, error) {
	t.Helper()

	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://"+addr+"/stats", nil)
	require.NoError(t, err)

	client := &http.Client{Timeout: 2 * time.Second}

	resp, err := client.Do(request)
	if err != nil {
		return 0, "", err //nolint: wrapcheck // the caller wants the client's own error
	}

	defer resp.Body.Close() //nolint: errcheck

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	return resp.StatusCode, string(body), nil
}

// shutdownWithin runs Shutdown and fails if it does not return in time.
// Shutdown now waits for the API server, and a wait that could hang is worse
// than one that was missing.
func shutdownWithin(t *testing.T, proxy *Proxy, limit time.Duration) {
	t.Helper()

	done := make(chan struct{})

	go func() {
		proxy.Shutdown()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(limit):
		t.Fatal("Shutdown did not return")
	}
}

// The API answers while the proxy runs, and its port is free the moment
// Shutdown returns: a listener bound to the same address right after must
// succeed, and a request must fail. Remove the wait in Shutdown and the rebind
// races a server still winding down.
func TestManagementAPILivesAndDiesWithTheProxy(t *testing.T) {
	t.Parallel()

	// The socket is the test's own, so no other test can take the port between
	// picking it and the proxy binding it.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	addr := ln.Addr().String()

	opts, _ := servingOpts(t)
	opts.APIListener = ln

	proxy, err := NewProxy(opts)
	require.NoError(t, err)

	status, body, err := getStats(t, addr)
	require.NoError(t, err, "the API must answer while the proxy runs")
	assert.Equal(t, http.StatusOK, status)
	assert.Contains(t, body, `"features"`)

	shutdownWithin(t, proxy, 10*time.Second)

	// No sleep, no retry: the contract is that the port is free when Shutdown
	// returns, and a test that waited for it would be testing something weaker.
	rebound, err := net.Listen("tcp", addr)
	require.NoError(t, err, "the API port was still held after Shutdown returned")

	defer rebound.Close() //nolint: errcheck

	_, _, err = getStats(t, addr)
	require.Error(t, err, "the API answered after the proxy shut down")
}

// A bind address that cannot be bound is reported and the proxy still starts.
// Its job is the MTProto port; an operator who lost the API to a taken port
// must not lose every client with it. Pinned here because this commit is the
// one that moved the bind, and the outcome must not have moved with it.
func TestAnUnbindableAPIAddressIsAWarningNotAFailure(t *testing.T) {
	t.Parallel()

	taken, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	defer taken.Close() //nolint: errcheck

	opts, _ := servingOpts(t)
	opts.APIBindTo = taken.Addr().String()

	proxy, err := NewProxy(opts)
	require.NoError(t, err, "a taken API port must not stop the proxy from starting")

	shutdownWithin(t, proxy, 10*time.Second)
}

// With nothing configured there is no API, and Shutdown does not wait on a
// server that was never started.
func TestNoAPIIsNoAPI(t *testing.T) {
	t.Parallel()

	opts, _ := servingOpts(t)

	proxy, err := NewProxy(opts)
	require.NoError(t, err)

	shutdownWithin(t, proxy, 10*time.Second)
}
