package webrelay

import (
	"bytes"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Arman2122/mtg-proxy/internal/webrelay/frame"
	"github.com/Arman2122/mtg-proxy/mtglib"
	"github.com/stretchr/testify/require"
)

// countedRelay is a whole relay with its counters attached, plus the pieces a
// test needs to drive it.
type countedRelay struct {
	origin   *Origin
	server   *httptest.Server
	counters *Counters
	secret   mtglib.Secret
	accepted chan net.Conn
}

func newCountedRelay(t *testing.T) *countedRelay {
	t.Helper()

	backendListener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	t.Cleanup(func() { backendListener.Close() }) //nolint: errcheck

	accepted := make(chan net.Conn, 4)

	go func() {
		for {
			conn, err := backendListener.Accept()
			if err != nil {
				return
			}

			accepted <- conn
		}
	}()

	signer, err := NewSigner(bytes.Repeat([]byte{5}, TokenKeySize))
	require.NoError(t, err)

	secret := mtglib.Secret{Mode: mtglib.SecretModeFakeTLS, Host: "www.cloudflare.com"}
	secret.Key[0] = 42

	backend, err := NewTCPBackend(backendListener.Addr().String(), false, 0)
	require.NoError(t, err)

	counters := NewCounters(time.Now())
	counters.SetProfiles([]string{"alice"})

	origin, err := NewOrigin(OriginOptions{
		Host:     originHost,
		Secrets:  []mtglib.Secret{secret},
		Signer:   signer,
		Cover:    http.NotFoundHandler(),
		Backend:  backend,
		Counters: counters,
		ClientIP: func(*http.Request) net.Addr {
			return &net.TCPAddr{IP: net.IPv4(203, 0, 113, 42), Port: 40000}
		},
	})
	require.NoError(t, err)

	server := httptest.NewServer(origin)
	t.Cleanup(server.Close)

	return &countedRelay{
		origin:   origin,
		server:   server,
		counters: counters,
		secret:   secret,
		accepted: accepted,
	}
}

// stats is what the relay's own stats socket would answer right now.
func (r *countedRelay) stats() RelayStats {
	return r.origin.StatsHandler(time.Now).counters.Snapshot(
		time.Now(), r.origin.store.maxSessions, r.origin.store.countSessions())
}

// openSession walks the bootstrap the bridge page walks and returns the session
// token.
func (r *countedRelay) openSession(t *testing.T) string {
	t.Helper()

	capability, err := Derive(WebSecret(r.secret), originHost)
	require.NoError(t, err)

	pageResponse, err := r.server.Client().Get( //nolint:noctx // a test request
		r.server.URL + "/?bridge=" + capability.String())
	require.NoError(t, err)

	defer pageResponse.Body.Close()

	document, err := io.ReadAll(pageResponse.Body)
	require.NoError(t, err)

	const marker = `"token":"`

	start := strings.Index(string(document), marker)
	require.Positive(t, start)

	rest := string(document)[start+len(marker):]
	bootstrap := rest[:strings.IndexByte(rest, '"')]

	hello, err := frame.Limits{}.EncodeBatch(nil, []frame.Frame{frame.NewHello()}, frame.ClientToRelay)
	require.NoError(t, err)

	request, err := http.NewRequestWithContext(t.Context(), http.MethodPost,
		r.server.URL+sessionPath, bytes.NewReader(hello))
	require.NoError(t, err)

	request.Header.Set("Authorization", "Bearer "+bootstrap)

	sessionResponse, err := r.server.Client().Do(request)
	require.NoError(t, err)

	defer sessionResponse.Body.Close()

	require.Equal(t, http.StatusOK, sessionResponse.StatusCode)

	return sessionResponse.Header.Get("X-Session-Token")
}

// The counters move when a real client goes through the whole relay.
//
// Every other test in this file exercises the Counters type. This one is about
// the SEAMS: a counter incremented in the wrong place is still a working
// counter, and the number it produces is wrong in a way no unit test of the
// type can see. Only driving the relay end to end says the increments are where
// an operator would expect them.
func TestCountersFollowARealSession(t *testing.T) {
	t.Parallel()

	relay := newCountedRelay(t)

	require.Zero(t, relay.stats().Sessions.Created, "nothing has happened yet")

	token := relay.openSession(t)

	created := relay.stats()
	require.EqualValues(t, 1, created.Sessions.Created)
	require.EqualValues(t, 1, created.Sessions.Active, "the store is holding it")
	require.Zero(t, created.Sessions.Attached, "no carrier has joined it yet")

	client := dialCarrier(t, relay.server, token)

	require.Eventually(t, func() bool {
		return relay.stats().Sessions.Attached == 1
	}, 5*time.Second, 10*time.Millisecond, "the carrier must be counted when it attaches")

	client.send(frame.NewOpen(1))

	backend := <-relay.accepted

	defer backend.Close() //nolint: errcheck

	require.Eventually(t, func() bool {
		return relay.stats().Streams.Opened == 1 && relay.stats().Streams.Active == 1
	}, 5*time.Second, 10*time.Millisecond, "a stream that reached the backend must be counted")

	// Uplink: what the client sent, counted only once the backend took it.
	payload := bytes.Repeat([]byte{0x7e}, 512)
	client.send(frame.NewData(1, payload))

	received := make([]byte, len(payload))
	require.NoError(t, backend.SetReadDeadline(time.Now().Add(5*time.Second)))

	_, err := io.ReadFull(backend, received)
	require.NoError(t, err)

	require.Eventually(t, func() bool {
		return relay.stats().Bytes.Up == int64(len(payload))
	}, 5*time.Second, 10*time.Millisecond,
		"uplink is counted after the backend write returns, not when it is queued")

	// Downlink: what the backend produced.
	down := bytes.Repeat([]byte{0x5a}, 1024)
	_, err = backend.Write(down)
	require.NoError(t, err)

	require.Eventually(t, func() bool {
		return relay.stats().Bytes.Down == int64(len(down))
	}, 5*time.Second, 10*time.Millisecond, "downlink must reach the counter")

	final := relay.stats()
	require.EqualValues(t, len(payload), final.Bytes.Up,
		"exactly the payload: frame headers and WebSocket framing are not relay bytes")
	require.EqualValues(t, len(down), final.Bytes.Down)
	require.Zero(t, final.Refused.CoverServed, "nothing in this test was refused")
	require.Zero(t, final.Refused.BadToken)
}

// The stream gauge comes back down when the stream ends, so it is a gauge
// rather than a total wearing a gauge's name.
func TestStreamGaugeReturnsToZero(t *testing.T) {
	t.Parallel()

	relay := newCountedRelay(t)
	token := relay.openSession(t)
	client := dialCarrier(t, relay.server, token)

	client.send(frame.NewOpen(1))

	backend := <-relay.accepted

	require.Eventually(t, func() bool {
		return relay.stats().Streams.Active == 1
	}, 5*time.Second, 10*time.Millisecond)

	backend.Close() //nolint: errcheck

	require.Eventually(t, func() bool {
		stats := relay.stats()

		return stats.Streams.Active == 0 && stats.Streams.Opened == 1
	}, 5*time.Second, 10*time.Millisecond,
		"active must fall while opened stays: a gauge that only rises is a total")
}

// A request carrying nothing this relay minted is counted as cover-served.
//
// This is the number an operator watches when users report failures: a climb
// here alongside complaints is the signature of a hostname or secret-set
// mismatch, where every real client is being handed the decoy site.
func TestCoverServedIsCounted(t *testing.T) {
	t.Parallel()

	relay := newCountedRelay(t)

	for _, path := range []string{"/", "/index.html", "/?bridge=" + strings.Repeat("a", 43)} {
		response, err := relay.server.Client().Get(relay.server.URL + path) //nolint:noctx // a test request
		require.NoError(t, err)
		require.NoError(t, response.Body.Close())
	}

	require.EqualValues(t, 3, relay.stats().Refused.CoverServed,
		"every unrecognised request is one the cover site answered")
}

// An authentic token naming no session is counted apart from an unrecognised
// request, because they mean different things: this one came from a client that
// really did hold a credential this relay minted.
func TestBadTokenIsCountedApartFromCover(t *testing.T) {
	t.Parallel()

	relay := newCountedRelay(t)
	token := relay.openSession(t)

	request, err := http.NewRequestWithContext(t.Context(), http.MethodDelete,
		relay.server.URL+sessionPath, nil)
	require.NoError(t, err)

	request.Header.Set("Authorization", "Bearer "+token)

	first, err := relay.server.Client().Do(request)
	require.NoError(t, err)
	require.NoError(t, first.Body.Close())
	require.Equal(t, http.StatusNoContent, first.StatusCode)

	require.Zero(t, relay.stats().Refused.BadToken, "the first delete named a real session")

	// The same authentic token again: still ours, no longer naming anything.
	repeat, err := http.NewRequestWithContext(t.Context(), http.MethodDelete,
		relay.server.URL+sessionPath, nil)
	require.NoError(t, err)

	repeat.Header.Set("Authorization", "Bearer "+token)

	second, err := relay.server.Client().Do(repeat)
	require.NoError(t, err)
	require.NoError(t, second.Body.Close())
	require.Equal(t, http.StatusNotFound, second.StatusCode)

	stats := relay.stats()
	require.EqualValues(t, 1, stats.Refused.BadToken)
	require.Zero(t, stats.Refused.CoverServed,
		"an authentic credential is never handed to the cover site, so it must not be counted there")
}
