package webrelay

import (
	"bytes"
	"cmp"
	"context"
	"crypto/rand"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/Arman2122/mtg-proxy/essentials"
	"github.com/Arman2122/mtg-proxy/events"
	"github.com/Arman2122/mtg-proxy/internal/proxyprotocol"
	"github.com/Arman2122/mtg-proxy/internal/testclient"
	"github.com/Arman2122/mtg-proxy/ipblocklist"
	"github.com/Arman2122/mtg-proxy/logger"
	"github.com/Arman2122/mtg-proxy/mtglib"
	"github.com/Arman2122/mtg-proxy/mtglib/obfuscation"
	"github.com/pires/go-proxyproto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	antireplay "github.com/Arman2122/mtg-proxy/antireplay"
)

// This file is the one test that runs the two processes together: a WEB client,
// through a real relay origin, into a real mtglib.Proxy, out to a stand-in
// Telegram. Every leg has its own unit tests and integration_test.go proves the
// relay reaches a backend socket; what only this can prove is the seam between
// them -- that the PROXY v2 header the relay's backend writes is the one the
// proxy's [[listener]] consumes, that the dd secret the WEB capability carries
// is one the proxy matches, and that a byte survives the whole round trip. That
// seam is exactly what the panel wires up, and nothing else exercises it.

// theClientIP is the address the front proxy would put in the PROXY header. It
// is a documentation range (TEST-NET-3), so if it ever appears where a real
// address should, it is unmistakably the test's and not a leak.
const theClientIP = "203.0.113.42"

// chainNetwork is the proxy's view of the internet: every dial, whatever DC it
// names, lands on one loopback echo server standing in for Telegram. It records
// that a dial happened, which is the proxy deciding to forward rather than
// refuse.
type chainNetwork struct {
	upstream string

	mu    sync.Mutex
	dials int
}

func (n *chainNetwork) Dial(_, _ string) (essentials.Conn, error) {
	n.mu.Lock()
	n.dials++
	n.mu.Unlock()

	conn, err := net.Dial("tcp", n.upstream)
	if err != nil {
		return nil, err //nolint: wrapcheck
	}

	return essentials.WrapNetConn(conn), nil
}

func (n *chainNetwork) DialContext(_ context.Context, network, address string) (essentials.Conn, error) {
	return n.Dial(network, address)
}

func (n *chainNetwork) MakeHTTPClient(
	_ func(ctx context.Context, network, address string) (essentials.Conn, error),
) *http.Client {
	// The proxy builds a client for its public-config updater at construction.
	// AutoUpdate is off, so it is never used; a default client is enough and
	// touches nothing.
	return &http.Client{}
}

func (n *chainNetwork) NativeDialer() *net.Dialer { return &net.Dialer{} }

func (n *chainNetwork) dialCount() int {
	n.mu.Lock()
	defer n.mu.Unlock()

	return n.dials
}

// allowEveryIP is the proxy's allowlist. The shipped noop returns Contains ==
// false, which the proxy reads as "not on the allowlist" and refuses -- right
// for a blocklist, fatal for an allowlist -- so the chain needs an explicit
// allow-all rather than that noop.
type allowEveryIP struct{}

func (allowEveryIP) Contains(net.IP) bool { return true }
func (allowEveryIP) Run(_ time.Duration)  {}
func (allowEveryIP) Shutdown()            {}

// clientIPRecorder captures the client address the proxy saw on EventStart.
// Behind the PROXY-protocol adapter that address is whatever the relay's
// backend stamped into the header; if the header were dropped it would be the
// relay's own loopback instead, so this one field is the whole proof that the
// header made it across.
type clientIPRecorder struct {
	mu  sync.Mutex
	ips []string
}

func (r *clientIPRecorder) Send(_ context.Context, evt mtglib.Event) {
	start, ok := evt.(mtglib.EventStart)
	if !ok {
		return
	}

	r.mu.Lock()
	r.ips = append(r.ips, start.RemoteIP.String())
	r.mu.Unlock()
}

func (r *clientIPRecorder) seen() []string {
	r.mu.Lock()
	defer r.mu.Unlock()

	return append([]string(nil), r.ips...)
}

// chain is the whole standing setup: the origin a client talks to, the shared
// secret its capability derives from, and the counters and observers the tests
// assert against.
type chain struct {
	server     *httptest.Server
	capability Capability
	key        [mtglib.SecretKeyLength]byte
	counters   *Counters
	network    *chainNetwork
	clientIPs  *clientIPRecorder

	// store is the relay's own session table, and the authority on how many
	// sessions are live -- the counters deliberately keep no such gauge.
	store *store

	// upstreams hands over, in arrival order, each connection the proxy made
	// to Telegram, when the chain was built with telegramHandover.
	upstreams <-chan net.Conn
}

// telegramMode is what the stand-in Telegram does with a connection.
type telegramMode int

const (
	// telegramEcho decrypts and echoes: what the chain tests assert through.
	telegramEcho telegramMode = iota

	// telegramHandover reads the proxy's 64-byte handshake and hands the raw
	// socket to the test, which then pushes or sinks bytes itself without ever
	// decrypting, so the cipher work a benchmark measures is the proxy's.
	telegramHandover
)

// chainOptions shape a chain beyond its defaults.
type chainOptions struct {
	limits   map[string]mtglib.SecretLimits
	telegram telegramMode

	// quiet discards the proxy's events instead of recording client IPs, for
	// benchmarks that make thousands of connections.
	quiet bool

	// idleTimeout is the proxy's; default 2s, which the churn test needs.
	idleTimeout time.Duration
}

// newChain stands up Telegram (an echo), a real proxy on a PROXY-protocol dd
// listener, and a relay origin whose backend is that listener. It is the binary
// minus the sockets the OS would assign in production and plus a stand-in for
// Telegram; nothing about the path between the client and the proxy is faked.
func newChain(tb testing.TB) *chain {
	tb.Helper()

	return newChainWith(tb, chainOptions{})
}

// newChainWithLimits is newChain with per-user limits on the proxy, for the
// one thing the relay must inherit from the proxy without knowing it: a
// user's speed limit, enforced on the proxy's side of the loopback hop and
// felt by the browser through the relay's own flow control.
func newChainWithLimits(tb testing.TB, limits map[string]mtglib.SecretLimits) *chain {
	tb.Helper()

	return newChainWith(tb, chainOptions{limits: limits})
}

// newChainWith is newChain shaped by o.
func newChainWith(t testing.TB, o chainOptions) *chain {
	t.Helper()

	var (
		upstream  string
		upstreams <-chan net.Conn
	)

	switch o.telegram {
	case telegramEcho:
		upstream = startEchoTelegram(t)
	case telegramHandover:
		upstream, upstreams = startHandoverTelegram(t)
	}

	network := &chainNetwork{upstream: upstream}
	clientIPs := &clientIPRecorder{}

	var eventStream mtglib.EventStream = clientIPs
	if o.quiet {
		eventStream = events.NewNoopStream()
	}

	// One key in three costumes: the client sends its dd handshake, the proxy
	// matches the same key as a dd secret, and the relay derives the WEB
	// capability from its ee form -- which is what a single user with one
	// secret actually looks like across the two processes.
	var key [mtglib.SecretKeyLength]byte
	key[0] = 42

	proxy, err := mtglib.NewProxy(mtglib.ProxyOpts{
		Network:         network,
		AntiReplayCache: antireplay.NewNoop(),
		IPBlocklist:     ipblocklist.NewNoop(),
		IPAllowlist:     allowEveryIP{},
		EventStream:     eventStream,
		Logger:          logger.NewNoopLogger(),
		Secrets:         map[string]mtglib.Secret{"web": {Mode: mtglib.SecretModeDD, Key: key}},
		SecretLimits:    o.limits,
		TrackClientIPs:  true,
		// Short, because the churn test measures what is left standing after a
		// client goes away, and the default is five minutes.
		//
		// When a client vanishes, the proxy's relay closes only the half that
		// ended -- deliberately, so Telegram can finish sending what it already
		// had -- and the other direction waits on a Telegram that has nothing
		// more to say. The idle timeout is what ends that wait, so it is the
		// real bound on how long a departed client's connections live, and the
		// test has to be able to outlast it to tell a slow teardown from a leak.
		IdleTimeout: cmp.Or(o.idleTimeout, 2*time.Second),
	})
	require.NoError(t, err)
	t.Cleanup(proxy.Shutdown)

	// The proxy's own loopback [[listener]], wrapped exactly as the CLI wraps a
	// backend socket: REQUIRE, so a connection with no PROXY header fails loudly
	// rather than being read as the first bytes of a handshake.
	base, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { base.Close() }) //nolint: errcheck

	wrapped := &proxyprotocol.ListenerAdapter{
		Listener: proxyproto.Listener{
			Listener: base,
			ConnPolicy: func(proxyproto.ConnPolicyOptions) (proxyproto.Policy, error) {
				return proxyproto.REQUIRE, nil
			},
		},
	}

	ddPolicy := mtglib.ListenerPolicy{
		Modes:           mtglib.ModeSetOf(mtglib.SecretModeDD, mtglib.SecretModePlain),
		ProxyProtocol:   true,
		OnUnknownSecret: mtglib.UnknownSecretClose,
	}

	go proxy.ServeWithPolicy(wrapped, ddPolicy) //nolint: errcheck

	// The relay backend dials the base socket and always writes a PROXY v2
	// header, which is why the listener above is set to REQUIRE.
	backend, err := NewTCPBackend(base.Addr().String(), true, 0)
	require.NoError(t, err)

	signer, err := NewSigner(make([]byte, TokenKeySize))
	require.NoError(t, err)

	eeSecret := mtglib.Secret{Mode: mtglib.SecretModeFakeTLS, Host: "www.cloudflare.com", Key: key}
	counters := NewCounters(time.Now())

	origin, err := NewOrigin(OriginOptions{
		Host:     originHost,
		Secrets:  []mtglib.Secret{eeSecret},
		Signer:   signer,
		Counters: counters,
		Cover:    http.NotFoundHandler(),
		Backend:  backend,
		ClientIP: func(*http.Request) net.Addr {
			return &net.TCPAddr{IP: net.ParseIP(theClientIP), Port: 40000}
		},
		Logger: logger.NewNoopLogger(),
	})
	require.NoError(t, err)

	server := httptest.NewServer(origin)
	t.Cleanup(server.Close)

	capability, err := Derive(WebSecret(eeSecret), originHost)
	require.NoError(t, err)

	return &chain{
		server:     server,
		capability: capability,
		key:        key,
		counters:   counters,
		network:    network,
		clientIPs:  clientIPs,
		store:      origin.store,
		upstreams:  upstreams,
	}
}

// startEchoTelegram is a stand-in Telegram: it reads the obfuscated2 handshake
// the proxy sends on a direct DC connection (nil secret) and echoes the
// plaintext back through the same de/encrypting wrapper. Echo is enough --
// proving a byte the client sent comes back to the client is proof it reached
// here and returned, through both obfuscation legs and both relay directions.
func startEchoTelegram(t testing.TB) string {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { listener.Close() }) //nolint: errcheck

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}

			go func(c net.Conn) {
				defer c.Close() //nolint: errcheck

				_ = c.SetDeadline(time.Now().Add(20 * time.Second))

				// A direct DC carries no MTProxy secret, so the proxy's leg to
				// here is keyed on nothing: the empty obfuscator reads it.
				_, _, plain, err := obfuscation.Obfuscator{}.ReadHandshake(
					essentials.WrapNetConn(c),
					obfuscation.TagSetOf(
						obfuscation.TagPaddedIntermediate,
						obfuscation.TagIntermediate,
						obfuscation.TagAbridged,
					),
				)
				if err != nil {
					return
				}

				io.Copy(plain, plain) //nolint: errcheck // echo until the client hangs up
			}(conn)
		}
	}()

	return listener.Addr().String()
}

// startHandoverTelegram is a stand-in Telegram for benchmarks: it reads the
// 64-byte handshake the proxy sends on a direct data-centre connection, without
// decrypting it, and hands the raw socket over.
func startHandoverTelegram(tb testing.TB) (string, <-chan net.Conn) {
	tb.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(tb, err)
	tb.Cleanup(func() { listener.Close() }) //nolint: errcheck

	handed := make(chan net.Conn, 4096)

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}

			go func(c net.Conn) {
				var handshake [64]byte
				if _, err := io.ReadFull(c, handshake[:]); err != nil {
					c.Close() //nolint: errcheck

					return
				}

				handed <- c
			}(conn)
		}
	}()

	return listener.Addr().String(), handed
}

// openStream walks the whole client dance -- bridge page, session bootstrap,
// carrier, open -- through the shared WEB client, and hands back an obfuscated
// conn ready to carry MTProto, keyed on the shared secret exactly as a real dd
// client would key it. The session comes back too, so a caller can end it
// cleanly the way a browser does on unload.
func (c *chain) openStream(t *testing.T, streamID uint32) (essentials.Conn, *testclient.WebSession) {
	t.Helper()

	session, err := testclient.OpenWebSession(t.Context(), c.server.URL, c.capability.String(),
		testclient.WebOptions{Origin: originHost})
	require.NoError(t, err)

	t.Cleanup(func() { session.Close() }) //nolint: errcheck

	stream, err := session.OpenStream(streamID)
	require.NoError(t, err)

	// The client's own dd handshake. Its bytes become the first DATA frame; the
	// proxy reads exactly 64 of them, matches the key, and dials out.
	obfuscated, err := obfuscation.Obfuscator{Secret: c.key[:]}.SendHandshake(
		stream, 2, obfuscation.TagPaddedIntermediate,
	)
	require.NoError(t, err)

	return obfuscated, session
}

// deleteSession ends a session the way a browser does when its tab closes: a
// DELETE with the session bearer, which reaps it at once rather than holding it
// for the reconnect grace. It is what keeps the churn test's teardown
// deterministic instead of waiting out a two-minute timer.
func (c *chain) deleteSession(t *testing.T, session *testclient.WebSession) {
	t.Helper()

	require.NoError(t, session.Delete(t.Context()))
}

// TestAWebClientReachesTelegramThroughTheProxy is the whole chain end to end: a
// byte the client writes comes back to the client, having crossed the relay,
// the PROXY-protocol backend socket, a real proxy that matched the dd secret,
// and the stand-in Telegram -- and the proxy saw the real client's address, not
// the relay's loopback.
func TestAWebClientReachesTelegramThroughTheProxy(t *testing.T) {
	t.Parallel()

	c := newChain(t)

	conn, _ := c.openStream(t, 17)

	const message = "the whole chain, one byte at a time"

	_, err := conn.Write([]byte(message))
	require.NoError(t, err)

	echoed := make([]byte, len(message))
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(10*time.Second)))
	_, err = io.ReadFull(conn, echoed)
	require.NoError(t, err)
	require.Equal(t, message, string(echoed),
		"a byte from the client must survive the whole round trip")

	require.Positive(t, c.network.dialCount(), "the proxy never dialled Telegram")

	// The address the proxy saw is the one the front proxy would have stamped,
	// carried across the loopback hop by PROXY v2 -- not 127.0.0.1, which is
	// what a dropped header would have left.
	require.Contains(t, c.clientIPs.seen(), theClientIP,
		"the proxy did not see the real client address; the PROXY header was lost")
	require.NotContains(t, c.clientIPs.seen(), "127.0.0.1",
		"the proxy saw the relay's own address, so the PROXY header was dropped")
}

// TestAWebStreamOutlastsTheInitialWindow pushes four times the relay's initial
// window each way through one stream. A client that never returns credit
// stalls the download at 4 MiB; one that ignores the relay's grants has its
// upload cut with ErrCreditExhausted. Either is a client that cannot carry a
// bulk transfer, which is what the load benchmarks need it to do.
func TestAWebStreamOutlastsTheInitialWindow(t *testing.T) {
	t.Parallel()

	const size = 16 << 20

	c := newChain(t)
	conn, _ := c.openStream(t, 3)

	sent := make([]byte, size)
	_, err := rand.Read(sent)
	require.NoError(t, err)

	wrote := make(chan error, 1)

	go func() {
		// A copy: the obfuscated2 writer encrypts in place.
		_, err := conn.Write(append([]byte(nil), sent...))
		wrote <- err
	}()

	echoed := make([]byte, size)
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(20*time.Second)))
	_, err = io.ReadFull(conn, echoed)
	require.NoError(t, err, "the download must not stall at the initial window")
	require.NoError(t, <-wrote, "the upload must not be cut for spending credit it was not given")
	require.True(t, bytes.Equal(sent, echoed), "every byte must come back, in order")
}

// A DELETEd session ends: its carrier and the streams on it stop, even if the
// client keeps the socket open. Today they do not -- store.remove cancels the
// session's context, but nothing watching it closes the WebSocket, so a client
// that holds the socket keeps its streams while the session is already gone
// from the table and from MaxSessions. Found while building the measurement
// tooling; it is the WEB relay project's to fix, and this test is its pin.
func TestADeletedSessionStopsServing(t *testing.T) {
	t.Parallel()

	c := newChain(t)
	conn, session := c.openStream(t, 7)

	_, err := conn.Write([]byte("before"))
	require.NoError(t, err)
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))
	_, err = io.ReadFull(conn, make([]byte, len("before")))
	require.NoError(t, err)

	// The DELETE alone, without the client closing anything.
	request, err := http.NewRequestWithContext(t.Context(), http.MethodDelete, c.server.URL+sessionPath, nil)
	require.NoError(t, err)
	request.Header.Set("Authorization", "Bearer "+session.Token())

	response, err := c.server.Client().Do(request)
	require.NoError(t, err)
	response.Body.Close() //nolint: errcheck
	require.Equal(t, http.StatusNoContent, response.StatusCode)

	require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))
	_, err = conn.Write([]byte("after"))

	if err == nil {
		_, err = io.ReadFull(conn, make([]byte, len("after")))
	}

	require.Error(t, err, "the stream of a deleted session must end")
	require.Eventually(t, func() bool { return c.counters.streamsActive.Load() == 0 },
		5*time.Second, 20*time.Millisecond, "no stream may outlive its deleted session")
}

// TestTheRelayProxyChainDoesNotLeakUnderChurn opens and tears down many full
// sessions against one standing relay and proxy, and asserts the relay is left
// holding nothing: no live stream, no live session, and no goroutine drift
// beyond a small tolerance. A leak here -- a stream never closed, a session
// never reaped -- would accumulate silently in production under exactly this
// pattern, one short-lived client after another.
func TestTheRelayProxyChainDoesNotLeakUnderChurn(t *testing.T) {
	t.Parallel()

	c := newChain(t)

	const rounds = 25

	// A first round settles the lazy one-time setup (buffers, the proxy's
	// config fetcher construction) so the baseline is taken past it.
	c.oneRound(t, 1)

	time.Sleep(50 * time.Millisecond)

	baseline := runtime.NumGoroutine()

	for i := range rounds {
		c.oneRound(t, uint32(i+2)) //nolint: gosec // a small loop index
	}

	// The streams and sessions are gone. streamsActive is the relay's own live
	// gauge; the store is the authority on sessions, and every one of them was
	// ended explicitly, so it must be empty rather than merely shrinking.
	require.Eventually(t, func() bool {
		return c.counters.streamsActive.Load() == 0
	}, 10*time.Second, 20*time.Millisecond, "a stream was never closed")

	require.Eventually(t, func() bool {
		return c.store.countSessions() == 0
	}, 10*time.Second, 20*time.Millisecond, "a session outlived the client that ended it")

	require.GreaterOrEqual(t, c.counters.sessionsCreated.Load(), int64(rounds),
		"the churn did not actually create sessions")

	// Goroutines return to where they were. The window is generous because it
	// has to outlast the idle timeout above -- the departed clients' downstream
	// halves are still waiting on a Telegram that will never speak again, and
	// only that timeout ends them. Anything still standing after it is a
	// genuine leak, and a genuine leak grows with the round count rather than
	// sitting inside a fixed tolerance.
	require.Eventually(t, func() bool {
		return runtime.NumGoroutine() <= baseline+8
	}, 30*time.Second, 100*time.Millisecond,
		"goroutines did not return to baseline: %d over %d rounds", runtime.NumGoroutine()-baseline, rounds)
}

// oneRound is a single client's whole life: connect, send a byte, read it back,
// hang up and say so. It is the unit the churn test repeats.
//
// The DELETE at the end is the part that matters for what the churn test
// measures. Dropping the carrier alone leaves the session standing for its
// reconnect grace -- by design, so a client that loses its network gets its
// streams back -- and a test that only dropped the socket would be measuring
// that timer rather than whether anything leaks.
func (c *chain) oneRound(t *testing.T, streamID uint32) {
	t.Helper()

	conn, session := c.openStream(t, streamID)

	_, err := conn.Write([]byte("ping"))
	require.NoError(t, err)

	echoed := make([]byte, 4)
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(10*time.Second)))
	_, err = io.ReadFull(conn, echoed)
	require.NoError(t, err)
	require.Equal(t, "ping", string(echoed))

	require.NoError(t, conn.Close())
	c.deleteSession(t, session)
}

// A speed limit set on the proxy is felt by a WEB client. The relay knows
// nothing about limits; the proxy holds its side of the loopback hop to the
// rate, the relay's stream stops being fed, its window credits stop, and the
// browser slows. This is the claim "every door" makes about the third door,
// and the one test that would catch the WEB path escaping a user's cap.
func TestAWebClientIsHeldToTheUsersSpeedLimit(t *testing.T) {
	t.Parallel()

	// 256 KiB/s, with a 256 KiB echo: the bytes go up through the proxy's
	// read path and come back down through its write path, half a megabyte
	// through one bucket that starts with a quarter in it -- about a second.
	const rateBytes = 256 << 10

	timeEcho := func(c *chain) time.Duration {
		conn, _ := c.openStream(t, 17)

		payload := make([]byte, rateBytes)
		started := time.Now()

		go func() { conn.Write(payload) }() //nolint: errcheck

		echoed := make([]byte, len(payload))
		require.NoError(t, conn.SetReadDeadline(time.Now().Add(15*time.Second)))
		_, err := io.ReadFull(conn, echoed)
		require.NoError(t, err)

		return time.Since(started)
	}

	capped := timeEcho(newChainWithLimits(t, map[string]mtglib.SecretLimits{
		"web": {SpeedBytesPerSecond: rateBytes},
	}))
	assert.GreaterOrEqual(t, capped, 800*time.Millisecond,
		"a capped user's WEB stream must be held to the rate")

	free := timeEcho(newChain(t))
	assert.Less(t, free, 500*time.Millisecond, "an uncapped user's WEB stream must not be paced")
	assert.Less(t, free, capped/2)
}
