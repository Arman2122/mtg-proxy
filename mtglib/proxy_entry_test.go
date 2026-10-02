package mtglib

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/Arman2122/mtg-proxy/essentials"
	"github.com/Arman2122/mtg-proxy/mtglib/internal/dc"
	"github.com/Arman2122/mtg-proxy/mtglib/internal/doppel"
	"github.com/Arman2122/mtg-proxy/mtglib/internal/tls"
	"github.com/Arman2122/mtg-proxy/mtglib/obfuscation"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// recordingEventStream keeps every event so a test can assert on what the proxy
// decided (fronting, replay, throttling) without reaching into its internals.
type recordingEventStream struct {
	mu     sync.Mutex
	events []Event
}

func (r *recordingEventStream) Send(_ context.Context, evt Event) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.events = append(r.events, evt)
}

func (r *recordingEventStream) count(match func(Event) bool) int {
	r.mu.Lock()
	defer r.mu.Unlock()

	var n int

	for _, evt := range r.events {
		if match(evt) {
			n++
		}
	}

	return n
}

func (r *recordingEventStream) frontings() int {
	return r.count(func(evt Event) bool {
		_, ok := evt.(EventDomainFronting)

		return ok
	})
}

func (r *recordingEventStream) replays() int {
	return r.count(func(evt Event) bool {
		_, ok := evt.(EventReplayAttack)

		return ok
	})
}

// memAntiReplay is a deterministic TestAndAdd, unlike the production stable
// bloom filter which evicts. A replay test must not race an eviction.
type memAntiReplay struct {
	mu   sync.Mutex
	seen map[string]struct{}
}

func newMemAntiReplay() *memAntiReplay {
	return &memAntiReplay{seen: make(map[string]struct{})}
}

func (m *memAntiReplay) SeenBefore(data []byte) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := string(data)
	if _, ok := m.seen[key]; ok {
		return true
	}

	m.seen[key] = struct{}{}

	return false
}

// fakeNetwork routes every Telegram dial to a local listener the test owns and
// counts native (fronting) dials without ever performing one.
type fakeNetwork struct {
	upstream net.Listener

	mu          sync.Mutex
	dialed      []string
	nativeDials int
}

func (f *fakeNetwork) Dial(_, address string) (essentials.Conn, error) {
	f.mu.Lock()
	f.dialed = append(f.dialed, address)
	f.mu.Unlock()

	conn, err := net.Dial("tcp", f.upstream.Addr().String())
	if err != nil {
		return nil, err //nolint: wrapcheck
	}

	return essentials.WrapNetConn(conn), nil
}

func (f *fakeNetwork) DialContext(_ context.Context, network, address string) (essentials.Conn, error) {
	return f.Dial(network, address)
}

func (f *fakeNetwork) MakeHTTPClient(
	_ func(ctx context.Context, network, address string) (essentials.Conn, error),
) *http.Client {
	return &http.Client{}
}

func (f *fakeNetwork) NativeDialer() *net.Dialer {
	return &net.Dialer{
		Control: func(_, _ string, _ syscall.RawConn) error {
			f.mu.Lock()
			defer f.mu.Unlock()

			f.nativeDials++

			return nil
		},
	}
}

func (f *fakeNetwork) telegramDials() int {
	f.mu.Lock()
	defer f.mu.Unlock()

	return len(f.dialed)
}

func (f *fakeNetwork) frontingDials() int {
	f.mu.Lock()
	defer f.mu.Unlock()

	return f.nativeDials
}

// entryHarness is a proxy wired for either entry: a real secret set, a fake
// Telegram upstream and recording observers. The doppelganger is constructed
// but left stopped; a test that drives the FakeTLS path end to end has to Run
// it, because Ganger.NewConn is a channel round-trip with the run loop.
type entryHarness struct {
	proxy    *Proxy
	events   *recordingEventStream
	network  *fakeNetwork
	upstream net.Listener

	// serverBytesRead counts every byte the proxy consumed from the client ends
	// this harness handed to ServeConn. It is what makes "did the refusal read
	// the frame or not" a measurement instead of an inference.
	serverBytesRead atomic.Int64
}

// readCountingConn tallies what the proxy read off the wire.
type readCountingConn struct {
	essentials.Conn

	read *atomic.Int64
}

func (c readCountingConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	c.read.Add(int64(n))

	return n, err //nolint: wrapcheck
}

func newEntryHarness(t testing.TB, secrets map[string]Secret, limits map[string]SecretLimits) *entryHarness {
	t.Helper()

	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { upstream.Close() }) //nolint: errcheck

	// A deadline so a regression that stops dialling Telegram fails the test
	// instead of hanging it.
	require.NoError(t, upstream.(*net.TCPListener).SetDeadline(time.Now().Add(20*time.Second)))

	telegram, err := dc.New(DefaultPreferIP)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	events := &recordingEventStream{}
	network := &fakeNetwork{upstream: upstream}

	proxy := &Proxy{
		ctx:                  ctx,
		ctxCancel:            cancel,
		stats:                NewProxyStats(),
		liveConns:            make(map[string]map[*streamContext]struct{}),
		logger:               testLogger(),
		eventStream:          events,
		network:              network,
		antiReplayCache:      newMemAntiReplay(),
		telegram:             telegram,
		handshakeTimeout:     5 * time.Second,
		idleTimeout:          time.Second,
		tolerateTimeSkewness: time.Hour,
		// A fronting host that is never reachable: any attempt to front from an
		// obfuscated listener is a bug, and this makes it visible instead of
		// silently dialling something real.
		domainFrontingHost: "127.0.0.1",
		domainFrontingPort: 1,
		// Constructed but not Run: NoiseParams answers with its zero value, which
		// is all doFakeTLSHandshake needs. A test that goes further -- through the
		// doppelganger wrap in ServeConn -- must Run it, because NewConn is a
		// channel round-trip with that run loop. With no scout URLs the raid it
		// starts is a no-op.
		doppelGanger: doppel.NewGanger(ctx, network, testLogger(), time.Hour, 1, nil, false),
	}

	set := buildSecretSet(secrets, nil, nil, limits)
	for _, name := range set.names {
		proxy.stats.PreRegister(name)
	}

	proxy.secrets.Store(set)
	// What NewProxy does after storing the set, so a harness with limits is
	// the proxy an operator would get and not a quieter one.
	proxy.applyLimits(set)
	proxy.obfsLimiter = newObfuscatedLimiter(ctx)

	return &entryHarness{
		proxy:    proxy,
		events:   events,
		network:  network,
		upstream: upstream,
	}
}

// dialProxy hands one accepted TCP connection to ServeConn (optionally stamped
// with a policy) and returns the client end. A real TCP pair is used so
// RemoteAddr is a *net.TCPAddr, which is what the policy layer reads.
func (h *entryHarness) dialProxy(t testing.TB, policy *ListenerPolicy) (net.Conn, <-chan struct{}) {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	defer listener.Close() //nolint: errcheck

	client, err := net.Dial("tcp", listener.Addr().String())
	require.NoError(t, err)

	t.Cleanup(func() { client.Close() }) //nolint: errcheck

	server, err := listener.Accept()
	require.NoError(t, err)

	var conn essentials.Conn = readCountingConn{
		Conn: essentials.WrapNetConn(server),
		read: &h.serverBytesRead,
	}

	if policy != nil {
		conn = policyConn{Conn: conn, policy: *policy}
	}

	done := make(chan struct{})

	go func() {
		defer close(done)

		h.proxy.ServeConn(conn)
	}()

	return client, done
}

// obfuscatedFrame produces exactly the 64 bytes a client sends for this key,
// transport tag and DC.
func obfuscatedFrame(t testing.TB, key [SecretKeyLength]byte, tag obfuscation.ConnectionTag, dcID int) []byte {
	t.Helper()

	sink := &frameSink{}

	_, err := obfuscation.Obfuscator{Secret: key[:]}.SendHandshake(sink, dcID, tag)
	require.NoError(t, err)

	return sink.wrote.Bytes()
}

// frameSink is an essentials.Conn that only supports Write. The embedded
// interface is nil on purpose so any other call panics loudly.
type frameSink struct {
	essentials.Conn

	wrote bytes.Buffer
}

func (f *frameSink) Write(p []byte) (int, error) {
	return f.wrote.Write(p) //nolint: wrapcheck
}

func obfuscatedPolicy(modes ModeSet, action UnknownSecretAction) *ListenerPolicy {
	return &ListenerPolicy{Modes: modes, OnUnknownSecret: action}
}

// liveStream returns the single registered stream for a secret name, waiting a
// short while for ServeConn to get there.
func (h *entryHarness) liveStream(t testing.TB, name string) *streamContext {
	t.Helper()

	for range 200 {
		h.proxy.liveMu.Lock()
		for stream := range h.proxy.liveConns[name] {
			h.proxy.liveMu.Unlock()

			return stream
		}
		h.proxy.liveMu.Unlock()

		time.Sleep(5 * time.Millisecond)
	}

	return nil
}

// TestObfuscatedEntryAttributesBeforeAccounting is the point of the whole entry
// split: on a plaintext listener the secret is unknown until the frame is
// decrypted, so every counter, the live-connection registry and the logger
// binding must wait for it. If admission ran first, all of this would land in
// the "" bucket.
func TestObfuscatedEntryAttributesBeforeAccounting(t *testing.T) {
	t.Parallel()

	alice, err := GenerateSecretMode(SecretModeDD, "")
	require.NoError(t, err)

	// bob sorts after alice, so a set-order bug would attribute to alice.
	bob, err := GenerateSecretMode(SecretModeDD, "")
	require.NoError(t, err)

	h := newEntryHarness(t, map[string]Secret{"alice": alice, "bob": bob}, nil)

	client, done := h.dialProxy(t, obfuscatedPolicy(ModeSetOf(SecretModeDD), UnknownSecretClose))

	_, err = client.Write(obfuscatedFrame(t, bob.Key, obfuscation.TagPaddedIntermediate, 2))
	require.NoError(t, err)

	// The proxy dials Telegram only after attribution succeeded, and the
	// upstream frame proves doTelegramCall ran.
	upstream, err := h.upstream.Accept()
	require.NoError(t, err)

	defer upstream.Close() //nolint: errcheck

	require.NoError(t, upstream.SetReadDeadline(time.Now().Add(5*time.Second)))

	var handshake [64]byte

	_, err = io.ReadFull(upstream, handshake[:])
	require.NoError(t, err)

	stream := h.liveStream(t, "bob")
	require.NotNil(t, stream, "the stream must be registered under the matched name")

	h.proxy.liveMu.Lock()
	assert.Equal(t, "bob", stream.secretName)
	assert.Equal(t, obfuscation.TagPaddedIntermediate, stream.connTag)
	assert.Equal(t, entryObfuscated, stream.entry)
	assert.NotContains(t, h.proxy.liveConns, "", "nothing may be registered under the empty name")
	assert.NotContains(t, h.proxy.liveConns, "alice")
	h.proxy.liveMu.Unlock()

	assert.Equal(t, int64(1), h.proxy.stats.users["bob"].connections.Load())
	assert.Equal(t, 0, h.events.frontings(), "an obfuscated listener must never front")

	client.Close() //nolint: errcheck
	<-done
}

// TestObfuscatedEntryHonoursOnlyConfiguredTags pins the difference between the
// dd and plain modes: dd is padded-intermediate and nothing else, while a bare
// key places no constraint on the client's transport.
func TestObfuscatedEntryHonoursOnlyConfiguredTags(t *testing.T) {
	t.Parallel()

	secret, err := GenerateSecretMode(SecretModePlain, "")
	require.NoError(t, err)

	cases := []struct {
		name      string
		modes     ModeSet
		tag       obfuscation.ConnectionTag
		wantAdmit bool
	}{
		{"abridged on plain listener", ModeSetOf(SecretModePlain), obfuscation.TagAbridged, true},
		{"intermediate on plain listener", ModeSetOf(SecretModePlain), obfuscation.TagIntermediate, true},
		{"abridged on dd listener", ModeSetOf(SecretModeDD), obfuscation.TagAbridged, false},
		{"padded on dd listener", ModeSetOf(SecretModeDD), obfuscation.TagPaddedIntermediate, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newEntryHarness(t, map[string]Secret{"alice": secret}, nil)

			client, done := h.dialProxy(t, obfuscatedPolicy(tc.modes, UnknownSecretClose))

			_, err := client.Write(obfuscatedFrame(t, secret.Key, tc.tag, 2))
			require.NoError(t, err)

			if tc.wantAdmit {
				stream := h.liveStream(t, "alice")
				require.NotNil(t, stream, "an honoured transport must be admitted")

				h.proxy.liveMu.Lock()
				assert.Equal(t, tc.tag, stream.connTag, "the client's own tag must be carried through")
				h.proxy.liveMu.Unlock()

				client.Close() //nolint: errcheck
				<-done

				return
			}

			<-done

			assertDeniedSilently(t, client)
			assert.Equal(t, 0, h.network.telegramDials())
			assert.Equal(t, 0, h.events.frontings())
		})
	}
}

// assertDeniedSilently checks the one property every deny path shares: the
// proxy never wrote a byte back before closing.
func assertDeniedSilently(t *testing.T, client net.Conn) {
	t.Helper()

	require.NoError(t, client.SetReadDeadline(time.Now().Add(5*time.Second)))

	var buf [1]byte

	n, err := client.Read(buf[:])
	assert.Zero(t, n, "a refused obfuscated connection must never write a byte back")
	assert.Error(t, err)
}

// probeHandshakeTimeout keeps the timing probes quick. It stands in for the
// production DefaultHandshakeTimeout of 10s.
const probeHandshakeTimeout = time.Second

// obfuscatedProbe is one connection's whole observable exit: how long the proxy
// held it, how many bytes it consumed, and how the socket ended. A clean FIN
// reads back as io.EOF; a reset (which is what a close with unread bytes still
// in the receive queue produces) does not.
type obfuscatedProbe struct {
	elapsed   time.Duration
	bytesRead int64
	readErr   error
}

// probe runs one connection to completion and reports what a censor sees.
func (h *entryHarness) probe(t *testing.T, policy *ListenerPolicy, payload []byte) obfuscatedProbe {
	t.Helper()

	client, done := h.dialProxy(t, policy)

	started := time.Now()

	if len(payload) > 0 {
		_, err := client.Write(payload)
		require.NoError(t, err)
	}

	<-done

	elapsed := time.Since(started)

	// Read only after ServeConn has returned, so the close has already landed
	// and this cannot race FIN against RST.
	require.NoError(t, client.SetReadDeadline(time.Now().Add(5*time.Second)))

	var buf [1]byte

	_, err := client.Read(buf[:])

	return obfuscatedProbe{
		elapsed:   elapsed,
		bytesRead: h.serverBytesRead.Load(),
		readErr:   err,
	}
}

// TestObfuscatedRateLimitedExitMatchesMiss is the acceptance test for the
// rate-limited exit, and it is two probes a censor can actually run.
//
// Silence probe: connect and send nothing. A peer with budget is held for the
// whole handshake timeout; a peer without budget must be held for exactly as
// long. When the budget was consulted before the read, it was closed in ~0ms
// having read nothing -- so burning the budget with junk and then opening one
// silent connection named the listener in a single round trip.
//
// 64-byte probe: send a frame no secret matches. Both peers must consume all 64
// bytes and end the same way. When the budget was consulted first, the
// rate-limited peer left 64 unread bytes in the receive queue, and closing a
// socket in that state sends a reset instead of a FIN -- one connection, one
// read, deny reason recovered.
func TestObfuscatedRateLimitedExitMatchesMiss(t *testing.T) {
	t.Parallel()

	known, err := GenerateSecretMode(SecretModeDD, "")
	require.NoError(t, err)

	unknown, err := GenerateSecretMode(SecretModeDD, "")
	require.NoError(t, err)

	// Public, because the budget is armed only there, and close, because that is
	// the default disposal and the only one on which the two exits are required
	// to be identical (see SECURITY.md on the drain listener).
	policy := &ListenerPolicy{
		Modes:           ModeSetOf(SecretModeDD),
		Public:          true,
		HandshakesPerIP: 1,
		OnUnknownSecret: UnknownSecretClose,
	}

	// A fresh harness per probe: the byte counter must belong to one connection,
	// and the budget must be exhausted for one of them and untouched for the
	// other.
	runProbe := func(t *testing.T, exhausted bool, payload []byte) obfuscatedProbe {
		t.Helper()

		h := newEntryHarness(t, map[string]Secret{"alice": known}, nil)
		h.proxy.handshakeTimeout = probeHandshakeTimeout

		if exhausted {
			// The burst is 2x the rate, so three failures empty the bucket.
			for range 3 {
				h.proxy.obfsLimiter.Fail(*policy, net.ParseIP("127.0.0.1"))
			}

			require.False(t, h.proxy.obfsLimiter.Allow(*policy, net.ParseIP("127.0.0.1")))
		}

		return h.probe(t, policy, payload)
	}

	t.Run("silence probe", func(t *testing.T) {
		t.Parallel()

		budgeted := runProbe(t, false, nil)
		limited := runProbe(t, true, nil)

		t.Logf("silence: budgeted elapsed=%v read=%d err=%v", budgeted.elapsed, budgeted.bytesRead, budgeted.readErr)
		t.Logf("silence: limited  elapsed=%v read=%d err=%v", limited.elapsed, limited.bytesRead, limited.readErr)

		// Both must sit in the same io.ReadFull until the same deadline.
		floor := probeHandshakeTimeout - probeHandshakeTimeout/10

		assert.GreaterOrEqual(t, budgeted.elapsed, floor)
		assert.GreaterOrEqual(t, limited.elapsed, floor,
			"a rate-limited peer must be held exactly as long as one with budget")

		assert.Equal(t, int64(0), budgeted.bytesRead)
		assert.Equal(t, int64(0), limited.bytesRead)
	})

	t.Run("64 byte probe", func(t *testing.T) {
		t.Parallel()

		frame := obfuscatedFrame(t, unknown.Key, obfuscation.TagPaddedIntermediate, 2)

		budgeted := runProbe(t, false, frame)
		limited := runProbe(t, true, frame)

		t.Logf("64-byte: budgeted elapsed=%v read=%d err=%v", budgeted.elapsed, budgeted.bytesRead, budgeted.readErr)
		t.Logf("64-byte: limited  elapsed=%v read=%d err=%v", limited.elapsed, limited.bytesRead, limited.readErr)

		assert.Equal(t, int64(64), budgeted.bytesRead)
		assert.Equal(t, int64(64), limited.bytesRead,
			"a rate-limited peer must consume the frame, not leave it in the receive queue")

		// The frame is read and the socket closed at once on both, so neither may
		// approach the handshake deadline.
		assert.Less(t, budgeted.elapsed, probeHandshakeTimeout/2)
		assert.Less(t, limited.elapsed, probeHandshakeTimeout/2)

		// A clean FIN on both. An unread receive queue would show up here as a
		// reset instead.
		assert.ErrorIs(t, budgeted.readErr, io.EOF)
		assert.ErrorIs(t, limited.readErr, io.EOF,
			"a rate-limited peer must get the same clean FIN a no-match gets")
	})
}

// TestObfuscatedDenyNeverAnswersOrFronts covers the exits a prober can reach:
// no matching secret and an over-quota user must be indistinguishable, and
// neither may reach the cover site.
func TestObfuscatedDenyNeverAnswersOrFronts(t *testing.T) {
	t.Parallel()

	known, err := GenerateSecretMode(SecretModeDD, "")
	require.NoError(t, err)

	unknown, err := GenerateSecretMode(SecretModeDD, "")
	require.NoError(t, err)

	cases := []struct {
		name      string
		limits    map[string]SecretLimits
		quotaUsed int64
		frameOf   Secret
	}{
		{"no matching secret", nil, 0, unknown},
		{"disabled user", map[string]SecretLimits{"alice": {Disabled: true}}, 0, known},
		{"expired user", map[string]SecretLimits{"alice": {ExpiresAt: time.Now().Add(-time.Hour)}}, 0, known},
		{"over quota user", map[string]SecretLimits{"alice": {QuotaBytes: 100}}, 500, known},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newEntryHarness(t, map[string]Secret{"alice": known}, tc.limits)
			h.proxy.stats.users["alice"].quotaUsed.Store(tc.quotaUsed)

			client, done := h.dialProxy(t, obfuscatedPolicy(ModeSetOf(SecretModeDD), UnknownSecretClose))

			_, err := client.Write(obfuscatedFrame(t, tc.frameOf.Key, obfuscation.TagPaddedIntermediate, 2))
			require.NoError(t, err)

			<-done

			assertDeniedSilently(t, client)
			assert.Equal(t, 0, h.events.frontings(), "the obfuscated deny path must never domain-front")
			assert.Equal(t, 0, h.network.frontingDials())
			assert.Equal(t, 0, h.network.telegramDials())
			assert.Equal(t, int64(0), h.proxy.stats.users["alice"].connections.Load())
		})
	}
}

// TestObfuscatedDrainIsBoundedByHandshakeTimeout runs the slot-exhaustion
// lever: connect, idle until just before the handshake deadline, send a
// non-matching frame, then dribble. When the drain opened a window of its own,
// that bought a hold of handshakeTimeout + drain window -- about 30s at the
// defaults -- and at DefaultConcurrency roughly 140 conn/s is then enough to
// saturate the worker pool and start dropping real clients with
// ErrPoolOverload. The drain inherits the handshake deadline, so the total hold
// is handshakeTimeout, full stop.
func TestObfuscatedDrainIsBoundedByHandshakeTimeout(t *testing.T) {
	t.Parallel()

	known, err := GenerateSecretMode(SecretModeDD, "")
	require.NoError(t, err)

	unknown, err := GenerateSecretMode(SecretModeDD, "")
	require.NoError(t, err)

	h := newEntryHarness(t, map[string]Secret{"alice": known}, nil)
	h.proxy.handshakeTimeout = probeHandshakeTimeout

	client, done := h.dialProxy(t, obfuscatedPolicy(ModeSetOf(SecretModeDD), UnknownSecretDrain))

	started := time.Now()

	// Spend nearly the whole handshake budget before byte 64 even arrives.
	time.Sleep(probeHandshakeTimeout * 9 / 10)

	_, err = client.Write(obfuscatedFrame(t, unknown.Key, obfuscation.TagPaddedIntermediate, 2))
	require.NoError(t, err)

	// Dribble, slowly enough never to reach the 8 KiB bound: time has to be
	// what ends this.
	dribbling := make(chan struct{})

	go func() {
		defer close(dribbling)

		for {
			select {
			case <-done:
				return
			case <-time.After(20 * time.Millisecond):
				if _, err := client.Write([]byte{0x00}); err != nil {
					return
				}
			}
		}
	}()

	<-done
	<-dribbling

	elapsed := time.Since(started)

	t.Logf("drain lever: total hold=%v (handshake timeout %v)", elapsed, probeHandshakeTimeout)

	assert.Less(t, elapsed, probeHandshakeTimeout+probeHandshakeTimeout/2,
		"the total hold must be bounded by the handshake timeout, not extended by the drain")
	assert.Equal(t, int64(1), h.proxy.obfsStats.denied.Load())
	assert.Equal(t, int64(0), h.proxy.obfsStats.draining.Load())
}

// TestObfuscatedRateLimitedPeerDoesNotDrain is the other half of that bound: a
// peer that has spent its per-IP budget gets the shortest disposal, not the
// longest one. Giving it the drain inverted the point of the budget -- one IP
// could hold a worker slot for a whole handshakeTimeout, over and over, and the
// budget would do nothing about it.
func TestObfuscatedRateLimitedPeerDoesNotDrain(t *testing.T) {
	t.Parallel()

	known, err := GenerateSecretMode(SecretModeDD, "")
	require.NoError(t, err)

	unknown, err := GenerateSecretMode(SecretModeDD, "")
	require.NoError(t, err)

	policy := &ListenerPolicy{
		Modes:           ModeSetOf(SecretModeDD),
		Public:          true,
		HandshakesPerIP: 1,
		OnUnknownSecret: UnknownSecretDrain,
	}

	h := newEntryHarness(t, map[string]Secret{"alice": known}, nil)
	h.proxy.handshakeTimeout = probeHandshakeTimeout

	for range 3 {
		h.proxy.obfsLimiter.Fail(*policy, net.ParseIP("127.0.0.1"))
	}

	client, done := h.dialProxy(t, policy)

	started := time.Now()

	_, err = client.Write(obfuscatedFrame(t, unknown.Key, obfuscation.TagPaddedIntermediate, 2))
	require.NoError(t, err)

	// Bytes a drain would swallow. The frame itself must still be read.
	_, err = client.Write(make([]byte, 512))
	require.NoError(t, err)

	<-done

	elapsed := time.Since(started)

	t.Logf("rate-limited on a drain listener: hold=%v read=%d", elapsed, h.serverBytesRead.Load())

	assert.Less(t, elapsed, probeHandshakeTimeout/2, "a rate-limited peer must not be drained")
	assert.Equal(t, int64(64), h.serverBytesRead.Load(),
		"the frame is read, and nothing beyond it")
	assert.Equal(t, int64(1), h.proxy.obfsStats.rateLimited.Load())
	assert.Equal(t, int64(1), h.proxy.obfsStats.denied.Load(), "it still takes the deny exit")
	assert.Equal(t, int64(0), h.proxy.obfsStats.trials.Load(), "and never enters the trial loop")

	assertDeniedSilently(t, client)
}

// TestObfuscatedThrottleTakesTheDenyExit pins the rule that every failure on an
// obfuscated listener takes one exit. Throttling ran after the entry and
// returned with no disposal at all: on a drain listener the throttled stream
// was closed at once while an unknown secret was drained, and it was missing
// from the denied counter -- the deny reason readable in one connection.
func TestObfuscatedThrottleTakesTheDenyExit(t *testing.T) {
	t.Parallel()

	secret, err := GenerateSecretMode(SecretModeDD, "")
	require.NoError(t, err)

	h := newEntryHarness(t, map[string]Secret{"alice": secret}, nil)

	// A cap of zero connections: the secret is valid and within its limits, and
	// admission refuses it anyway.
	h.proxy.stats.SetThrottle(1, time.Hour)
	h.proxy.stats.throttleMu.Lock()
	h.proxy.stats.throttleCaps["alice"] = 0
	h.proxy.stats.throttleMu.Unlock()

	client, done := h.dialProxy(t, obfuscatedPolicy(ModeSetOf(SecretModeDD), UnknownSecretDrain))

	_, err = client.Write(obfuscatedFrame(t, secret.Key, obfuscation.TagPaddedIntermediate, 2))
	require.NoError(t, err)

	_, err = client.Write(make([]byte, 512))
	require.NoError(t, err)

	require.NoError(t, client.(*net.TCPConn).CloseWrite())

	<-done

	assertDeniedSilently(t, client)

	throttled := h.events.count(func(evt Event) bool {
		_, ok := evt.(EventThrottled)

		return ok
	})

	assert.Equal(t, 1, throttled)
	assert.Equal(t, int64(1), h.proxy.obfsStats.denied.Load(),
		"a throttled stream is denied like every other refusal on this listener")
	assert.Greater(t, h.serverBytesRead.Load(), int64(64),
		"and it is drained like every other refusal on a drain listener")
	assert.Equal(t, int64(0), h.proxy.obfsStats.draining.Load())
	assert.Equal(t, 0, h.network.telegramDials())
	assert.Equal(t, 0, h.events.frontings())

	h.proxy.liveMu.Lock()
	assert.Empty(t, h.proxy.liveConns["alice"])
	h.proxy.liveMu.Unlock()
}

// TestObfuscatedDenyDrainReadsAndDiscards pins the drain disposal: the peer's
// bytes are consumed rather than answered, and still nothing comes back.
func TestObfuscatedDenyDrainReadsAndDiscards(t *testing.T) {
	t.Parallel()

	known, err := GenerateSecretMode(SecretModeDD, "")
	require.NoError(t, err)

	unknown, err := GenerateSecretMode(SecretModeDD, "")
	require.NoError(t, err)

	h := newEntryHarness(t, map[string]Secret{"alice": known}, nil)

	client, done := h.dialProxy(t, obfuscatedPolicy(ModeSetOf(SecretModeDD), UnknownSecretDrain))

	_, err = client.Write(obfuscatedFrame(t, unknown.Key, obfuscation.TagPaddedIntermediate, 2))
	require.NoError(t, err)

	// The drain reads until the bound or EOF; closing our write end ends it.
	_, err = client.Write(make([]byte, 4096))
	require.NoError(t, err)

	require.NoError(t, client.(*net.TCPConn).CloseWrite())

	<-done

	assertDeniedSilently(t, client)
	assert.Equal(t, 0, h.events.frontings())
	assert.Equal(t, int64(1), h.proxy.obfsStats.denied.Load())
	assert.Equal(t, int64(0), h.proxy.obfsStats.draining.Load(), "the drain gauge must return to zero")
}

// TestObfuscatedReplayIsRefusedAfterFirstUse pins both halves: the first frame
// is admitted, and a byte-identical replay of it takes the deny exit.
func TestObfuscatedReplayIsRefusedAfterFirstUse(t *testing.T) {
	t.Parallel()

	secret, err := GenerateSecretMode(SecretModeDD, "")
	require.NoError(t, err)

	h := newEntryHarness(t, map[string]Secret{"alice": secret}, nil)

	frame := obfuscatedFrame(t, secret.Key, obfuscation.TagPaddedIntermediate, 2)
	policy := obfuscatedPolicy(ModeSetOf(SecretModeDD), UnknownSecretClose)

	first, firstDone := h.dialProxy(t, policy)

	_, err = first.Write(frame)
	require.NoError(t, err)

	require.NotNil(t, h.liveStream(t, "alice"), "the first use of a frame must be admitted")

	second, secondDone := h.dialProxy(t, policy)

	_, err = second.Write(frame)
	require.NoError(t, err)

	<-secondDone

	assertDeniedSilently(t, second)
	assert.Equal(t, 1, h.events.replays())
	assert.Equal(t, 0, h.events.frontings(), "a replay on this path must not be fronted either")

	first.Close() //nolint: errcheck
	<-firstDone
}

// tlsApplicationRecord frames a payload as one TLS 1.2 application-data
// record. After SendServerHello the ee entry reads through the faketls record
// layer, so this is how a real client's obfuscated handshake arrives.
func tlsApplicationRecord(payload []byte) []byte {
	record := []byte{
		tls.TypeApplicationData,
		tls.TLSVersion[0], tls.TLSVersion[1],
		byte(len(payload) >> 8), byte(len(payload)),
	}

	return append(record, payload...)
}

// TestFakeTLSEntryEndToEndThroughServeConn drives the whole ee path through the
// restructured ServeConn: ClientHello, ServerHello, admission, the doppelganger
// wrap, the obfuscated handshake read back out through the record layer, the
// deadline clear, the Telegram dial, and registration under the matched name.
//
// Every other FakeTLS test calls doFakeTLSHandshake directly, so the ordering
// this restructure exists to preserve had nothing holding it in place. What
// this pins, and each of them is a real regression shape:
//   - admit runs and registers the stream under the name the ee handshake
//     matched, not under "" and not under the wrong index;
//   - the doppelganger wrap and the obfuscated handshake still happen, and on
//     this path only -- dc and connTag come from the client's own frame, which
//     is only readable if the wrap went in the right place;
//   - the deadline is cleared and Telegram is dialled;
//   - release undoes admission when the stream ends.
func TestFakeTLSEntryEndToEndThroughServeConn(t *testing.T) {
	t.Parallel()

	hosted := GenerateSecret("cover.example.com")

	dd, err := GenerateSecretMode(SecretModeDD, "")
	require.NoError(t, err)

	// "aaa" is hostless and sorts first, so a stream billed through the hosted
	// candidate index without mapping back shows up here as the wrong name.
	h := newEntryHarness(t, map[string]Secret{"aaa": dd, "zzz": hosted}, nil)

	// Ganger.NewConn is a channel round-trip with the run loop, so the ee path
	// cannot get past the wrap unless the ganger is running.
	h.proxy.doppelGanger.Run()
	t.Cleanup(h.proxy.doppelGanger.Shutdown)

	client, done := h.dialProxy(t, nil)

	_, err = client.Write(fakeTLSClientHello(t, hosted.Key, "cover.example.com", bytes.Repeat([]byte{0x33}, 32)))
	require.NoError(t, err)

	// Wait for the ServerHello before sending the frame, exactly as a client
	// does. It also keeps the two out of one read buffer.
	require.NoError(t, client.SetReadDeadline(time.Now().Add(5*time.Second)))

	var serverHello [1]byte

	_, err = io.ReadFull(client, serverHello[:])
	require.NoError(t, err, "the ee entry must answer a valid ClientHello")

	firstRecordType := serverHello[0]
	require.EqualValues(t, 0x16, firstRecordType, "the flight must open with a handshake record")

	frame := obfuscatedFrame(t, hosted.Key, obfuscation.TagPaddedIntermediate, 2)

	_, err = client.Write(tlsApplicationRecord(frame))
	require.NoError(t, err)

	upstream, err := h.upstream.Accept()
	require.NoError(t, err, "the ee path must dial Telegram")

	defer upstream.Close() //nolint: errcheck

	require.NoError(t, upstream.SetReadDeadline(time.Now().Add(5*time.Second)))

	var handshake [64]byte

	_, err = io.ReadFull(upstream, handshake[:])
	require.NoError(t, err)

	// Anything Telegram sends must reach the client inside TLS application
	// records. Nothing else in the suite observes the server->client direction,
	// so without this the doppelganger wrap could be deleted from ServeConn and
	// every test would still pass while every real ee client broke: the relayed
	// bytes would arrive raw and the record parse below would not survive it.
	const relayed = 128

	_, err = upstream.Write(bytes.Repeat([]byte{0x5a}, relayed))
	require.NoError(t, err)

	assertTLSFramedAtLeast(t, client, firstRecordType, relayed)

	stream := h.liveStream(t, "zzz")
	require.NotNil(t, stream, "the stream must be registered under the matched secret name")

	h.proxy.liveMu.Lock()
	assert.Equal(t, "zzz", stream.secretName)
	assert.Equal(t, entryFakeTLS, stream.entry)
	assert.Equal(t, 2, stream.dc,
		"the dc must come from the client's own frame, read back out through the record layer")
	assert.Equal(t, obfuscation.TagPaddedIntermediate, stream.connTag)
	assert.NotContains(t, h.proxy.liveConns, "", "nothing may be registered under the empty name")
	assert.NotContains(t, h.proxy.liveConns, "aaa")
	h.proxy.liveMu.Unlock()

	assert.Equal(t, int64(1), h.proxy.stats.users["zzz"].connections.Load())
	assert.Equal(t, 0, h.events.frontings(), "a valid ClientHello must not be fronted")

	client.Close() //nolint: errcheck
	<-done

	// release is the other half of admit, and it runs on this path too.
	h.proxy.liveMu.Lock()
	assert.Empty(t, h.proxy.liveConns["zzz"])
	h.proxy.liveMu.Unlock()

	assert.Equal(t, int64(0), h.proxy.stats.users["zzz"].connections.Load())
}

// TestBareServeConnDefaultsToFakeTLS is the fail-closed guarantee: a connection
// that carries no policy -- an embedder calling ServeConn, a listener wired
// without a policy -- must never reach the obfuscated entry.
func TestBareServeConnDefaultsToFakeTLS(t *testing.T) {
	t.Parallel()

	hosted := GenerateSecret("front.example.com")
	dd, err := GenerateSecretMode(SecretModeDD, "")
	require.NoError(t, err)

	h := newEntryHarness(t, map[string]Secret{"alice": hosted, "bob": dd}, nil)

	client, done := h.dialProxy(t, nil)

	// A perfectly valid dd frame. On the FakeTLS door it is not a ClientHello,
	// so it is fronted -- never attributed, never admitted.
	_, err = client.Write(obfuscatedFrame(t, dd.Key, obfuscation.TagPaddedIntermediate, 2))
	require.NoError(t, err)

	<-done

	assert.Equal(t, 1, h.events.frontings(), "an unstamped conn must take the FakeTLS door")
	assert.Equal(t, 0, h.network.telegramDials())

	h.proxy.liveMu.Lock()
	assert.Empty(t, h.proxy.liveConns)
	h.proxy.liveMu.Unlock()

	assert.Equal(t, int64(0), h.proxy.stats.users["bob"].connections.Load())
}

// TestPolicyConnIsUnwrapped checks that the policy is stripped before the
// stream context is built, so nothing downstream sees the wrapper.
func TestPolicyConnIsUnwrapped(t *testing.T) {
	t.Parallel()

	secret, err := GenerateSecretMode(SecretModeDD, "")
	require.NoError(t, err)

	h := newEntryHarness(t, map[string]Secret{"alice": secret}, nil)

	client, done := h.dialProxy(t, obfuscatedPolicy(ModeSetOf(SecretModeDD), UnknownSecretClose))

	_, err = client.Write(obfuscatedFrame(t, secret.Key, obfuscation.TagPaddedIntermediate, 2))
	require.NoError(t, err)

	stream := h.liveStream(t, "alice")
	require.NotNil(t, stream)

	h.proxy.liveMu.Lock()
	_, wrapped := stream.client().(policyConn)
	h.proxy.liveMu.Unlock()

	assert.False(t, wrapped, "policyConn must not survive into the stream context")

	client.Close() //nolint: errcheck
	<-done
}

func TestObfuscatedLimiterDisarmedOnLoopbackListener(t *testing.T) {
	t.Parallel()

	limiter := newObfuscatedLimiter(t.Context())
	policy := ListenerPolicy{Modes: ModeSetOf(SecretModeDD), HandshakesPerIP: 1}
	ip := net.ParseIP("127.0.0.1")

	// Not public: behind a loopback carrier every connection presents the same
	// address, so a per-IP bucket would be one shared bucket an attacker empties
	// for every legitimate user at once.
	for range 100 {
		limiter.Fail(policy, ip)
	}

	assert.True(t, limiter.Allow(policy, ip))
}

func TestObfuscatedLimiterBudgetsFailuresPerIP(t *testing.T) {
	t.Parallel()

	limiter := newObfuscatedLimiter(t.Context())
	policy := ListenerPolicy{Modes: ModeSetOf(SecretModeDD), Public: true, HandshakesPerIP: 1}

	first := net.ParseIP("198.51.100.7")
	second := net.ParseIP("198.51.100.8")

	assert.True(t, limiter.Allow(policy, first), "an unseen peer starts with a full burst")

	// Burst is 2x the rate, so the third failure exhausts it.
	for range 3 {
		limiter.Fail(policy, first)
	}

	assert.False(t, limiter.Allow(policy, first))
	assert.True(t, limiter.Allow(policy, second), "one peer's budget must not touch another's")

	// A zero budget disables the limiter entirely.
	assert.True(t, limiter.Allow(ListenerPolicy{Public: true}, first))
}

func TestObfuscatedLimiterKeysIPv6OnPrefix(t *testing.T) {
	t.Parallel()

	limiter := newObfuscatedLimiter(t.Context())
	policy := ListenerPolicy{Modes: ModeSetOf(SecretModeDD), Public: true, HandshakesPerIP: 1}

	// A single host is routinely handed a whole /64, so budgeting per address
	// would be free to evade.
	for range 3 {
		limiter.Fail(policy, net.ParseIP("2001:db8::1"))
	}

	assert.False(t, limiter.Allow(policy, net.ParseIP("2001:db8::dead:beef")))
	assert.True(t, limiter.Allow(policy, net.ParseIP("2001:db8:0:1::1")))
}

// assertTLSFramedAtLeast consumes the FakeTLS server flight and then asserts
// that at least want bytes of relayed traffic arrive as well-formed TLS
// application records. firstType is the flight's opening record type, already
// read off the wire by the caller.
//
// The flight is exactly three records -- ServerHello, ChangeCipherSpec, and one
// noise record -- so accumulation starts only after them, and the relayed bytes
// cannot be satisfied by the noise. Without the doppelganger wrap the relayed
// bytes arrive raw and the header checks below fail on the first one.
func assertTLSFramedAtLeast(t *testing.T, r io.Reader, firstType byte, want int) {
	t.Helper()

	readHeader := func(typeByte byte) int {
		t.Helper()

		var rest [4]byte

		_, err := io.ReadFull(r, rest[:])
		require.NoError(t, err, "a TLS record header must follow")
		require.EqualValues(t, 0x03, rest[0], "record version major")
		require.EqualValues(t, 0x03, rest[1], "record version minor")

		length := int(rest[2])<<8 | int(rest[3])
		require.Positive(t, length, "record type %#x must carry a payload", typeByte)
		require.LessOrEqual(t, length, tls.MaxRecordPayloadSize)

		_, err = io.CopyN(io.Discard, r, int64(length))
		require.NoError(t, err, "a record must carry the length it declares")

		return length
	}

	readHeader(firstType)

	for _, wantType := range []byte{0x14, 0x17} {
		var typeByte [1]byte

		_, err := io.ReadFull(r, typeByte[:])
		require.NoError(t, err)
		require.Equal(t, wantType, typeByte[0], "unexpected record type in the server flight")
		readHeader(typeByte[0])
	}

	for got := 0; got < want; {
		var typeByte [1]byte

		_, err := io.ReadFull(r, typeByte[:])
		require.NoError(t, err, "relayed traffic must keep arriving")
		require.EqualValues(t, 0x17, typeByte[0],
			"client-bound traffic must be framed as TLS application data, not raw obfuscated2")

		got += readHeader(typeByte[0])
	}
}
