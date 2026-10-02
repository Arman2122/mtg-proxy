package mtglib

import (
	"context"
	"crypto/rand"
	"io"
	"net"
	"testing"
	"time"

	"github.com/Arman2122/mtg-proxy/mtglib/obfuscation"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newLimitTestProxy(secrets map[string]Secret, limits map[string]SecretLimits) *Proxy {
	p := &Proxy{
		stats:     NewProxyStats(),
		liveConns: make(map[string]map[*streamContext]struct{}),
		logger:    testLogger(),
	}

	set := buildSecretSet(secrets, nil, nil, limits)
	for _, name := range set.names {
		p.stats.PreRegister(name)
	}

	p.secrets.Store(set)

	return p
}

func TestCheckLimits(t *testing.T) {
	t.Parallel()

	p := newLimitTestProxy(map[string]Secret{"alice": GenerateSecret("alice.example.com")}, nil)
	p.stats.users["alice"].quotaUsed.Store(1000)

	past := time.Now().Add(-time.Hour)
	future := time.Now().Add(time.Hour)

	cases := []struct {
		name       string
		lim        SecretLimits
		wantOK     bool
		wantReason DenyReason
	}{
		{"no limits", SecretLimits{}, true, DenyNone},
		{"disabled", SecretLimits{Disabled: true}, false, DenyDisabled},
		{"expired", SecretLimits{ExpiresAt: past}, false, DenyExpired},
		{"not yet expired", SecretLimits{ExpiresAt: future}, true, DenyNone},
		{"under quota", SecretLimits{QuotaBytes: 2000}, true, DenyNone},
		{"at quota", SecretLimits{QuotaBytes: 1000}, false, DenyQuota},
		{"over quota", SecretLimits{QuotaBytes: 500}, false, DenyQuota},
		{"disabled beats quota", SecretLimits{Disabled: true, QuotaBytes: 5000}, false, DenyDisabled},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ok, reason := p.checkLimits("alice", tc.lim)
			assert.Equal(t, tc.wantOK, ok)
			assert.Equal(t, tc.wantReason, reason)
		})
	}
}

func TestCloseDeniedConns(t *testing.T) {
	t.Parallel()

	secrets := map[string]Secret{
		"disabled": GenerateSecret("d.example.com"),
		"expired":  GenerateSecret("e.example.com"),
		"quota":    GenerateSecret("q.example.com"),
		"ok":       GenerateSecret("o.example.com"),
	}
	limits := map[string]SecretLimits{
		"disabled": {Disabled: true},
		"expired":  {ExpiresAt: time.Now().Add(-time.Hour)},
		"quota":    {QuotaBytes: 100},
		"ok":       {QuotaBytes: 1_000_000},
	}

	p := newLimitTestProxy(secrets, limits)
	p.stats.users["quota"].quotaUsed.Store(500) // over quota

	streams := map[string]*streamContext{}
	for name := range secrets {
		streams[name] = registerFakeStream(p, name)
	}

	p.closeDeniedConns()

	assert.ErrorIs(t, streams["disabled"].Err(), context.Canceled, "disabled secret's stream must be closed")
	assert.ErrorIs(t, streams["expired"].Err(), context.Canceled, "expired secret's stream must be closed")
	assert.ErrorIs(t, streams["quota"].Err(), context.Canceled,
		"an exhausted user's stream must be closed: a quota is a ceiling, and an idle stream would otherwise outlive it")
	assert.NoError(t, streams["ok"].Err(), "healthy stream must stay connected")
}

func TestQuotaMonthlyRollover(t *testing.T) {
	t.Parallel()

	stats := NewProxyStats()
	stats.PreRegister("alice")
	stats.users["alice"].quotaUsed.Store(500)

	lastMonth := time.Now().AddDate(0, -1, 0)
	stats.users["alice"].periodStart.Store(lastMonth.UnixNano())

	// A monthly reset zeroes usage when the calendar month has changed.
	used := stats.QuotaUsed("alice", QuotaResetMonthly)
	assert.Equal(t, int64(0), used)

	// A "none" policy never rolls over.
	stats.users["alice"].quotaUsed.Store(500)
	stats.users["alice"].periodStart.Store(lastMonth.UnixNano())
	assert.Equal(t, int64(500), stats.QuotaUsed("alice", QuotaResetNone))
}

func TestQuotaSameMonthNoRollover(t *testing.T) {
	t.Parallel()

	stats := NewProxyStats()
	stats.PreRegister("alice")
	stats.users["alice"].quotaUsed.Store(500)
	stats.users["alice"].periodStart.Store(time.Now().UnixNano())

	assert.Equal(t, int64(500), stats.QuotaUsed("alice", QuotaResetMonthly))
}

func TestResetQuota(t *testing.T) {
	t.Parallel()

	stats := NewProxyStats()
	stats.PreRegister("alice")
	stats.users["alice"].quotaUsed.Store(1234)

	before := time.Now()
	stats.ResetQuota("alice")

	assert.Equal(t, int64(0), stats.users["alice"].quotaUsed.Load())
	assert.GreaterOrEqual(t, stats.users["alice"].periodStart.Load(), before.UnixNano())
}

func TestLoadFlushUsageRoundTrip(t *testing.T) {
	t.Parallel()

	path := t.TempDir() + "/usage.json"
	period := time.Now().Add(-48 * time.Hour).UnixNano()

	src := NewProxyStats()
	src.PreRegister("alice")
	src.users["alice"].quotaUsed.Store(7777)
	src.users["alice"].periodStart.Store(period)

	require.NoError(t, src.FlushUsage(path))

	dst := NewProxyStats()
	require.NoError(t, dst.LoadUsage(path))

	assert.Equal(t, int64(7777), dst.users["alice"].quotaUsed.Load())
	assert.Equal(t, period, dst.users["alice"].periodStart.Load())
}

func TestLoadUsageMissingFileIsOK(t *testing.T) {
	t.Parallel()

	stats := NewProxyStats()
	assert.NoError(t, stats.LoadUsage(t.TempDir()+"/does-not-exist.json"))
}

func TestSwapPreservesUsage(t *testing.T) {
	t.Parallel()

	alice := GenerateSecret("alice.example.com")
	p := newLimitTestProxy(map[string]Secret{"alice": alice}, map[string]SecretLimits{
		"alice": {QuotaBytes: 1000},
	})
	p.stats.users["alice"].quotaUsed.Store(400)

	// Reloading with a larger quota must not wipe the usage counter.
	require.NoError(t, p.ReplaceSecrets(SecretConfig{
		Secrets: map[string]Secret{"alice": alice},
		Limits:  map[string]SecretLimits{"alice": {QuotaBytes: 5000}},
	}))

	assert.Equal(t, int64(400), p.stats.users["alice"].quotaUsed.Load())
	assert.Equal(t, int64(5000), p.secrets.Load().limits[0].QuotaBytes)
}

// govCoverHost is the SNI every ee secret in the governance tests is issued
// for. Sharing one hostname is deliberate: it is what a management panel does,
// and it means the ee door has to pick the right key out of the candidate list
// by HMAC rather than by hostname.
const govCoverHost = "cover.example.com"

// govEntryCase is the {ee, dd} dimension. Phase 1 added a second door where the
// secret is unknown until the frame is trial-decrypted, and every piece of
// per-user governance -- quota, throttling, byte counting, revocation by hot
// reload -- had to move behind that identification. Nothing proves the two
// doors agree unless the SAME assertions run over both, so the governance tests
// in this file, in traffic_gate_test.go and in proxy_reload_test.go are table
// driven over this and share one body each.
//
// Where the doors legitimately differ the difference is a FIELD here, never a
// skipped assertion.
type govEntryCase struct {
	name string

	// mode is the secret form the client presents, which also selects the door:
	// ee arrives on the FakeTLS listener, dd on an obfuscated2 one.
	mode SecretMode

	// policy stamps the accepting socket. nil is an unstamped conn, which is
	// DefaultListenerPolicy -- FakeTLS only.
	policy *ListenerPolicy

	// frontingsOnEntryDeny is how a refusal DURING the entry looks from outside.
	// The FakeTLS door relays the probe on to the cover site so a wrong secret
	// and an over-quota one are indistinguishable; the plaintext door does not
	// speak TLS, so relaying to an HTTPS cover site would pipe a TLS alert out
	// of a plaintext port, and it closes instead.
	frontingsOnEntryDeny int
}

func govEntryCases() []govEntryCase {
	return []govEntryCase{
		{
			name:                 "ee",
			mode:                 SecretModeFakeTLS,
			policy:               nil,
			frontingsOnEntryDeny: 1,
		},
		{
			name:                 "dd",
			mode:                 SecretModeDD,
			policy:               obfuscatedPolicy(ModeSetOf(SecretModeDD), UnknownSecretClose),
			frontingsOnEntryDeny: 0,
		},
		{
			// The third wire form is not a variation on dd. It arrives on a
			// socket that honours the abridged and intermediate transport tags
			// as well as padded-intermediate, and it is the form a WEB relay
			// backend may be configured to accept -- so every governance rule
			// built on top of these cases (quota billing, expiry, disable,
			// revocation, throttling) has to hold on it too, and nothing
			// asserted that until it had a row here.
			name:                 "plain",
			mode:                 SecretModePlain,
			policy:               obfuscatedPolicy(ModeSetOf(SecretModePlain), UnknownSecretClose),
			frontingsOnEntryDeny: 0,
		},
	}
}

// secret mints a secret of this case's wire form.
func (ec govEntryCase) secret(t *testing.T) Secret {
	t.Helper()

	if ec.mode == SecretModeFakeTLS {
		return GenerateSecret(govCoverHost)
	}

	secret, err := GenerateSecretMode(ec.mode, "")
	require.NoError(t, err)

	return secret
}

// harness builds the shared entry harness with the doppelganger running. The ee
// path cannot get past the doppelganger wrap in ServeConn unless it is: NewConn
// is a channel round-trip with that run loop. Running it for dd as well costs
// nothing and keeps the two rows built by identical code.
func (ec govEntryCase) harness(
	t *testing.T, secrets map[string]Secret, limits map[string]SecretLimits,
) *entryHarness {
	t.Helper()

	h := newEntryHarness(t, secrets, limits)

	// The doppelganger paces the ee write path on purpose, drawing a wait
	// before every record from a heavy-tailed model: half a megabyte took 200ms
	// on average and over 500ms in about one run in twenty-five, which is a
	// speed limit nobody set. Like the two timeouts below it is pinned, so that
	// the cap is the only thing that can pace these streams; the records are
	// still framed by the same write loop, only without the wait. Pinned here
	// and not in newEntryHarness: the golden test leaves record segmentation to
	// that race on purpose.
	h.proxy.doppelGanger.Unpace()
	h.proxy.doppelGanger.Run()
	t.Cleanup(h.proxy.doppelGanger.Shutdown)

	// The harness idles a relayed stream out after a second. Every "was it
	// refused or was it relayed" bound below would then read green for the wrong
	// reason: a stream that a removed governance check wrongly admitted carries
	// no traffic in these tests, so it would die of idleness well inside the
	// budget and look exactly like a refusal. Governance has to be the only
	// thing that can end these streams.
	h.proxy.idleTimeout = time.Minute

	// Pinned here rather than inherited, for the same reason. On the ee door a
	// wrongly admitted stream then blocks waiting for an obfuscated frame that
	// never comes, and it is this deadline -- not any governance check -- that
	// eventually ends it. It has to stay well above govDenyBudget or the bound
	// below stops discriminating on that row.
	h.proxy.handshakeTimeout = 3 * govDenyBudget

	return h
}

// openEntry writes the first flight this door expects: a forged ClientHello on
// ee, the 64-byte obfuscated2 frame on dd. It is everything the proxy needs to
// attribute the stream and run the per-user limit check, on either path.
func (ec govEntryCase) openEntry(t *testing.T, client net.Conn, key [SecretKeyLength]byte) {
	t.Helper()

	var flight []byte

	if ec.mode == SecretModeFakeTLS {
		// A fresh session id per connection: the anti-replay cache is a
		// deterministic TestAndAdd in these tests, so a fixed id would make the
		// second connection of any test a replay.
		sessionID := make([]byte, 32)

		_, err := rand.Read(sessionID)
		require.NoError(t, err)

		flight = fakeTLSClientHello(t, key, govCoverHost, sessionID)
	} else {
		flight = obfuscatedFrame(t, key, obfuscation.TagPaddedIntermediate, 2)
	}

	_, err := client.Write(flight)
	require.NoError(t, err)
}

// framePayload wraps post-handshake client traffic the way this door carries
// it. After SendServerHello the ee entry reads through the faketls record
// layer; the plaintext door reads the bytes as they are.
func (ec govEntryCase) framePayload(payload []byte) []byte {
	if ec.mode == SecretModeFakeTLS {
		return tlsApplicationRecord(payload)
	}

	return payload
}

// govStream is one client carried all the way into the relay.
type govStream struct {
	client   net.Conn
	upstream net.Conn
	ctx      *streamContext
	done     <-chan struct{}
}

// connect drives one client through this case's door and out the other side:
// entry handshake, attribution, admission, the obfuscated handshake and the
// Telegram dial. It returns with the stream registered and relaying, which is
// the state every governance assertion is about.
//
// It must be called one client at a time: the harness has a single upstream
// listener, so a second concurrent dial could be accepted here.
func (ec govEntryCase) connect(
	t *testing.T, h *entryHarness, name string, key [SecretKeyLength]byte,
) *govStream {
	t.Helper()

	client, done := h.dialProxy(t, ec.policy)

	ec.openEntry(t, client, key)

	if ec.mode == SecretModeFakeTLS {
		// Wait for the server flight before the obfuscated frame goes out, as a
		// real client does. The ee entry reads the ClientHello through a rewind
		// buffer that is dropped on success, so a frame landing in the same read
		// would be swallowed.
		require.NoError(t, client.SetReadDeadline(time.Now().Add(5*time.Second)))

		var first [1]byte

		_, err := io.ReadFull(client, first[:])
		require.NoError(t, err, "the ee entry must answer a valid ClientHello")
		require.EqualValues(t, 0x16, first[0], "the flight must open with a handshake record")

		_, err = client.Write(ec.framePayload(
			obfuscatedFrame(t, key, obfuscation.TagPaddedIntermediate, 2),
		))
		require.NoError(t, err)
	}

	upstream, err := h.upstream.Accept()
	require.NoError(t, err, "an admitted stream must dial Telegram")

	t.Cleanup(func() { upstream.Close() }) //nolint: errcheck

	require.NoError(t, upstream.SetReadDeadline(time.Now().Add(5*time.Second)))

	var handshake [64]byte

	_, err = io.ReadFull(upstream, handshake[:])
	require.NoError(t, err)

	stream := h.liveStream(t, name)
	require.NotNil(t, stream, "the stream must be registered under the matched secret name")

	return &govStream{client: client, upstream: upstream, ctx: stream, done: done}
}

// close ends the stream from both sides and waits for ServeConn to return.
// Closing only the client end leaves the Telegram direction of the relay
// waiting on the idle tracker, which these tests deliberately set long.
func (s *govStream) close() {
	s.client.Close()   //nolint: errcheck
	s.upstream.Close() //nolint: errcheck
	<-s.done
}

// govAwait waits for ServeConn to return, bounded.
//
// The bound is the load-bearing part of every deny assertion: when a governance
// check is removed the connection is not refused but RELAYED, and a relayed
// stream never returns on its own. On the ee door the refusal would instead
// surface only when the handshake deadline expires -- and by then release() has
// already undone the accounting, so every post-hoc counter reads green. The
// clock is what tells "refused" from "admitted" on both rows.
func govAwait(done <-chan struct{}, within time.Duration) bool {
	timer := time.NewTimer(within)
	defer timer.Stop()

	select {
	case <-done:
		return true
	case <-timer.C:
		return false
	}
}

// govDenyBudget is comfortably below the harness handshake timeout of 5s, so an
// ee stream that was wrongly admitted is still blocked waiting for its
// obfuscated frame when this expires.
const govDenyBudget = 2 * time.Second

// TestGovernanceLimitDenialAcrossEntries runs the per-user limit check over
// both doors. checkLimits is reached from attribute(), which Phase 1 moved
// behind identification so that the dd path -- where the secret is unknown
// until the frame is decrypted -- enforces the same limits at the same point as
// the ee path.
//
// Two users are configured, and the limited one is deliberately NOT the
// alphabetically first. attribute() indexes limits by the same i it uses for
// names, and that slice is sorted, so a check that read a fixed index would
// hand bob alice's empty entry -- silently disarming disable, expiry and quota
// for everybody except the first user. One secret cannot see that at all.
func TestGovernanceLimitDenialAcrossEntries(t *testing.T) {
	t.Parallel()

	// bobUsed and aliceUsed are separate because the two index bugs they catch
	// pull in opposite directions. Reading limits at the LAST index only shows
	// up on the quota row when alice is also over the ceiling; metering the
	// quota against the FIRST-sorted name only shows up when she is not. One
	// row cannot be both, so there are two quota rows.
	limitCases := []struct {
		name      string
		limits    SecretLimits
		bobUsed   int64
		aliceUsed int64
	}{
		{"over quota", SecretLimits{QuotaBytes: 100}, 500, 500},
		{"over quota, first user clean", SecretLimits{QuotaBytes: 100}, 500, 0},
		{"disabled", SecretLimits{Disabled: true}, 0, 0},
		{"expired", SecretLimits{ExpiresAt: time.Now().Add(-time.Hour)}, 0, 0},
	}

	for _, ec := range govEntryCases() {
		for _, lc := range limitCases {
			t.Run(ec.name+"/"+lc.name, func(t *testing.T) {
				t.Parallel()

				alice := ec.secret(t)
				bob := ec.secret(t)

				// alice sorts first and carries no limits at all; bob is the one
				// under test.
				h := ec.harness(t,
					map[string]Secret{"alice": alice, "bob": bob},
					map[string]SecretLimits{"bob": lc.limits})
				h.proxy.stats.users["bob"].quotaUsed.Store(lc.bobUsed)

				// alice's usage is inert for her -- she has no quota configured --
				// but it decides which index bug the row can see. See the table.
				h.proxy.stats.users["alice"].quotaUsed.Store(lc.aliceUsed)

				client, done := h.dialProxy(t, ec.policy)
				ec.openEntry(t, client, bob.Key)

				// Catches the limit check being dropped from attribute(), and
				// equally the limits being read at a fixed index: without either,
				// bob is admitted and relayed, and a relayed stream never ends by
				// itself on either door.
				require.True(t, govAwait(done, govDenyBudget),
					"a denied user's connection must be disposed of, not relayed")

				// The doors dispose of an entry-time refusal differently, and that
				// is a per-mode expectation rather than a skipped assertion: the ee
				// door must keep fronting so a denied user is indistinguishable
				// from a wrong secret, and the plaintext door must never front.
				assert.Equal(t, ec.frontingsOnEntryDeny, h.events.frontings())
				assert.Equal(t, ec.frontingsOnEntryDeny, h.network.frontingDials())

				// The other half of the index check. Denying everyone is not a
				// correct answer either, and a lookup that fetched bob's entry for
				// every user would pass the bound above while shutting the proxy
				// down for its unlimited users. Reaching the relay is the proof:
				// connect only returns once the stream is registered and dialled.
				ec.connect(t, h, "alice", alice.Key).close()
			})
		}
	}
}

// TestGovernanceThrottleAcrossEntries runs the connection throttle over both
// doors. It lives in admit(), after attribution, so on the dd path it is the
// first thing that can be keyed on a real name at all.
func TestGovernanceThrottleAcrossEntries(t *testing.T) {
	t.Parallel()

	for _, ec := range govEntryCases() {
		t.Run(ec.name, func(t *testing.T) {
			t.Parallel()

			secret := ec.secret(t)
			h := ec.harness(t, map[string]Secret{"alice": secret}, nil)

			// A cap of zero: the secret is valid and within its limits, and
			// admission refuses it anyway.
			h.proxy.stats.SetThrottle(1, time.Hour)
			h.proxy.stats.throttleMu.Lock()
			h.proxy.stats.throttleCaps["alice"] = 0
			h.proxy.stats.throttleMu.Unlock()

			client, done := h.dialProxy(t, ec.policy)
			ec.openEntry(t, client, secret.Key)

			// Catches the CanConnect check being dropped from admit(): the stream
			// would be admitted and relayed instead of refused.
			require.True(t, govAwait(done, govDenyBudget),
				"a throttled connection must be refused, not relayed")

			// Catches the refusal happening silently, and catches it being billed
			// to the wrong name: the throttle event is the only signal an operator
			// has that a user is hitting its cap, and it has to carry the name the
			// door matched.
			throttled := h.events.count(func(evt Event) bool {
				thr, ok := evt.(EventThrottled)

				return ok && thr.SecretName == "alice"
			})
			assert.Equal(t, 1, throttled, "the throttle refusal must name the matched secret")

			// A refusal must leave the counter exactly where it found it. The
			// two ways to get this wrong are both self-amplifying and neither is
			// visible anywhere else: crediting OnConnect before the gate locks
			// the user out permanently once they reach the cap, and releasing on
			// the deny path drives the count negative, which reads as "under the
			// cap" forever and silently disables the throttle for good.
			assert.Equal(t, int64(0), h.proxy.stats.users["alice"].connections.Load(),
				"a throttled refusal must not move the connection count")
		})
	}
}

// TestGovernanceQuotaResetPolicyAcrossEntries pins that the admission gate
// meters usage under the secret's OWN reset policy. checkLimits reads the live
// counter through QuotaUsed(name, lim.QuotaReset), and that second argument is
// the only thing that rolls a monthly period over at the moment a client asks
// to be let in.
//
// Hardcode it to QuotaResetNone and a monthly user whose usage predates the
// boundary is refused at the start of the new period -- for up to
// usageFlushInterval, until the persistence loop's rolloverAllQuotas catches up.
// Hardcode it the other way and a lifetime quota silently replenishes every
// month. Neither is visible from a table of limits alone: it takes a stale
// period start and a real connection attempt, which is what the two rows below
// are.
func TestGovernanceQuotaResetPolicyAcrossEntries(t *testing.T) {
	t.Parallel()

	policyCases := []struct {
		name         string
		reset        QuotaReset
		wantAdmitted bool
	}{
		{"monthly rolls the stale period over", QuotaResetMonthly, true},
		{"none keeps a lifetime allowance spent", QuotaResetNone, false},
	}

	for _, ec := range govEntryCases() {
		for _, pc := range policyCases {
			t.Run(ec.name+"/"+pc.name, func(t *testing.T) {
				t.Parallel()

				secret := ec.secret(t)
				h := ec.harness(t,
					map[string]Secret{"alice": secret},
					map[string]SecretLimits{"alice": {QuotaBytes: 100, QuotaReset: pc.reset}})

				h.proxy.stats.mu.RLock()
				aliceStats := h.proxy.stats.users["alice"]
				h.proxy.stats.mu.RUnlock()

				// Spent, and spent in the PREVIOUS calendar month. Anchored to the
				// first of this month rather than now.AddDate(0, -1, 0), which
				// normalises the 31st back into the same month and would leave the
				// row green for the wrong reason a few days a year.
				now := time.Now()
				firstOfMonth := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.Local)

				aliceStats.quotaUsed.Store(500)
				aliceStats.periodStart.Store(firstOfMonth.AddDate(0, 0, -1).UnixNano())

				if !pc.wantAdmitted {
					client, done := h.dialProxy(t, ec.policy)
					ec.openEntry(t, client, secret.Key)

					require.True(t, govAwait(done, govDenyBudget),
						"a spent lifetime quota must still deny, however old the usage is")

					return
				}

				// connect only returns once the stream is registered and dialled,
				// so reaching it IS the admission. A dropped reset policy denies
				// instead, and the stream never gets as far as the upstream accept.
				stream := ec.connect(t, h, "alice", secret.Key)
				defer stream.close()

				// And the admission came from a real rollover, not from a ceiling
				// that was never consulted: the new period starts from zero.
				assert.Zero(t, aliceStats.quotaUsed.Load(),
					"the new quota period must start with the counter cleared")
			})
		}
	}
}

// TestGovernanceCountsConnectionsAcrossEntries runs the per-user connection
// accounting over both doors. admit() keys OnConnect, UpdateLastSeen and the
// live-connection registry on the name the door matched, and release() undoes
// the first two on the way out.
//
// The counter is what the fair-share throttle divides its budget by and what
// /stats reports as a live gauge, so a stream billed to the "" bucket or to the
// wrong user is a throttle that protects nobody and a panel that shows an idle
// proxy under load. A second configured user is present and must stay at zero:
// "somebody was counted" is not the property, "the matched user and only the
// matched user" is.
func TestGovernanceCountsConnectionsAcrossEntries(t *testing.T) {
	t.Parallel()

	for _, ec := range govEntryCases() {
		t.Run(ec.name, func(t *testing.T) {
			t.Parallel()

			target := ec.secret(t)
			other := ec.secret(t)

			h := ec.harness(t, map[string]Secret{"alice": target, "bob": other}, nil)

			// Resolved before the stream runs: accounting billed to a name that has
			// no entry yet writes the users map, and an unlocked read here would
			// surface as a data race instead of the assertion going red.
			h.proxy.stats.mu.RLock()
			aliceStats := h.proxy.stats.users["alice"]
			bobStats := h.proxy.stats.users["bob"]
			h.proxy.stats.mu.RUnlock()

			stream := ec.connect(t, h, "alice", target.Key)

			assert.Equal(t, int64(1), aliceStats.connections.Load(),
				"an admitted stream must be counted against the user this door matched")
			assert.Equal(t, int64(0), bobStats.connections.Load(),
				"and against no other configured user")

			lastSeen, ok := aliceStats.lastSeen.Load().(time.Time)
			require.True(t, ok)
			assert.False(t, lastSeen.IsZero(),
				"admission must stamp the matched user as seen, not some other bucket")

			h.proxy.stats.mu.RLock()
			_, unnamed := h.proxy.stats.users[""]
			h.proxy.stats.mu.RUnlock()
			assert.False(t, unnamed, "no accounting may land in the empty-name bucket")

			// close waits for ServeConn to return, so the deferred release has run
			// by the time these read.
			stream.close()

			assert.Equal(t, int64(0), aliceStats.connections.Load(),
				"release must give the connection back, or every stream leaks a count")

			h.proxy.liveMu.Lock()
			assert.Empty(t, h.proxy.liveConns["alice"],
				"and must unregister the stream, or hot-reload revocation chases dead streams")
			h.proxy.liveMu.Unlock()
		})
	}
}
