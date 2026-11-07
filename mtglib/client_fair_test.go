package mtglib

import (
	"context"
	"encoding/json"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/time/rate"
)

// client-fair, the work-conserving share, as the proxy runs it: fair share's
// ticker (fair_share.go decides, the proxy drives it once a second under its
// own context), and the reload that puts a fair limiter on, or takes it off,
// every entry a secret has -- the rest entry and the idle ones included -- so
// that a change reaches the streams already open. And the switch itself, as
// the API carries it and the secret set holds it. How it times out against the
// wall clock through the door is fair_share_e2e_test.go.

// countFairPasses has the proxy's fair-share ticker report each pass it
// finishes. It must be called before the ticker starts: the hook is read
// without a lock.
func countFairPasses(p *Proxy) <-chan struct{} {
	passes := make(chan struct{}, 1)

	p.afterFairPass = func() {
		select {
		case passes <- struct{}{}:
		default:
		}
	}

	return passes
}

// fairLastTick is when the table's last tick of name measured, zero for none,
// read under the table's lock.
func fairLastTick(table *clientTable, name string) time.Time {
	table.mu.Lock()
	defer table.mu.Unlock()

	if sc := table.secrets[name]; sc != nil {
		return sc.fair.lastTick
	}

	return time.Time{}
}

// awaitFairPass waits for the next pass the ticker reports, bounded.
func awaitFairPass(passes <-chan struct{}, within time.Duration) bool {
	timer := time.NewTimer(within)
	defer timer.Stop()

	select {
	case <-passes:
		return true
	case <-timer.C:
		return false
	}
}

// The ticker is part of the maintenance loop: whatever starts that -- NewProxy,
// under the proxy's own context -- starts fair share's ticker with it, at its
// one-second period.
func TestTheFairShareTickerRunsWithTheMaintenanceLoop(t *testing.T) {
	t.Parallel()

	probe := newClientTableProbe(t, false)
	passes := countFairPasses(probe.proxy)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	probe.proxy.startMaintenanceEvery(ctx, time.Hour, time.Hour, time.Hour)

	assert.True(t, awaitFairPass(passes, 3*fairTickInterval), "the maintenance loop starts fair share's ticker")
}

// The ticker runs at the period it is given and stops with the context it runs
// under, and the proxy can wait for it: once its goroutine has returned,
// nothing ticks any more.
func TestTheFairShareTickerStopsWithItsContext(t *testing.T) {
	t.Parallel()

	probe := newClientTableProbe(t, false)
	p := probe.proxy
	passes := countFairPasses(p)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	p.startFairShare(ctx, 5*time.Millisecond)

	// Three passes of a 5 ms ticker take 15 ms; one of fairTickInterval
	// takes a second.
	deadline := time.Now().Add(500 * time.Millisecond)

	for i := range 3 {
		require.True(t, awaitFairPass(passes, time.Until(deadline)),
			"pass %d within 500 ms: the ticker runs at the period it is given", i+1)
	}

	cancel()

	stopped := make(chan struct{})

	go func() {
		defer close(stopped)

		p.fairWaitGroup.Wait()
	}()

	require.True(t, govAwait(stopped, 2*time.Second), "the ticker's goroutine returns once its context ends")

	// A pass that was already under way when the context ended has reported
	// by now; nothing after it may.
	select {
	case <-passes:
	default:
	}

	assert.False(t, awaitFairPass(passes, 100*time.Millisecond), "and it passes no more")
}

// Task 7's C1, for fair share: a reload that takes away the last per-address
// control leaves a set that wants no entries, and the backfill skips its walk.
// The entries made while the control was there are still held -- a stream, an
// idle address within retention, the rest entry -- and their fair limiters
// must come off all the same, in the walk over the entries that exist, not in
// the backfill that returns early.
func TestAReloadThatWantsNoEntriesTakesEveryFairShareOff(t *testing.T) {
	t.Parallel()

	probe := newClientTableProbe(t, false)
	p := probe.proxy

	reload := func(limits map[string]SecretLimits) {
		t.Helper()

		cfg := p.secrets.Load().toConfig()
		cfg.Limits = limits

		require.NoError(t, p.ReplaceSecrets(cfg))
	}

	reload(map[string]SecretLimits{"alice": {ClientConns: 8}})

	live := admitFrom(t, probe, tcpFrom("203.0.113.61", 50001))
	idle := admitFrom(t, probe, tcpFrom("203.0.113.62", 50002))
	local := admitFrom(t, probe, tcpFrom("127.0.0.1", 50003))

	idleEntry := idle.addrEntry.Load()
	require.NotNil(t, idleEntry)
	p.unregisterConn(idle)
	require.Equal(t, 0, clientRefs(p.clients, idleEntry), "an entry no stream holds")

	rest := local.addrEntry.Load()
	require.NotNil(t, rest)
	require.True(t, rest.rest)

	// Shares as a fair secret's entries carry them, on each of the three.
	for _, entry := range []*clientEntry{live.addrEntry.Load(), idleEntry, rest} {
		for b := range fairBucketCount {
			entry.fairLimiter(b).install(fairTestTotal, fairBurst(fairTestTotal))
		}
	}

	reload(nil)

	require.False(t, p.clientEntriesWantedBy(p.secrets.Load()),
		"nothing asks for entries any more: the backfill has no walk to do")
	assert.True(t, assertFairInvariant(t, p.clients, "alice", fairTotals{}),
		"every fair limiter is off, on the held, the idle and the rest entry alike")
	assert.Same(t, rest, local.addrEntry.Load(), "the streams keep their entries")
}

// NewProxy starts the ticker and Shutdown stops it: a fair secret is ticked on
// the clock from the moment the proxy is built, Shutdown returns only once the
// ticker has stopped, and nothing ticks after it.
func TestShutdownStopsTheFairShareTicker(t *testing.T) {
	t.Parallel()

	lim := SecretLimits{SpeedDownBytesPerSecond: 1 << 20, ClientFair: true}

	opts, _ := servingOpts(t)
	opts.SecretLimits = map[string]SecretLimits{"alice": lim}

	proxy, err := NewProxy(opts)
	require.NoError(t, err)

	// The cleanup shuts the proxy down only if the test never began to. A
	// Shutdown that hangs must fail the test by name below, not hang the
	// whole package in a cleanup waiting behind it.
	var shuttingDown atomic.Bool

	t.Cleanup(func() {
		if !shuttingDown.Load() {
			proxy.Shutdown()
		}
	})

	require.NotNil(t, proxy.clients.acquire("alice", "203.0.113.9", true, entryInitOf(lim)))

	require.Eventually(t, func() bool { return !fairLastTick(proxy.clients, "alice").IsZero() },
		5*fairTickInterval, 10*time.Millisecond, "the proxy ticks its fair secret on the clock")

	stopped := make(chan struct{})

	shuttingDown.Store(true)

	go func() {
		defer close(stopped)

		proxy.Shutdown()
	}()

	require.True(t, govAwait(stopped, 10*time.Second), "Shutdown returns once the ticker has stopped")

	last := fairLastTick(proxy.clients, "alice")

	time.Sleep(fairTickInterval * 5 / 2)
	assert.Equal(t, last, fairLastTick(proxy.clients, "alice"), "and nothing ticks after it")
}

// A pass ticks every secret whose client-fair divides a speed -- the second
// such secret in name order as well as the first -- and no other: not one
// with speeds and fair share off, which its own bucket holds and nothing
// divides, and not one switched on with no speed to divide. Each is ticked at
// the table's clock, the one the data path stamps the blocked trackers by, not
// the wall clock.
func TestTheFairShareTickerTicksTheFairSecretsAtTheTablesClock(t *testing.T) {
	t.Parallel()

	clock := newFakeAddrClock()
	probe := newClientTableProbe(t, false)
	p := probe.proxy
	p.clients = newClientTable(clock.clock())

	limits := map[string]SecretLimits{
		"alice": {SpeedDownBytesPerSecond: fairTestTotal, ClientFair: true},
		"bob":   {SpeedBytesPerSecond: fairTestTotal, SpeedDownBytesPerSecond: fairTestTotal},
		"carol": {ClientFair: true},
		"dave":  {SpeedUpBytesPerSecond: fairTestTotal, ClientFair: true},
	}

	p.secrets.Store(buildSecretSet(map[string]Secret{
		"alice": GenerateSecret("alice.example.com"),
		"bob":   GenerateSecret("bob.example.com"),
		"carol": GenerateSecret("carol.example.com"),
		"dave":  GenerateSecret("dave.example.com"),
	}, nil, nil, limits))

	for name, lim := range limits {
		require.NotNil(t, p.clients.acquire(name, "203.0.113.9", true, entryInitOf(lim)))
	}

	p.tickFairShare()
	assert.Equal(t, clock.read(), fairLastTick(p.clients, "alice"), "a fair secret is ticked, at the table's clock")
	assert.Equal(t, clock.read(), fairLastTick(p.clients, "dave"), "and so is every other one")

	clock.advance(fairTickInterval)
	p.tickFairShare()
	assert.Equal(t, clock.read(), fairLastTick(p.clients, "alice"))
	assert.Equal(t, clock.read(), fairLastTick(p.clients, "dave"))

	assert.True(t, fairLastTick(p.clients, "bob").IsZero(), "a secret whose fair share is off is not ticked")
	assert.True(t, fairLastTick(p.clients, "carol").IsZero(), "nor one with no speed to divide")
}

// client-fair is a per-address control: it asks for entries on its own, with
// tracking off, as the other two do -- the switch alone, too, though the config
// and the API refuse it without a speed -- and a new entry of a fair secret
// starts from the secret's speeds as its totals, each divided on its own. The
// speeds without the switch are limits on the secret as a whole, and the
// per-address ceiling is no total.
func TestClientFairIsAPerAddressControl(t *testing.T) {
	t.Parallel()

	fair := SecretLimits{
		SpeedBytesPerSecond:     3 << 20,
		SpeedUpBytesPerSecond:   1 << 20,
		SpeedDownBytesPerSecond: 2 << 20,
		ClientFair:              true,
	}

	off := fair
	off.ClientFair = false

	assert.True(t, fair.hasClientControl())
	assert.True(t, SecretLimits{ClientFair: true}.hasClientControl(), "the switch alone asks for entries")
	assert.False(t, off.hasClientControl(), "the speeds alone are limits on the secret as a whole")

	assert.Equal(t, fairTotals{Speed: 3 << 20, Up: 1 << 20, Down: 2 << 20}, entryInitOf(fair).FairTotals,
		"each speed is a total of its own")
	assert.Zero(t, entryInitOf(off).FairTotals, "off: nothing is divided")

	ceiling := entryInitOf(SecretLimits{
		SpeedDownBytesPerSecond: 2 << 20, ClientSpeedBytesPerSecond: 1 << 20, ClientFair: true,
	})
	assert.Equal(t, fairTotals{Down: 2 << 20}, ceiling.FairTotals, "the ceiling is no total")
	assert.EqualValues(t, 1<<20, ceiling.CeilingRate)

	secrets := map[string]Secret{
		"alice": GenerateSecret("alice.example.com"),
		"bob":   GenerateSecret("bob.example.com"),
		"carol": GenerateSecret("carol.example.com"),
	}
	untracked := &Proxy{}

	for _, limits := range []map[string]SecretLimits{
		{"alice": fair, "bob": {IPLimit: 2}},
		{"alice": {IPLimit: 2}, "bob": off, "carol": fair},
	} {
		set := buildSecretSet(secrets, nil, nil, limits)

		assert.True(t, set.anyClientControl(), "a fair secret anywhere in the set is a per-address control")
		assert.True(t, untracked.clientEntriesWantedBy(set), "and the set wants entries with tracking off")
	}

	assert.False(t, buildSecretSet(secrets, nil, nil, map[string]SecretLimits{"alice": off}).anyClientControl())
}

// fairDownLimiters is each of the named secret's entries' speed-down fair
// limiter object, by address, "" for the rest entry, nil for none.
func fairDownLimiters(table *clientTable, name string) map[addressKey]*rate.Limiter {
	out := map[addressKey]*rate.Limiter{}

	for _, entry := range table.snapshot(name) {
		out[entry.key] = entry.fairDown.limiter.Load()
	}

	return out
}

// requireSameLimiters requires two readings of fairDownLimiters to hold the
// same objects, address by address: the same buckets, not equal ones.
func requireSameLimiters(t *testing.T, want, got map[addressKey]*rate.Limiter, what string) {
	t.Helper()

	require.Len(t, got, len(want), what)

	for key, limiter := range want {
		require.Same(t, limiter, got[key], "%s: %q", what, key)
	}
}

// Review Focus 4 for fair share, through the real door: a reload that turns
// client-fair on, changes what it divides, or turns it off reaches the streams
// open before it -- a keyed stream on its own entry, a loopback stream on the
// secret's rest entry -- and an address that left within the retention
// window, whose entry no stream holds. After every reload each fair limiter is
// installed on each of those entries exactly when its total is set, with that
// total's burst. A total changed within its burst's band re-rates the same
// bucket; one changed past it gets a new one. Turning fair share off, when it
// was the secret's only per-address control, leaves a set that wants no
// entries, and the shares come off all the same. A re-key keeps the entries and
// their shares; a removal drops them.
func TestAReloadMovesTheFairShareOfStreamsAlreadyOpen(t *testing.T) {
	t.Parallel()

	const (
		down   = 1_000_000 // a burst of the 64 KiB floor
		within = 1_200_000 // the same burst
		beyond = 8_000_000 // another one
		up     = 500_000
	)

	require.Equal(t, fairBurst(down), fairBurst(within))
	require.NotEqual(t, fairBurst(down), fairBurst(beyond))

	ec := govEntryCases()[1]
	secret := ec.secret(t)
	h := ec.harness(t, map[string]Secret{"alice": secret}, map[string]SecretLimits{
		"alice": {SpeedDownBytesPerSecond: down},
	})
	table := h.proxy.clients

	require.False(t, h.proxy.trackClientIPs)

	reload := func(step string, key Secret, lim SecretLimits, want fairTotals) {
		t.Helper()

		require.NoError(t, h.proxy.ReplaceSecrets(SecretConfig{
			Secrets: map[string]Secret{"alice": key},
			Limits:  map[string]SecretLimits{"alice": lim},
		}), step)
		require.True(t, assertFairInvariant(t, table, "alice", want), step)
	}

	keyed := openCeilingStream(t, ec, h, secret.Key, tcpFrom("203.0.113.51", 50001))
	local := openCeilingStream(t, ec, h, secret.Key, nil)

	require.Nil(t, table.snapshot("alice"), "creation: fair share off, nothing asks for an entry")

	reload("fair share on", secret, SecretLimits{SpeedDownBytesPerSecond: down, ClientFair: true}, fairTotals{Down: down})

	own, rest := keyed.ctx.addrEntry.Load(), local.ctx.addrEntry.Load()
	require.NotNil(t, own, "an open keyed stream is given its own entry")
	require.False(t, own.rest)
	require.NotNil(t, rest, "an open loopback stream joins the rest entry")
	require.True(t, rest.rest)

	// An address that comes and goes within the retention window.
	gone := openCeilingStream(t, ec, h, secret.Key, tcpFrom("198.51.100.52", 50002))
	idle := gone.ctx.addrEntry.Load()
	require.NotNil(t, idle)
	endStream(gone.client, gone.upstream, gone.done)
	require.Equal(t, 0, clientRefs(table, idle), "an entry no stream holds")
	require.Len(t, table.snapshot("alice"), 3)
	require.True(t, assertFairInvariant(t, table, "alice", fairTotals{Down: down}), "an entry made after")

	shares := fairDownLimiters(table, "alice")

	reload("speed-up added", secret, SecretLimits{
		SpeedUpBytesPerSecond: up, SpeedDownBytesPerSecond: down, ClientFair: true,
	}, fairTotals{Up: up, Down: down})
	requireSameLimiters(t, shares, fairDownLimiters(table, "alice"), "speed-down's shares are kept")

	reload("speed-down raised within its burst", secret, SecretLimits{
		SpeedUpBytesPerSecond: up, SpeedDownBytesPerSecond: within, ClientFair: true,
	}, fairTotals{Up: up, Down: within})
	requireSameLimiters(t, shares, fairDownLimiters(table, "alice"), "re-rated in place")

	for key, limiter := range shares {
		assert.InDelta(t, float64(within), float64(limiter.Limit()), 0, "%q runs at the new total until a tick", key)
	}

	reload("speed-down raised past its burst", secret, SecretLimits{
		SpeedUpBytesPerSecond: up, SpeedDownBytesPerSecond: beyond, ClientFair: true,
	}, fairTotals{Up: up, Down: beyond})

	for key, limiter := range fairDownLimiters(table, "alice") {
		assert.NotSame(t, shares[key], limiter, "%q: a new bucket for a new burst", key)
	}

	reload("speed-up removed", secret, SecretLimits{SpeedDownBytesPerSecond: beyond, ClientFair: true},
		fairTotals{Down: beyond})

	reload("fair share off", secret, SecretLimits{SpeedDownBytesPerSecond: beyond}, fairTotals{})
	require.False(t, h.proxy.clientEntriesWantedBy(h.proxy.secrets.Load()),
		"it was the only per-address control: nothing asks for entries any more")
	assert.Same(t, own, keyed.ctx.addrEntry.Load(), "the open streams keep their entries")
	assert.Same(t, rest, local.ctx.addrEntry.Load())

	reload("fair share on again", secret, SecretLimits{SpeedDownBytesPerSecond: beyond, ClientFair: true},
		fairTotals{Down: beyond})
	assert.Same(t, own, keyed.ctx.addrEntry.Load(), "on the entries they had")

	shares = fairDownLimiters(table, "alice")

	reload("re-keyed", ec.secret(t), SecretLimits{SpeedDownBytesPerSecond: beyond, ClientFair: true},
		fairTotals{Down: beyond})
	require.True(t, govAwait(keyed.done, govDenyBudget), "a re-key closes the streams of the old key")
	require.True(t, govAwait(local.done, govDenyBudget))
	requireSameLimiters(t, shares, fairDownLimiters(table, "alice"), "and keeps the entries and their shares")
	require.True(t, assertFairInvariant(t, table, "alice", fairTotals{Down: beyond}), "once the streams are gone")

	require.NoError(t, h.proxy.ReplaceSecrets(SecretConfig{Secrets: map[string]Secret{"bob": ec.secret(t)}}))
	assert.Nil(t, table.snapshot("alice"), "removed: its entries go with it")
}

// The switch travels the API as client_fair: PUT sets it and answers 200, it
// reads back as client_fair on GET /secrets/{name} and inside the user object
// on /stats -- never a key under users -- a POST that sends it keeps it and
// one that does not clears it, and a mutation of another secret leaves it
// alone. It divides the secret's speed, so a request that turns it on with no
// speed, speed_up or speed_down beside it is a 400 that names it, on PUT and
// on POST, and so is one with only the per-address ceiling; a refused request
// leaves the running share as it was.
func TestClientFairThroughTheAPI(t *testing.T) {
	t.Parallel()

	alice := GenerateSecret("alice.example.com")
	bob := GenerateSecret("bob.example.com")
	p := newAPITestProxy(map[string]Secret{"alice": alice})

	userOf := func(t *testing.T) map[string]any {
		t.Helper()

		raw := statsRaw(t, doAPI(t, p, "", http.MethodGet, "/stats", "").Body.Bytes())

		users, ok := raw["users"].(map[string]any)
		require.True(t, ok)

		for name := range users {
			assert.Contains(t, []string{"alice", "bob"}, name, "nothing new is a key under users")
		}

		user, ok := users["alice"].(map[string]any)
		require.True(t, ok)

		return user
	}

	secretOf := func(t *testing.T) map[string]any {
		t.Helper()

		out := map[string]any{}
		require.NoError(t, json.Unmarshal(doAPI(t, p, "", http.MethodGet, "/secrets/alice", "").Body.Bytes(), &out))

		return out
	}

	fairOn := func() bool {
		lim, _ := p.secrets.Load().limitsOf("alice")

		return lim.ClientFair
	}

	assert.NotContains(t, userOf(t), "client_fair", "absent while off")
	assert.NotContains(t, secretOf(t), "client_fair")

	rec := doAPI(t, p, "", http.MethodPut, "/secrets",
		`{"secrets":{"alice":{"secret":"`+alice.Hex()+`","speed_down":"8mbit","client_fair":true}}}`)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.JSONEq(t, `{"status":"ok"}`, rec.Body.String())

	assert.True(t, fairOn())
	assert.Equal(t, true, secretOf(t)["client_fair"])
	assert.Equal(t, true, userOf(t)["client_fair"])

	for name, request := range map[string]struct{ method, body string }{
		"PUT without a speed": {
			http.MethodPut,
			`{"secrets":{"alice":{"secret":"` + alice.Hex() + `","client_fair":true}}}`,
		},
		"PUT with only the ceiling": {
			http.MethodPut,
			`{"secrets":{"alice":{"secret":"` + alice.Hex() + `","client_fair":true,"client_speed":"1mbit"}}}`,
		},
		"POST without a speed": {
			http.MethodPost,
			`{"name":"alice","secret":"` + alice.Hex() + `","client_fair":true,"quota":"1GB"}`,
		},
	} {
		rec := doAPI(t, p, "", request.method, "/secrets", request.body)
		assert.Equal(t, http.StatusBadRequest, rec.Code, name)
		assert.Contains(t, rec.Body.String(), "client_fair", "%s: the refusal names the field", name)
		assert.True(t, fairOn(), "%s: a refused request leaves the running share alone", name)
	}

	rec = doAPI(t, p, "", http.MethodPost, "/secrets",
		`{"name":"alice","secret":"`+alice.Hex()+`","speed":"8mbit","client_fair":"yes"}`)
	assert.Equal(t, http.StatusBadRequest, rec.Code, "not a boolean")
	assert.True(t, fairOn())

	// Another secret's mutation starts from a copy of the set, which keeps it.
	require.Equal(t, http.StatusOK, doAPI(t, p, "", http.MethodPost, "/secrets",
		`{"name":"bob","secret":"`+bob.Hex()+`"}`).Code)
	assert.Equal(t, true, secretOf(t)["client_fair"])

	require.Equal(t, http.StatusOK, doAPI(t, p, "", http.MethodPost, "/secrets",
		`{"name":"alice","secret":"`+alice.Hex()+`","speed_up":"2mbit","client_fair":true}`).Code)
	assert.True(t, fairOn(), "sent, with a speed of any direction, it is kept")
	assert.Equal(t, true, userOf(t)["client_fair"])

	require.Equal(t, http.StatusOK, doAPI(t, p, "", http.MethodPost, "/secrets",
		`{"name":"alice","secret":"`+alice.Hex()+`","speed_up":"2mbit"}`).Code)
	assert.False(t, fairOn(), "not sent, it is cleared")
	assert.NotContains(t, secretOf(t), "client_fair")
	assert.NotContains(t, userOf(t), "client_fair")
	assert.Equal(t, float64(250_000), secretOf(t)["speed_limit_up"], "and what was sent is kept")
}
