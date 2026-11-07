package mtglib

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// client-speed, the per-address ceiling: how fast one address of a shared
// secret may move bytes, both directions together, whatever the others do. It
// is a bucket of its own on the address's entry, separate from fair share's,
// and the secret's rest entry -- every unkeyed peer, every address past a cap --
// never has one.

// testCeiling is the ceiling the tests against the clock hold an address to: a
// quarter of a megabyte a second, whose bucket is the 64 KiB floor. Twice it
// takes an address about 1.75 s past the full bucket it starts with; two
// addresses wrongly sharing one bucket would take about 3.75 s for the same.
const testCeiling = 256 << 10

// The bands the clock is read against. Wide on purpose: an address held to its
// ceiling cannot finish twice testCeiling in under heldAtLeast, two addresses
// held each to its own finish both well inside eachOnItsOwn, which two sharing
// one bucket cannot, and a peer the ceiling does not reach finishes inside
// notHeld. Each band is about a second from what it tells apart, on both sides.
const (
	heldAtLeast  = time.Second
	eachOnItsOwn = 2750 * time.Millisecond
	notHeld      = time.Second
)

// ceilingRefill is how long a transfer against the clock waits for the bucket
// the transfer before it drained to fill again: testCeiling refills the 64 KiB
// floor in a quarter of a second, and the rest is room for the last bytes of the
// transfer before to clear. The bucket is one for both directions, so without
// it a transfer that follows another starts empty and takes a quarter of a
// second longer than one that starts full, and the bands above would have to
// allow for both.
const ceilingRefill = 400 * time.Millisecond

// ceilingTransfer is one timed transfer of a stream, or why it failed: a
// goroutine reports it, and only the test's own goroutine may fail the test.
type ceilingTransfer struct {
	took time.Duration
	err  error
}

// timeDownload has Telegram send n bytes down the stream and says how long the
// client took to receive them. On the ee door the client counts the TLS records
// the bytes arrive in, which are only larger, so reaching n is enough.
func timeDownload(client, upstream net.Conn, n int) <-chan ceilingTransfer {
	out := make(chan ceilingTransfer, 1)

	go upstream.Write(make([]byte, n)) //nolint: errcheck

	go func() {
		if err := client.SetReadDeadline(time.Now().Add(15 * time.Second)); err != nil {
			out <- ceilingTransfer{err: err}

			return
		}

		started := time.Now()
		buf := make([]byte, 64<<10)

		for received := 0; received < n; {
			k, err := client.Read(buf)
			if err != nil {
				out <- ceilingTransfer{err: err}

				return
			}

			received += k
		}

		out <- ceilingTransfer{took: time.Since(started)}
	}()

	return out
}

// ceilingUploadPiece is how much one record of an upload carries: under the
// FakeTLS record's payload limit, and as much as the obfuscated door is sent at
// once.
const ceilingUploadPiece = 16000

// timeUpload has the client send n bytes up the stream, framed as the door
// expects, and says how long Telegram took to receive them. That end receives
// exactly the payload, so it is counted exactly.
func timeUpload(ec govEntryCase, client, upstream net.Conn, n int) <-chan ceilingTransfer {
	out := make(chan ceilingTransfer, 1)

	go func() {
		for sent := 0; sent < n; sent += ceilingUploadPiece {
			if _, err := client.Write(ec.framePayload(make([]byte, min(ceilingUploadPiece, n-sent)))); err != nil {
				return
			}
		}
	}()

	go func() {
		if err := upstream.SetReadDeadline(time.Now().Add(15 * time.Second)); err != nil {
			out <- ceilingTransfer{err: err}

			return
		}

		started := time.Now()

		_, err := io.ReadFull(upstream, make([]byte, n))

		out <- ceilingTransfer{took: time.Since(started), err: err}
	}()

	return out
}

// tookFor is how long a transfer took, failing the test when it failed.
func tookFor(t *testing.T, transfer <-chan ceilingTransfer, what string) time.Duration {
	t.Helper()

	result := <-transfer
	require.NoError(t, result.err, what)

	return result.took
}

// ceilingStream is one of alice's streams through the real door, from where.
type ceilingStream struct {
	client, upstream net.Conn
	done             <-chan struct{}
	ctx              *streamContext
}

// openCeilingStream connects one of alice's clients through this door from
// where -- nil is the harness's own loopback -- and finds its stream by the
// address admission recorded.
func openCeilingStream(
	t *testing.T, ec govEntryCase, h *entryHarness, key [SecretKeyLength]byte, where *net.TCPAddr,
) *ceilingStream {
	t.Helper()

	var (
		client net.Conn
		done   <-chan struct{}
		at     = addressKey("127.0.0.1")
	)

	if where == nil {
		client, done = h.dialProxy(t, ec.policy)
	} else {
		client, done = dialProxyFrom(t, h, ec.policy, where)
		at = addressKey(where.IP.String())
	}

	upstream := connectThrough(t, ec, h, client, "alice", key)

	t.Cleanup(func() { endStream(client, upstream, done) })

	return &ceilingStream{client: client, upstream: upstream, done: done, ctx: liveStreamAt(t, h.proxy, "alice", at)}
}

// ceilingOf is the rate and the burst of an entry's ceiling, 0 and 0 for none.
func ceilingOf(entry *clientEntry) (int64, int) {
	current := entry.ceiling.limiter.Load()
	if current == nil {
		return 0, 0
	}

	return int64(current.Limit()), current.Burst()
}

// The ceiling against the clock, through the real door, on both doors and in
// both directions: two places of one secret are each held to it -- their rates
// do not add up to it -- while a loopback peer of the same secret, which is not
// one place and is governed as the secret's rest entry, is not held at all. It
// is client-speed alone that asks for entries here: the proxy keeps no
// addresses. The time the places spent held is the user's throttled time, and
// the ceiling reads back on /stats. That the two places have a bucket each is
// asserted on the objects first; the clock is what shows the buckets hold.
func TestClientSpeedHoldsEachAddressToItsCeiling(t *testing.T) {
	t.Parallel()

	for _, ec := range govEntryCases()[:2] {
		t.Run(ec.name, func(t *testing.T) {
			t.Parallel()

			secret := ec.secret(t)
			h := ec.harness(t, map[string]Secret{"alice": secret},
				map[string]SecretLimits{"alice": {ClientSpeedBytesPerSecond: testCeiling}})

			require.False(t, h.proxy.trackClientIPs, "the ceiling alone is what asks for entries")

			first := openCeilingStream(t, ec, h, secret.Key, tcpFrom("203.0.113.31", 50001))
			second := openCeilingStream(t, ec, h, secret.Key, tcpFrom("198.51.100.32", 50002))
			local := openCeilingStream(t, ec, h, secret.Key, nil)

			firstEntry, secondEntry := first.ctx.addrEntry.Load(), second.ctx.addrEntry.Load()
			require.NotNil(t, firstEntry)
			require.NotNil(t, secondEntry)
			require.NotSame(t, firstEntry, secondEntry, "two places, two entries")

			for _, entry := range []*clientEntry{firstEntry, secondEntry} {
				require.False(t, entry.rest)

				rate, burst := ceilingOf(entry)
				assert.EqualValues(t, testCeiling, rate, "%s is held to the secret's client-speed", entry.key)
				assert.Equal(t, ceilingBurst(testCeiling), burst)
			}

			assert.NotSame(t, installedLimiter(t, &firstEntry.ceiling), installedLimiter(t, &secondEntry.ceiling),
				"two places, two buckets: the clock below shows what one shared between them would do")

			rest := local.ctx.addrEntry.Load()
			require.NotNil(t, rest, "a loopback peer is governed, as the rest entry")
			require.True(t, rest.rest)
			assert.False(t, rest.ceiling.installed(), "and the rest entry has no ceiling")

			for i, direction := range []struct {
				name  string
				start func(s *ceilingStream) <-chan ceilingTransfer
			}{
				{"download", func(s *ceilingStream) <-chan ceilingTransfer {
					return timeDownload(s.client, s.upstream, 2*testCeiling)
				}},
				{"upload", func(s *ceilingStream) <-chan ceilingTransfer {
					return timeUpload(ec, s.client, s.upstream, 2*testCeiling)
				}},
			} {
				if i > 0 {
					time.Sleep(ceilingRefill)
				}

				firstTook, secondTook, localTook := direction.start(first), direction.start(second), direction.start(local)

				a := tookFor(t, firstTook, direction.name+" from the first place")
				b := tookFor(t, secondTook, direction.name+" from the second place")
				free := tookFor(t, localTook, direction.name+" from loopback")

				assert.GreaterOrEqual(t, a, heldAtLeast, "%s: the first place is held to its ceiling", direction.name)
				assert.GreaterOrEqual(t, b, heldAtLeast, "%s: the second place is held to its ceiling", direction.name)
				assert.Less(t, max(a, b), eachOnItsOwn,
					"%s: each place is held to the ceiling on its own, not to the ceiling between them", direction.name)
				assert.Less(t, free, notHeld, "%s: the rest entry has no ceiling", direction.name)
				assert.Less(t, free, min(a, b)/2, "%s: the loopback peer was not paced", direction.name)
			}

			user := h.proxy.stats.getOrCreate("alice")
			assert.Positive(t, user.clientThrottledNanos.Load(), "time held to a ceiling is the user's throttled time")
			assert.Zero(t, user.speed.throttledNanos.Load(), "and the secret's own bucket held nobody")
			assert.Positive(t, firstEntry.throttledNanos.Load())
			assert.Positive(t, secondEntry.throttledNanos.Load())
			assert.Zero(t, rest.throttledNanos.Load())

			stats := statsFor(t, h.proxy).Users["alice"]
			assert.EqualValues(t, testCeiling, stats.ClientSpeedLimit, "the ceiling reads back")
			assert.Positive(t, stats.ThrottledMillis)
		})
	}
}

// Review Focus 4 for the ceiling, through the real door on both doors: a reload
// reaches the streams that were open before it. Adding client-speed gives an
// open keyed stream an entry with the ceiling and holds it there, and an open
// loopback stream the rest entry, which has none; lowering it re-rates the same
// bucket; raising it past the band its burst was sized for replaces the bucket;
// removing it -- the secret's only per-address control, with the proxy keeping
// no addresses, so nothing asks for entries any more -- leaves the stream on its
// entry with no ceiling, unheld; and adding it again gives that entry one back.
func TestAReloadMovesTheCeilingOfStreamsAlreadyOpen(t *testing.T) {
	t.Parallel()

	for _, ec := range govEntryCases()[:2] {
		t.Run(ec.name, func(t *testing.T) {
			t.Parallel()

			secret := ec.secret(t)
			h := ec.harness(t, map[string]Secret{"alice": secret}, nil)

			require.False(t, h.proxy.trackClientIPs)

			reload := func(ceiling int64) {
				t.Helper()

				cfg := SecretConfig{Secrets: map[string]Secret{"alice": secret}}
				if ceiling > 0 {
					cfg.Limits = map[string]SecretLimits{"alice": {ClientSpeedBytesPerSecond: ceiling}}
				}

				require.NoError(t, h.proxy.ReplaceSecrets(cfg))
			}

			keyed := openCeilingStream(t, ec, h, secret.Key, tcpFrom("203.0.113.33", 50001))
			local := openCeilingStream(t, ec, h, secret.Key, nil)

			require.Nil(t, keyed.ctx.addrEntry.Load(), "nothing needed an entry before the reload")
			require.Nil(t, local.ctx.addrEntry.Load())

			reload(testCeiling)

			own := keyed.ctx.addrEntry.Load()
			require.NotNil(t, own, "an open keyed stream is given an entry")
			require.False(t, own.rest)

			rate, _ := ceilingOf(own)
			require.EqualValues(t, testCeiling, rate, "and the entry has the ceiling the reload set")

			rest := local.ctx.addrEntry.Load()
			require.NotNil(t, rest, "an open loopback stream joins the rest entry")
			require.True(t, rest.rest)
			assert.False(t, rest.ceiling.installed())

			keyedTook, localTook := timeDownload(keyed.client, keyed.upstream, 2*testCeiling),
				timeDownload(local.client, local.upstream, 2*testCeiling)

			held := tookFor(t, keyedTook, "download after the ceiling was added")
			free := tookFor(t, localTook, "download from loopback")

			assert.GreaterOrEqual(t, held, heldAtLeast, "the stream open before the reload is held to it")
			assert.Less(t, free, notHeld, "the loopback stream is not")

			bucket := installedLimiter(t, &own.ceiling)

			reload(testCeiling / 2)

			assert.Same(t, bucket, installedLimiter(t, &own.ceiling), "lowered: the same bucket, re-rated")
			assert.InDelta(t, float64(testCeiling/2), float64(bucket.Limit()), 0)

			reload(8 << 20)

			raised := installedLimiter(t, &own.ceiling)
			assert.NotSame(t, bucket, raised, "raised past its burst's band: a new bucket")
			assert.InDelta(t, float64(8<<20), float64(raised.Limit()), 0)
			assert.Equal(t, ceilingBurst(8<<20), raised.Burst(), "with the burst of its rate")
			assert.False(t, rest.ceiling.installed(), "and the rest entry never has one")

			// Back to a ceiling that holds, so that the clock below can tell a
			// removed ceiling from one left at its last rate.
			reload(testCeiling)

			rate, burst := ceilingOf(own)
			assert.EqualValues(t, testCeiling, rate)
			assert.Equal(t, ceilingBurst(testCeiling), burst)

			reload(0)

			require.False(t, h.proxy.clientEntriesWantedBy(h.proxy.secrets.Load()),
				"it was the only per-address control: nothing asks for entries any more")
			assert.Same(t, own, keyed.ctx.addrEntry.Load(), "the open stream keeps its entry")
			assert.False(t, own.ceiling.installed(), "removed: the ceiling is gone, not left at its last rate")

			free = tookFor(t, timeDownload(keyed.client, keyed.upstream, 2*testCeiling), "download after the removal")
			assert.Less(t, free, notHeld, "the stream is not held any more")

			reload(testCeiling)

			rate, _ = ceilingOf(own)
			assert.EqualValues(t, testCeiling, rate, "added again: the entry the stream holds has it again")
			assert.False(t, rest.ceiling.installed())
		})
	}
}

// ceilingProbe is a table probe on a fake clock whose alice has the given
// client-speed, applied as a reload applies it, and the function that reloads
// her with another: everything a reload, admission and the table touch, with
// numbers instead of bands.
func ceilingProbe(t *testing.T, ceiling int64) (*denyProbe, *fakeAddrClock, func(ceiling int64)) {
	t.Helper()

	clock := newFakeAddrClock()
	probe := newClientTableProbe(t, false)
	probe.proxy.clients = newClientTable(clock.clock())

	reload := func(ceiling int64) {
		t.Helper()

		cfg := probe.proxy.secrets.Load().toConfig()
		cfg.Limits = nil

		if ceiling > 0 {
			cfg.Limits = map[string]SecretLimits{"alice": {ClientSpeedBytesPerSecond: ceiling}}
		}

		require.NoError(t, probe.proxy.ReplaceSecrets(cfg))
	}

	reload(ceiling)

	return probe, clock, reload
}

// admitFrom admits one of alice's streams from addr and returns it.
func admitFrom(t *testing.T, probe *denyProbe, addr net.Addr) *streamContext {
	t.Helper()

	sc := probe.stream(t, addr, 0)
	require.Equal(t, DenyNone, probe.proxy.tryRegisterConn(sc))

	return sc
}

// A reload moves the ceiling of every entry in place, as the numbers show it:
// a reload that changes nothing replaces and refills nothing; a new rate inside
// the band the bucket's burst was sized for re-rates the same bucket, its spent
// tokens still spent; a rate outside it gets a new bucket with the burst of
// that rate, the only way a burst changes, and a new entry is made with that
// burst too; an entry no stream holds is moved with the others, so its address
// finds the new ceiling when it comes back; a reconnect finds the bucket its
// address left; the rest entry never has one;
// and removing the key leaves no ceiling, whatever else the entry carries -- a
// fair share is not the ceiling's to touch.
func TestAReloadReRatesTheCeilingInPlace(t *testing.T) {
	t.Parallel()

	probe, clock, reload := ceilingProbe(t, 1<<20)
	table := probe.proxy.clients

	held := admitFrom(t, probe, tcpFrom("203.0.113.40", 50001))
	entry := held.addrEntry.Load()
	require.NotNil(t, entry, "client-speed asks for an entry")

	bucket := installedLimiter(t, &entry.ceiling)
	require.Equal(t, ceilingBurst(1<<20), bucket.Burst())
	drainAddrLimiter(t, &entry.ceiling)

	idle := admitFrom(t, probe, tcpFrom("203.0.113.41", 50002))
	idleEntry := idle.addrEntry.Load()
	require.NotNil(t, idleEntry)
	probe.proxy.unregisterConn(idle)
	require.Equal(t, 0, clientRefs(table, idleEntry), "an entry no stream holds")

	rest := admitFrom(t, probe, tcpFrom("127.0.0.1", 50003)).addrEntry.Load()
	require.NotNil(t, rest)
	require.True(t, rest.rest)

	spent := func() float64 { return bucket.TokensAt(clock.read()) }

	reload(1 << 20)
	assert.Same(t, bucket, installedLimiter(t, &entry.ceiling), "a reload that changes nothing replaces nothing")
	assert.Less(t, spent(), 1.0, "and refills nothing")

	reload(512 << 10)
	assert.Same(t, bucket, installedLimiter(t, &entry.ceiling), "lowered inside the band: re-rated in place")
	assert.InDelta(t, float64(512<<10), float64(bucket.Limit()), 0)
	assert.Less(t, spent(), 1.0, "the tokens it spent stay spent")

	reload(1 << 20)
	assert.Same(t, bucket, installedLimiter(t, &entry.ceiling), "raised inside the band: re-rated in place")
	assert.InDelta(t, float64(1<<20), float64(bucket.Limit()), 0)

	again := admitFrom(t, probe, tcpFrom("203.0.113.40", 50004))
	require.Same(t, entry, again.addrEntry.Load())
	assert.Same(t, bucket, installedLimiter(t, &entry.ceiling), "a reconnect finds the bucket its address left")
	assert.Less(t, spent(), 1.0, "spent")

	reload(16 << 20)

	raised := installedLimiter(t, &entry.ceiling)
	assert.NotSame(t, bucket, raised, "raised past the band: a new bucket")
	assert.Equal(t, ceilingBurst(16<<20), raised.Burst())
	assert.InDelta(t, float64(16<<20), float64(raised.Limit()), 0)

	// An address new at that rate is made with the burst of that rate, above
	// the floor -- the burst a reload gives it too -- so a reload that changes
	// nothing refills nobody, whatever burst an entry was made with.
	fresh := admitFrom(t, probe, tcpFrom("203.0.113.47", 50006)).addrEntry.Load()
	require.NotNil(t, fresh)

	made := installedLimiter(t, &fresh.ceiling)
	require.Greater(t, ceilingBurst(16<<20), minAddrBurst, "the rate is above the floor's band")
	assert.Equal(t, ceilingBurst(16<<20), made.Burst(), "a new entry has the burst of its rate")
	drainAddrLimiter(t, &fresh.ceiling)

	reload(16 << 20)
	assert.Same(t, made, installedLimiter(t, &fresh.ceiling), "a reload that changes nothing replaces nothing")
	assert.Less(t, made.TokensAt(clock.read()), 1.0, "and refills nothing")
	assert.Same(t, raised, installedLimiter(t, &entry.ceiling))

	back := admitFrom(t, probe, tcpFrom("203.0.113.41", 50005))
	require.Same(t, idleEntry, back.addrEntry.Load())

	rate, burst := ceilingOf(idleEntry)
	assert.EqualValues(t, 16<<20, rate, "the idle entry was moved with the others")
	assert.Equal(t, ceilingBurst(16<<20), burst)

	assert.False(t, rest.ceiling.installed(), "the rest entry never has a ceiling")

	reload(0)

	assert.False(t, entry.ceiling.installed(), "removed: no ceiling, unlimited")
	assert.False(t, idleEntry.ceiling.installed())

	// The ceilings' walk on its own, whatever it does to the ceiling, leaves a
	// fair share beside it as it is: that one follows client-fair, which a
	// reload applies in a walk of its own.
	entry.fairSpeed.install(8<<20, fairBurst(8<<20))
	fair := installedLimiter(t, &entry.fairSpeed)

	table.applyCeilings(func(string) (int64, bool) { return 1 << 20, true })
	table.applyCeilings(func(string) (int64, bool) { return 0, true })

	assert.False(t, entry.ceiling.installed())
	assert.Same(t, fair, installedLimiter(t, &entry.fairSpeed), "and the fair share is not the ceiling's to touch")
	assert.InDelta(t, float64(8<<20), float64(fair.Limit()), 0)
}

// A reload that removes a secret leaves its addresses' ceilings as they are.
// The walk moves the ceilings of the secrets the new set holds; the removed
// one's entries are dropped, and its streams closed, straight after it. Taken
// for a secret with no ceiling, they would be lifted first, and its streams
// would relay unheld for the moment between.
func TestARemovedSecretsCeilingsAreLeftToTheDrop(t *testing.T) {
	t.Parallel()

	probe := newClientTableProbe(t, false)
	p := probe.proxy
	bob := GenerateSecret("bob.example.com")

	cfg := p.secrets.Load().toConfig()
	cfg.Secrets["bob"] = bob
	cfg.Limits = map[string]SecretLimits{"alice": {ClientSpeedBytesPerSecond: 1 << 20}}
	require.NoError(t, p.ReplaceSecrets(cfg))

	entry := admitFrom(t, probe, tcpFrom("203.0.113.48", 50001)).addrEntry.Load()
	require.NotNil(t, entry)

	bucket := installedLimiter(t, &entry.ceiling)

	require.NoError(t, p.ReplaceSecrets(SecretConfig{Secrets: map[string]Secret{"bob": bob}}))

	assert.Nil(t, p.clients.snapshot("alice"), "the removed secret's entries are dropped")
	assert.Same(t, bucket, installedLimiter(t, &entry.ceiling),
		"and the ceiling of the stream still holding one was not lifted on the way out")
}

// The stale-ceiling race of spec §1: a new entry's ceiling comes from the
// secret set as it is when admission takes the entry, under liveMu, not from
// the set the secret matched in. A reload that lands between the match and the
// admission must not leave the entry on the old ceiling: the reload's own
// re-rate has already run and will not come back to it.
func TestANewEntryTakesTheCeilingOfTheSetAtAdmission(t *testing.T) {
	t.Parallel()

	probe, _, _ := ceilingProbe(t, 1<<20)
	p := probe.proxy
	matched := p.secrets.Load()

	sc := probe.stream(t, tcpFrom("203.0.113.42", 50001), 0)
	require.Equal(t, DenyNone, p.attribute(sc, matched, indexOfName(t, matched, "alice")))

	cfg := matched.toConfig()
	cfg.Limits = map[string]SecretLimits{"alice": {ClientSpeedBytesPerSecond: 2 << 20}}
	require.NoError(t, p.ReplaceSecrets(cfg))

	require.Equal(t, DenyNone, p.tryRegisterConn(sc))
	require.NotNil(t, sc.addrEntry.Load(), "client-speed asks for an entry")

	rate, _ := ceilingOf(sc.addrEntry.Load())
	assert.EqualValues(t, 2<<20, rate, "the ceiling of the set the entry was made under")
}

// Spec §1: a new entry is published with its ceiling already in place. Seen
// from the step right after the table gave the stream its entry -- from where
// any other reader of the table would see it -- the keyed entry has the
// secret's ceiling and the rest entry has none.
func TestANewEntryIsPublishedWithItsCeiling(t *testing.T) { //nolint: paralleltest // swaps a package variable
	probe, _, _ := ceilingProbe(t, 1<<20)
	table := probe.proxy.clients

	// Every entry each step sees, and what its ceiling was then: one sighting
	// must not overwrite another, or a later step that sees the entry fixed up
	// would hide the step that saw it without.
	type sighting struct {
		key     addressKey
		ceiling int64
	}

	var seen []sighting

	installRegisterStepHook(t, func(step registerStep, _ *streamContext) DenyReason {
		if step == stepEntryAcquired {
			for _, entry := range table.snapshot("alice") {
				rate, _ := ceilingOf(entry)
				seen = append(seen, sighting{entry.key, rate})
			}
		}

		return DenyNone
	})

	admitFrom(t, probe, tcpFrom("203.0.113.43", 50001))
	admitFrom(t, probe, tcpFrom("127.0.0.1", 50002))

	assert.ElementsMatch(t, []sighting{
		{"203.0.113.43", 1 << 20},
		{"203.0.113.43", 1 << 20},
		{"", 0},
	}, seen, "a keyed entry is never seen without its ceiling, the rest entry never with one")
}

// The lock order's reason, in both of its halves: a reload swaps its set in
// first and only then moves the ceilings, under liveMu, the lock admission makes
// an entry under. So an admission that read the old set made its entry before
// the walk, which moves it, and one after the walk reads the new set. With
// liveMu held here, the new set is already in place -- the swap did not wait for
// liveMu -- and no ceiling has moved until liveMu is let go.
func TestAReloadMovesCeilingsUnderLiveMu(t *testing.T) {
	t.Parallel()

	probe, _, _ := ceilingProbe(t, 1<<20)
	p := probe.proxy

	entry := admitFrom(t, probe, tcpFrom("203.0.113.44", 50001)).addrEntry.Load()
	require.NotNil(t, entry, "client-speed asks for an entry")

	rate, _ := ceilingOf(entry)
	require.EqualValues(t, 1<<20, rate)

	cfg := p.secrets.Load().toConfig()
	cfg.Limits = map[string]SecretLimits{"alice": {ClientSpeedBytesPerSecond: 2 << 20}}

	p.liveMu.Lock()

	done := make(chan error, 1)

	go func() { done <- p.ReplaceSecrets(cfg) }()

	// Not require: the reload must be let go below whatever happens here.
	assert.Eventually(t, func() bool {
		lim, _ := p.secrets.Load().limitsOf("alice")

		return lim.ClientSpeedBytesPerSecond == 2<<20
	}, 2*time.Second, 5*time.Millisecond, "the reload swaps its set in before it needs liveMu")

	assert.Never(t, func() bool {
		rate, _ := ceilingOf(entry)

		return rate != 1<<20
	}, 100*time.Millisecond, 5*time.Millisecond, "no ceiling moves while liveMu is held")

	p.liveMu.Unlock()
	require.NoError(t, <-done)

	rate, _ = ceilingOf(entry)
	assert.EqualValues(t, 2<<20, rate)
}

// The ceiling is one bucket for both directions of an address: a read and a
// write of a chunk each take that chunk from the same tokens.
func TestTheCeilingIsOneBucketForBothDirections(t *testing.T) {
	t.Parallel()

	table, clock := newTestClientTable(t)
	entry := table.acquire("alice", "203.0.113.45", true, entryInit{CeilingRate: testAddrRate})
	bucket := installedLimiter(t, &entry.ceiling)

	conn, _, _ := clientStream(t.Context(), NewProxyStats(), entry)

	readChunk(t, conn)
	writeChunk(t, conn)

	assert.InDelta(t, float64(testAddrBurst-2*testClientChunk), bucket.TokensAt(clock.read()), 0,
		"an upload and a download paid the one bucket")
	assert.Empty(t, clock.sleeps(), "and neither waited: the bucket started full")
}

// An address with no ceiling is not held and not cut, so an unlimited secret
// still writes once: an entry the secret keeps for another control, and the
// same entry once a reload has taken its ceiling away again.
func TestAnAddressWithoutACeilingWritesOnce(t *testing.T) {
	t.Parallel()

	clock := newFakeAddrClock()
	probe := newClientTableProbe(t, false)
	p := probe.proxy
	p.clients = newClientTable(clock.clock())

	limits := func(ceiling int64) {
		t.Helper()

		cfg := p.secrets.Load().toConfig()
		cfg.Limits = map[string]SecretLimits{"alice": {ClientConns: 4, ClientSpeedBytesPerSecond: ceiling}}
		require.NoError(t, p.ReplaceSecrets(cfg))
	}

	limits(0)

	sc := admitFrom(t, probe, tcpFrom("203.0.113.46", 50001))
	require.NotNil(t, sc.addrEntry.Load(), "client-conns keeps an entry")
	require.False(t, sc.addrEntry.Load().ceiling.installed())

	writes := func() int {
		t.Helper()

		counter := &writeCounter{}
		conn := newCountingConn(t.Context(), nil, counter, p.stats, "alice").withClient(&sc.addrEntry)

		n, err := conn.Write(make([]byte, 1<<20))
		require.NoError(t, err)
		require.Equal(t, 1<<20, n)

		return counter.calls
	}

	assert.Equal(t, 1, writes(), "no ceiling: one write")

	limits(testAddrRate)
	assert.Equal(t, (1<<20)/testAddrBurst, writes(), "a ceiling cuts the write to its burst")

	limits(0)
	assert.Equal(t, 1, writes(), "and once it is removed, one write again")
}

// client-speed is a per-address control: it asks for entries on its own, and a
// new entry of a secret with it starts with its ceiling.
func TestClientSpeedIsAPerAddressControl(t *testing.T) {
	t.Parallel()

	lim := SecretLimits{ClientSpeedBytesPerSecond: MinSpeedBytesPerSecond}

	assert.True(t, lim.hasClientControl())
	assert.True(t, buildSecretSet(map[string]Secret{
		"alice": GenerateSecret("alice.example.com"),
		"bob":   GenerateSecret("bob.example.com"),
	}, nil, nil, map[string]SecretLimits{"alice": lim, "bob": {IPLimit: 2}}).anyClientControl())

	assert.EqualValues(t, MinSpeedBytesPerSecond, entryInitOf(lim).CeilingRate)
	assert.Zero(t, entryInitOf(SecretLimits{SpeedBytesPerSecond: 1 << 20}).CeilingRate,
		"the secret's own speed is not a ceiling on its addresses")
}

// The ceiling travels the API as client_speed, spelled as speed is and parsed by
// the same function, so it has speed's floor: PUT sets it and answers 200, it
// reads back as client_speed_limit in bytes a second, on GET /secrets/{name} and
// inside the user object on /stats; a POST that sends it keeps it and one that
// does not clears it, a mutation of another secret leaves it alone, and a value
// the parser refuses is a 400 that names the field, with the running ceiling
// untouched.
func TestClientSpeedThroughTheAPI(t *testing.T) {
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

	assert.NotContains(t, userOf(t), "client_speed_limit", "absent while unset")
	assert.NotContains(t, secretOf(t), "client_speed_limit")

	rec := doAPI(t, p, "", http.MethodPut, "/secrets",
		`{"secrets":{"alice":{"secret":"`+alice.Hex()+`","client_speed":"2mbit"}}}`)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.JSONEq(t, `{"status":"ok"}`, rec.Body.String())

	assert.EqualValues(t, 250_000, p.secrets.Load().limits[0].ClientSpeedBytesPerSecond, "a ceiling alone is kept")
	assert.Equal(t, float64(250_000), secretOf(t)["client_speed_limit"], "read back in bytes a second")
	assert.Equal(t, float64(250_000), userOf(t)["client_speed_limit"])
	assert.NotContains(t, userOf(t), "speed_limit", "it is not the secret's own speed")

	// Another secret's mutation starts from a copy of the set, which keeps it.
	require.Equal(t, http.StatusOK, doAPI(t, p, "", http.MethodPost, "/secrets",
		`{"name":"bob","secret":"`+bob.Hex()+`"}`).Code)
	assert.Equal(t, float64(250_000), secretOf(t)["client_speed_limit"])

	require.Equal(t, http.StatusOK, doAPI(t, p, "", http.MethodPost, "/secrets",
		`{"name":"alice","secret":"`+alice.Hex()+`","client_speed":"1MB/s"}`).Code)
	assert.Equal(t, float64(1<<20), secretOf(t)["client_speed_limit"], "sent, it is kept")

	for name, value := range map[string]string{
		"below speed's floor": `"32kbit"`,
		"not a speed":         `"fast"`,
		"negative":            `"-1mbit"`,
		"zero":                `"0"`,
	} {
		rec := doAPI(t, p, "", http.MethodPost, "/secrets",
			`{"name":"alice","secret":"`+alice.Hex()+`","client_speed":`+value+`}`)
		assert.Equal(t, http.StatusBadRequest, rec.Code, name)
		assert.Contains(t, rec.Body.String(), "client_speed", "%s: the refusal names the field", name)
		assert.Equal(t, float64(1<<20), secretOf(t)["client_speed_limit"],
			"%s: a refused request leaves the running ceiling alone", name)
	}

	require.Equal(t, http.StatusOK, doAPI(t, p, "", http.MethodPost, "/secrets",
		`{"name":"alice","secret":"`+alice.Hex()+`","client_speed":"64kbit"}`).Code, "the floor itself is accepted")
	assert.Equal(t, float64(MinSpeedBytesPerSecond), secretOf(t)["client_speed_limit"])

	require.Equal(t, http.StatusOK, doAPI(t, p, "", http.MethodPost, "/secrets",
		`{"name":"alice","secret":"`+alice.Hex()+`","ip_limit":2}`).Code)
	assert.NotContains(t, secretOf(t), "client_speed_limit", "not sent, it is cleared")
	assert.NotContains(t, userOf(t), "client_speed_limit")
	assert.Equal(t, float64(2), secretOf(t)["ip_limit"])
}
