package mtglib

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/Arman2122/mtg-proxy/essentials"
	"github.com/Arman2122/mtg-proxy/internal/testclient"
	"github.com/Arman2122/mtg-proxy/mtglib/internal/tls/fake"
	"github.com/Arman2122/mtg-proxy/mtglib/obfuscation"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The hint cache at the FakeTLS door, end to end through ServeConn. Every
// connection here comes from an address the test chose (dialProxyFrom): the
// harness's own peers are loopback, which is unkeyed and gets no hints at all.

// fakeTLSDoor is the ee row of the governance cases.
func fakeTLSDoor() govEntryCase { return govEntryCases()[0] }

// hintedHarness is the ee governance harness with the hint cache on. The
// harness builds a Proxy literal, and a literal has none.
func hintedHarness(t *testing.T, secrets map[string]Secret, limits map[string]SecretLimits) *entryHarness {
	t.Helper()

	h := fakeTLSDoor().harness(t, secrets, limits)
	h.proxy.hints = newMatchHints(h.proxy.ctx)

	return h
}

// doorTally is what the FakeTLS door counted, or what one connection moved.
type doorTally struct {
	verifications, hinted, scanned, unmatched int64
}

func tallyOf(p *Proxy) doorTally {
	return doorTally{
		verifications: p.fakeStats.verifications.Load(),
		hinted:        p.fakeStats.hinted.Load(),
		scanned:       p.fakeStats.scanned.Load(),
		unmatched:     p.fakeStats.unmatched.Load(),
	}
}

func (d doorTally) minus(o doorTally) doorTally {
	return doorTally{
		verifications: d.verifications - o.verifications,
		hinted:        d.hinted - o.hinted,
		scanned:       d.scanned - o.scanned,
		unmatched:     d.unmatched - o.unmatched,
	}
}

// connectFrom carries one client of name from addr into the relay, requires it
// to be registered under name, ends it, and returns what that one handshake
// moved. connectThrough returns only once the Telegram dial has been read, and
// that dial comes after admit and after the hint write, so the hint is in place
// by the time this returns.
func connectFrom(
	t *testing.T, h *entryHarness, ec govEntryCase, addr net.Addr, name string, key [SecretKeyLength]byte,
) doorTally {
	t.Helper()

	before := tallyOf(h.proxy)

	client, done := dialProxyFrom(t, h, ec.policy, addr)
	upstream := connectThrough(t, ec, h, client, name, key)
	endStream(client, upstream, done)

	return tallyOf(h.proxy).minus(before)
}

// refusedFrom is connectFrom for a hello the proxy must refuse. ServeConn has
// returned when it does.
func refusedFrom(t *testing.T, h *entryHarness, addr net.Addr, key [SecretKeyLength]byte) doorTally {
	t.Helper()

	before := tallyOf(h.proxy)

	refuseFrom(t, fakeTLSDoor(), h, key, addr)

	return tallyOf(h.proxy).minus(before)
}

func reloadSecrets(t *testing.T, p *Proxy, secrets map[string]Secret) {
	t.Helper()

	p.reloadMu.Lock()
	defer p.reloadMu.Unlock()

	require.NoError(t, p.swapSecretConfigLocked(SecretConfig{Secrets: secrets}))
}

func TestAReturningClientIsVerifiedBeforeTheScan(t *testing.T) {
	t.Parallel()

	const hosted = 200

	ec := fakeTLSDoor()
	secrets, name := hostedAmongDecoys(t, ec, hosted, "last")
	h := hintedHarness(t, secrets, nil)

	set := h.proxy.secrets.Load()
	require.Len(t, set.cands, hosted)
	require.Equal(t, hosted-1, set.candByName[name], "the client's secret is the last the scan reaches")

	key := secrets[name].Key

	assert.Equal(t, doorTally{verifications: hosted, scanned: 1},
		connectFrom(t, h, ec, tcpFrom("203.0.113.7", 41001), name, key),
		"a first connection scans every candidate up to its own, which is the last")

	assert.Equal(t, doorTally{verifications: 1, hinted: 1},
		connectFrom(t, h, ec, tcpFrom("203.0.113.7", 41002), name, key),
		"a returning client is verified against its hint and nothing else")

	assert.Equal(t, doorTally{verifications: hosted, scanned: 1},
		connectFrom(t, h, ec, tcpFrom("203.0.113.8", 41003), name, key),
		"a hint belongs to the address that earned it")

	// Review Focus 1, at the door: the key of an IPv6 client is its /64.
	assert.Equal(t, doorTally{verifications: hosted, scanned: 1},
		connectFrom(t, h, ec, tcpFrom("2001:db8:1:2::1", 41004), name, key))

	assert.Equal(t, doorTally{verifications: 1, hinted: 1},
		connectFrom(t, h, ec, tcpFrom("2001:db8:1:2:ffff::9", 41005), name, key),
		"another host in the same /64 is the same place")
}

// Review Focus 2, at the door: a peer whose address is not one place -- private
// here, as behind a carrier that does not forward the client address -- gets
// no hint, however often it comes back.
func TestAnUnkeyedPeerIsScannedEveryTime(t *testing.T) {
	t.Parallel()

	const hosted = 20

	ec := fakeTLSDoor()
	secrets, name := hostedAmongDecoys(t, ec, hosted, "last")
	key := secrets[name].Key
	h := hintedHarness(t, secrets, nil)

	port := 48000
	from := func(place string) net.Addr {
		port++

		return tcpFrom(place, port)
	}

	for _, place := range []string{"10.0.0.7", "fd00::7"} {
		for visit := 1; visit <= 2; visit++ {
			assert.Equal(t, doorTally{verifications: hosted, scanned: 1},
				connectFrom(t, h, ec, from(place), name, key),
				"%s, visit %d: every candidate up to the last, every time", place, visit)
		}

		assert.Nil(t, h.proxy.hints.recall(net.ParseIP(place)), "%s has no hint", place)
	}

	// The control: the same client from a routable address is hinted on its
	// second visit, so this harness does have hints on.
	const routable = "203.0.113.60"

	assert.Equal(t, doorTally{verifications: hosted, scanned: 1}, connectFrom(t, h, ec, from(routable), name, key))
	assert.Equal(t, doorTally{verifications: 1, hinted: 1}, connectFrom(t, h, ec, from(routable), name, key),
		"the control: a routable address is hinted on its second visit")

	current, previous := hintsSize(h.proxy.hints)
	assert.Equal(t, 1, current+previous, "the routable address is the only one ever stored")
}

func TestAStaleHintFallsThroughAndStillMatches(t *testing.T) {
	t.Parallel()

	ec := fakeTLSDoor()
	alice, bob, carol := ec.secret(t), ec.secret(t), ec.secret(t)
	h := hintedHarness(t, map[string]Secret{"alice": alice, "bob": bob, "carol": carol}, nil)

	require.Equal(t, map[string]int{"alice": 0, "bob": 1, "carol": 2}, h.proxy.secrets.Load().candByName)

	const place = "203.0.113.20"

	recall := func() []string { return h.proxy.hints.recall(net.ParseIP(place)) }

	assert.Equal(t, doorTally{verifications: 1, scanned: 1},
		connectFrom(t, h, ec, tcpFrom(place, 42001), "alice", alice.Key))
	assert.Equal(t, []string{"alice"}, recall())

	// carol from the same place: alice is tried first and fails, then the scan
	// passes over alice, already tried, to bob and to carol.
	assert.Equal(t, doorTally{verifications: 3, scanned: 1},
		connectFrom(t, h, ec, tcpFrom(place, 42002), "carol", carol.Key),
		"one hint that missed, then the scan over the rest")
	assert.Equal(t, []string{"carol", "alice"}, recall(), "the match goes to the front")

	assert.Equal(t, doorTally{verifications: 2, hinted: 1},
		connectFrom(t, h, ec, tcpFrom(place, 42003), "alice", alice.Key),
		"the second hint is tried second")
	assert.Equal(t, []string{"alice", "carol"}, recall())

	// A hello no secret matches: both hints, then the scan over what is left.
	// Refused, and no hint moves.
	stranger := ec.secret(t)

	assert.Equal(t, doorTally{verifications: 3, unmatched: 1},
		refusedFrom(t, h, tcpFrom(place, 42004), stranger.Key))
	assert.Equal(t, []string{"alice", "carol"}, recall())
}

// Review Focus 6: nothing writes a hint unless the whole handshake succeeded --
// the match, the replay check, the per-user limits AND admission.
func TestAHintIsWrittenOnlyAfterAdmit(t *testing.T) {
	t.Parallel()

	const (
		earned  = "198.51.100.30"
		refused = "198.51.100.31"
	)

	ec := fakeTLSDoor()

	noHint := func(t *testing.T, h *entryHarness) {
		t.Helper()

		assert.Nil(t, h.proxy.hints.recall(net.ParseIP(refused)), "a refused handshake must not write a hint")
	}

	t.Run("an admitted client writes one", func(t *testing.T) {
		t.Parallel()

		alice := ec.secret(t)
		h := hintedHarness(t, map[string]Secret{"alice": alice}, nil)

		connectFrom(t, h, ec, tcpFrom(refused, 43001), "alice", alice.Key)

		assert.Equal(t, []string{"alice"}, h.proxy.hints.recall(net.ParseIP(refused)),
			"the control: without it a build that never writes passes every row below")
	})

	t.Run("a replayed hello", func(t *testing.T) {
		t.Parallel()

		alice := ec.secret(t)
		h := hintedHarness(t, map[string]Secret{"alice": alice}, nil)

		// The original goes through the door alone, from loopback: it is seen,
		// it writes nothing anywhere, and the copy below is a replay.
		hello := ec.clientHello(t, alice.Key, bytes.Repeat([]byte{0x5a}, 32))

		_, ok := h.fakeTLSAttempt(t, hello)
		require.True(t, ok)

		client, done := dialProxyFrom(t, h, ec.policy, tcpFrom(refused, 43002))

		_, err := client.Write(hello)
		require.NoError(t, err)
		require.True(t, govAwait(done, govDenyBudget))

		require.Equal(t, 1, h.events.replays(), "refused as a replay")
		assert.EqualValues(t, 2, h.proxy.fakeStats.scanned.Load(), "it matched, and counts as its match")
		noHint(t, h)
	})

	for _, tc := range []struct {
		name   string
		limits SecretLimits
		used   int64
	}{
		{"a disabled user", SecretLimits{Disabled: true}, 0},
		{"an expired user", SecretLimits{ExpiresAt: time.Now().Add(-time.Hour)}, 0},
		{"an over-quota user", SecretLimits{QuotaBytes: 100}, 500},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			alice := ec.secret(t)
			h := hintedHarness(t, map[string]Secret{"alice": alice}, map[string]SecretLimits{"alice": tc.limits})
			h.proxy.stats.users["alice"].quotaUsed.Store(tc.used)

			assert.Equal(t, doorTally{verifications: 1, scanned: 1},
				refusedFrom(t, h, tcpFrom(refused, 43003), alice.Key), "it matched, and counts as its match")
			require.Equal(t, 1, h.events.frontings(), "refused by the limit, on the fronting exit")
			noHint(t, h)
		})
	}

	t.Run("an ip-limit-refused user", func(t *testing.T) {
		t.Parallel()

		alice := ec.secret(t)
		h := hintedHarness(t, map[string]Secret{"alice": alice}, map[string]SecretLimits{"alice": {IPLimit: 1}})

		// One place holds alice's only slot, and writes its hint doing so.
		first, firstDone := dialProxyFrom(t, h, ec.policy, tcpFrom(earned, 43004))
		firstUp := connectThrough(t, ec, h, first, "alice", alice.Key)

		defer endStream(first, firstUp, firstDone)

		require.Equal(t, []string{"alice"}, h.proxy.hints.recall(net.ParseIP(earned)))

		refuseFrom(t, ec, h, alice.Key, tcpFrom(refused, 43005))

		require.EqualValues(t, 1, h.proxy.stats.users["alice"].ipLimitRefused.Load(), "refused by the address limit")
		noHint(t, h)
	})

	t.Run("a throttled user", func(t *testing.T) {
		t.Parallel()

		alice := ec.secret(t)
		h := hintedHarness(t, map[string]Secret{"alice": alice}, nil)

		h.proxy.stats.SetThrottle(1, time.Hour)
		h.proxy.stats.throttleMu.Lock()
		h.proxy.stats.throttleCaps["alice"] = 0
		h.proxy.stats.throttleMu.Unlock()

		refuseFrom(t, ec, h, alice.Key, tcpFrom(refused, 43006))

		require.Equal(t, 1, h.events.count(func(evt Event) bool {
			_, ok := evt.(EventThrottled)

			return ok
		}), "refused by the throttle")
		noHint(t, h)
	})
}

// Review Focus 5: a hint is a name, resolved against the snapshot the hello
// met, so a reload between the write and the next hello can make it useless and
// never makes it wrong.
func TestAReloadNeverMisattributesAHint(t *testing.T) {
	t.Parallel()

	ec := fakeTLSDoor()

	const place = "203.0.113.40"

	t.Run("a removed name", func(t *testing.T) {
		t.Parallel()

		alice, bob := ec.secret(t), ec.secret(t)
		h := hintedHarness(t, map[string]Secret{"alice": alice, "bob": bob}, nil)

		connectFrom(t, h, ec, tcpFrom(place, 44001), "bob", bob.Key)
		require.Equal(t, []string{"bob"}, h.proxy.hints.recall(net.ParseIP(place)))

		reloadSecrets(t, h.proxy, map[string]Secret{"alice": alice})
		require.Equal(t, map[string]int{"alice": 0}, h.proxy.secrets.Load().candByName)

		// bob names nobody now. Read with the one-value lookup it would be
		// position 0 -- alice's -- so alice is the client that tells.
		assert.Equal(t, doorTally{verifications: 1, scanned: 1},
			connectFrom(t, h, ec, tcpFrom(place, 44002), "alice", alice.Key),
			"a hint naming a removed secret is skipped, not read as position 0")

		assert.Equal(t, doorTally{verifications: 1, unmatched: 1},
			refusedFrom(t, h, tcpFrom(place, 44003), bob.Key),
			"and the removed secret's own key is refused")
	})

	t.Run("a re-keyed name", func(t *testing.T) {
		t.Parallel()

		alice, bob := ec.secret(t), ec.secret(t)
		h := hintedHarness(t, map[string]Secret{"alice": alice, "bob": bob}, nil)

		connectFrom(t, h, ec, tcpFrom(place, 44011), "bob", bob.Key)

		rekeyed := ec.secret(t)
		reloadSecrets(t, h.proxy, map[string]Secret{"alice": alice, "bob": rekeyed})

		assert.Equal(t, doorTally{verifications: 2, unmatched: 1},
			refusedFrom(t, h, tcpFrom(place, 44012), bob.Key),
			"the hint resolves to bob's new key, which the old one does not verify against")

		assert.Equal(t, doorTally{verifications: 1, hinted: 1},
			connectFrom(t, h, ec, tcpFrom(place, 44013), "bob", rekeyed.Key),
			"and the new key is the hint's at once")
	})

	t.Run("a re-sorted set", func(t *testing.T) {
		t.Parallel()

		alice, bob := ec.secret(t), ec.secret(t)
		h := hintedHarness(t, map[string]Secret{"alice": alice, "bob": bob}, nil)

		assert.Equal(t, doorTally{verifications: 2, scanned: 1},
			connectFrom(t, h, ec, tcpFrom(place, 44021), "bob", bob.Key))

		reloadSecrets(t, h.proxy, map[string]Secret{"aaron": ec.secret(t), "alice": alice, "bob": bob})
		require.Equal(t, map[string]int{"aaron": 0, "alice": 1, "bob": 2}, h.proxy.secrets.Load().candByName)

		assert.Equal(t, doorTally{verifications: 1, hinted: 1},
			connectFrom(t, h, ec, tcpFrom(place, 44022), "bob", bob.Key),
			"bob's hint finds bob where he is now; position 1, where he was, is alice's")
	})

	t.Run("a name that became a dropped repeat", func(t *testing.T) {
		t.Parallel()

		alice, bob := ec.secret(t), ec.secret(t)
		h := hintedHarness(t, map[string]Secret{"alice": alice, "bob": bob}, nil)

		connectFrom(t, h, ec, tcpFrom(place, 44031), "bob", bob.Key)
		require.Equal(t, []string{"bob"}, h.proxy.hints.recall(net.ParseIP(place)))

		// aaron sorts first and takes bob's key, so bob is now the later
		// duplicate: no candidate, absent from candByName. The key's hello
		// belongs to aaron, as it would with no hints at all.
		reloadSecrets(t, h.proxy, map[string]Secret{
			"aaron": eeSecretOf(bob.Key, govCoverHost),
			"alice": alice,
			"bob":   bob,
		})
		require.Equal(t, map[string]int{"aaron": 0, "alice": 1}, h.proxy.secrets.Load().candByName)

		assert.Equal(t, doorTally{verifications: 1, scanned: 1},
			connectFrom(t, h, ec, tcpFrom("203.0.113.41", 44032), "aaron", bob.Key),
			"the reference: from an address with no hints, the key is aaron's, found by the scan")

		assert.Equal(t, doorTally{verifications: 1, scanned: 1},
			connectFrom(t, h, ec, tcpFrom(place, 44033), "aaron", bob.Key),
			"bob's hint names no candidate and is skipped; the scan finds aaron, exactly as with no hints")
		assert.Equal(t, []string{"aaron", "bob"}, h.proxy.hints.recall(net.ParseIP(place)),
			"and the admission is written under the name it was attributed to")
	})
}

// A carrier NAT puts many users behind one address. Sixteen of them each keep
// a hint; a seventeenth pushes out the one least recently seen.
func TestSixteenUsersBehindOneAddressAllGetHints(t *testing.T) {
	t.Parallel()

	ec := fakeTLSDoor()
	secrets := make(map[string]Secret)
	users := make([]string, 0, maxHintNames+1)

	for i := range maxHintNames + 1 {
		name := fmt.Sprintf("u%02d", i)
		secrets[name] = ec.secret(t)
		users = append(users, name)
	}

	// Decoys sort before every user, so a scan is never the cheap way in.
	for i := range 8 {
		secrets[fmt.Sprintf("d%02d", i)] = ec.secret(t)
	}

	h := hintedHarness(t, secrets, nil)

	const nat = "198.51.100.20"

	port := 45000
	from := func() net.Addr {
		port++

		return tcpFrom(nat, port)
	}

	for _, user := range users[:maxHintNames] {
		require.EqualValues(t, 1, connectFrom(t, h, ec, from(), user, secrets[user].Key).scanned, user)
	}

	want := slices.Clone(users[:maxHintNames])
	slices.Reverse(want)
	require.Equal(t, want, h.proxy.hints.recall(net.ParseIP(nat)), "all sixteen, most recent first")

	// Round two in the order of round one: each user in turn is the least
	// recently seen, so the last of sixteen hints, and is found after the
	// fifteen others -- exactly sixteen verifications, then to the front.
	for _, user := range users[:maxHintNames] {
		got := connectFrom(t, h, ec, from(), user, secrets[user].Key)

		assert.EqualValues(t, 1, got.hinted, "%s is found among the hints", user)
		assert.Zero(t, got.scanned, user)
		assert.EqualValues(t, maxHintNames, got.verifications, "%s is the last hint tried", user)
	}

	newcomer := users[maxHintNames]
	connectFrom(t, h, ec, from(), newcomer, secrets[newcomer].Key)

	got := h.proxy.hints.recall(net.ParseIP(nat))
	assert.Len(t, got, maxHintNames)
	assert.Equal(t, newcomer, got[0])
	assert.NotContains(t, got, users[0], "u00 was the least recently seen")
}

func TestHintsFollowTrackClientIPsUnlessOverridden(t *testing.T) {
	t.Parallel()

	on, off := true, false

	for _, tc := range []struct {
		name  string
		track bool
		hints *bool
		want  bool
	}{
		{"unset, addresses not tracked", false, nil, false},
		{"unset, addresses tracked", true, nil, true},
		{"on, addresses not tracked", false, &on, true},
		{"off, addresses tracked", true, &off, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			opts, _ := servingOpts(t)
			opts.TrackClientIPs = tc.track
			opts.HandshakeHints = tc.hints

			proxy, err := NewProxy(opts)
			require.NoError(t, err)
			t.Cleanup(proxy.Shutdown)

			assert.Equal(t, tc.want, proxy.hints != nil, "the proxy has a hint cache exactly when hints are on")
		})
	}
}

// Hints are for a hello of at most maxScanBlocks. Above it a hello is never
// hinted, whatever its address earned -- and under the handshake budget's
// default mode, enforce, never scanned either: it is fronted.
func TestAnOversizedHelloNeverConsultsHints(t *testing.T) {
	t.Parallel()

	const hosted = 20

	ec := fakeTLSDoor()
	secrets, name := hostedAmongDecoys(t, ec, hosted, "last")
	key := secrets[name].Key
	h := hintedHarness(t, secrets, nil)

	// The harness is a Proxy literal, whose budget is off, so the scan cap
	// would not apply. An enforce budget with room for every scan here; the
	// observe twin is TestAnOversizedHelloIsScannedInObserveMode.
	h.proxy.scanBudget = newScanBudget(scanBudgetConfig{NsPerBlock: 10, CPUPercent: 100, Procs: 1000}, time.Now)

	blocksOf := func(size int) int {
		hello := fakeTLSClientHelloPadded(t, key, govCoverHost, make([]byte, 32), size)

		return parsedHello(t, hello, govCoverHost).Blocks()
	}

	require.Equal(t, 128, maxScanBlocks)
	require.Equal(t, maxScanBlocks, blocksOf(7991))
	require.Equal(t, maxScanBlocks+1, blocksOf(7992))

	const place = "203.0.113.50"

	require.Equal(t, doorTally{verifications: hosted, scanned: 1},
		connectFrom(t, h, ec, tcpFrom(place, 46001), name, key))

	assert.Equal(t, doorTally{verifications: 1, hinted: 1},
		connectFrom(t, h, ec.withHelloSize(7991), tcpFrom(place, 46002), name, key),
		"128 blocks is within the cap: hinted")

	before, oversized := tallyOf(h.proxy), h.proxy.fakeStats.oversized.Load()

	refuseFrom(t, ec.withHelloSize(7992), h, key, tcpFrom(place, 46003))

	assert.Equal(t, doorTally{}, tallyOf(h.proxy).minus(before),
		"129 blocks is above it: the hint is not consulted, and nothing is scanned")
	assert.Equal(t, oversized+1, h.proxy.fakeStats.oversized.Load(), "it is counted as oversized")
	assert.Equal(t, 1, h.events.frontings(), "and fronted")
}

// TestConcurrentEEHandshakesShareOneSnapshotAndHints runs real door handshakes
// from many clients at once against one secret set and one hint cache, so the
// race detector sees Candidates verified from many goroutines and the cache
// read and written from many goroutines.
func TestConcurrentEEHandshakesShareOneSnapshotAndHints(t *testing.T) {
	t.Parallel()

	const (
		hosted  = 24
		clients = 16
		rounds  = 10
	)

	ec := fakeTLSDoor()
	secrets := make(map[string]Secret, hosted)

	for i := range hosted {
		secrets[fmt.Sprintf("u%02d", i)] = ec.secret(t)
	}

	h := hintedHarness(t, secrets, nil)
	newUpstreamSink(t, h.upstream)

	require.Len(t, h.proxy.secrets.Load().cands, hosted)

	type client struct {
		name string
		addr *net.TCPAddr
	}

	all := make([]client, clients)

	// Client c is user u<c> at an address of its own: its first hello is
	// scanned and costs c+1 verifications, every later one is hinted and costs
	// one.
	var wantVerifications int64

	for c := range clients {
		all[c] = client{
			name: fmt.Sprintf("u%02d", c),
			addr: &net.TCPAddr{IP: net.IPv4(203, 0, 113, byte(100+c)), Port: 47000 + c},
		}
		wantVerifications += int64(c+1) + rounds - 1
	}

	// Released together, so the first-round scans -- every one of which
	// verifies u00's Candidate, and all but one u01's -- overlap by
	// construction rather than by scheduling luck. That overlap is what lets
	// the race detector see a write to a shared Candidate: a throwaway write in
	// Verify was reported in 20 runs out of 20.
	var wg sync.WaitGroup

	start := make(chan struct{})

	for _, cl := range all {
		wg.Go(func() {
			<-start

			for round := range rounds {
				if err := handshakeFrom(h, cl.addr, cl.name, secrets[cl.name].Key); err != nil {
					t.Errorf("%s, round %d: %v", cl.name, round, err)

					return
				}
			}
		})
	}

	close(start)
	wg.Wait()

	assert.Equal(t, doorTally{
		verifications: wantVerifications,
		hinted:        clients * (rounds - 1),
		scanned:       clients,
	}, tallyOf(h.proxy))

	for _, cl := range all {
		assert.Equal(t, []string{cl.name}, h.proxy.hints.recall(cl.addr.IP), cl.name)
	}
}

// handshakeFrom is one ee client of name, from addr, through ServeConn: the
// hello, the server flight (checked against the key), the obfuscated frame, and
// the stream registered under name from addr. It returns once ServeConn has,
// so the hint has been written before the next hello. Safe to call from any
// goroutine: it reports errors instead of calling require.
func handshakeFrom(h *entryHarness, addr *net.TCPAddr, name string, key [SecretKeyLength]byte) error {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err //nolint: wrapcheck
	}

	defer listener.Close() //nolint: errcheck

	client, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		return err //nolint: wrapcheck
	}

	server, err := listener.Accept()
	if err != nil {
		client.Close() //nolint: errcheck

		return err //nolint: wrapcheck
	}

	done := make(chan struct{})

	go func() {
		defer close(done)

		h.proxy.ServeConn(remoteAddrConn{Conn: essentials.WrapNetConn(server), addr: addr})
	}()

	defer func() {
		client.Close() //nolint: errcheck
		<-done
	}()

	if err := client.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return err //nolint: wrapcheck
	}

	sessionID := make([]byte, 32)
	if _, err := rand.Read(sessionID); err != nil {
		return err //nolint: wrapcheck
	}

	hello, err := testclient.ClientHello(key, govCoverHost, sessionID)
	if err != nil {
		return err //nolint: wrapcheck
	}

	if _, err := client.Write(hello); err != nil {
		return err //nolint: wrapcheck
	}

	_, flight, err := testclient.ReadServerFlight(client)
	if err != nil {
		return fmt.Errorf("no server flight: %w", err)
	}

	// The server random is the digest over the client random and the flight,
	// keyed with the secret the door matched.
	masked := slices.Clone(flight)
	clear(masked[fake.RandomOffset : fake.RandomOffset+fake.RandomLen])

	digest := hmac.New(sha256.New, key[:])
	digest.Write(hello[fake.RandomOffset : fake.RandomOffset+fake.RandomLen])
	digest.Write(masked)

	if !hmac.Equal(digest.Sum(nil), flight[fake.RandomOffset:fake.RandomOffset+fake.RandomLen]) {
		return errors.New("the server flight is not signed with the client's key")
	}

	frame, err := testclient.ObfuscatedFrame(key, obfuscation.TagPaddedIntermediate, 2)
	if err != nil {
		return err //nolint: wrapcheck
	}

	if _, err := client.Write(testclient.ApplicationRecord(frame)); err != nil {
		return err //nolint: wrapcheck
	}

	if !registeredFrom(h.proxy, name, addr.IP) {
		return fmt.Errorf("never registered as %s from %v", name, addr.IP)
	}

	return nil
}

// registeredFrom waits a little for a live stream under name counted from ip.
func registeredFrom(p *Proxy, name string, ip net.IP) bool {
	want, ok := addressKeyOf(ip)
	if !ok {
		return false
	}

	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(time.Millisecond) {
		p.liveMu.Lock()

		for stream := range p.liveConns[name] {
			if stream.addrCounted && stream.addrKey == want {
				p.liveMu.Unlock()

				return true
			}
		}

		p.liveMu.Unlock()
	}

	return false
}
