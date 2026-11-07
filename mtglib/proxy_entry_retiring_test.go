package mtglib

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"maps"
	"net"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Arman2122/mtg-proxy/essentials"
	"github.com/Arman2122/mtg-proxy/mtglib/internal/tls/fake"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The FakeTLS door with retiring keys (spec §3.1, tests D1-D4b, D7 and D13): an
// old link is tried after every primary, a hinted name tries its retiring keys
// after its primary, an expired candidate is never verified but is still
// charged, and the server's flight is signed with the key that matched.

// rotationClockAt gives p a rotation clock on a source the test moves, starting
// at at, and returns the source.
func rotationClockAt(p *Proxy, at time.Time) *steppedClock {
	source := newSteppedClock(at)
	p.rotation = NewRotationClock(source.now, nil)

	return source
}

// rotateTo swaps secrets in with the retiring entries through ReplaceSecrets, so
// the set is built at the proxy's clock, and requires that every entry was kept.
func rotateTo(t testing.TB, p *Proxy, secrets map[string]Secret, retiring ...RetiringSecret) *secretSet {
	t.Helper()

	require.NoError(t, p.ReplaceSecrets(SecretConfig{Secrets: secrets, Retiring: retiring}))

	set := p.secrets.Load()
	require.Len(t, set.retiring, len(retiring), "every retiring entry is kept")

	return set
}

// freshHello is a hello made with key for sni under a session id of its own,
// so that no two are replays of each other.
func freshHello(t testing.TB, key [SecretKeyLength]byte, sni string) []byte {
	t.Helper()

	sessionID := make([]byte, 32)

	_, err := rand.Read(sessionID)
	require.NoError(t, err)

	return fakeTLSClientHello(t, key, sni, sessionID)
}

// flightSignedWith reports whether flight carries the FakeTLS digest made with
// key: assertFakeTLSDigest as a value, so a test can also say which key did NOT
// sign it.
func flightSignedWith(key [SecretKeyLength]byte, clientRandom, flight []byte) bool {
	if len(flight) < fake.RandomOffset+fake.RandomLen {
		return false
	}

	masked := slices.Clone(flight)
	clear(masked[fake.RandomOffset : fake.RandomOffset+fake.RandomLen])

	digest := hmac.New(sha256.New, key[:])
	digest.Write(clientRandom)
	digest.Write(masked)

	return hmac.Equal(digest.Sum(nil), flight[fake.RandomOffset:fake.RandomOffset+fake.RandomLen])
}

// fakeTLSAttemptFrom is fakeTLSAttempt from the address addr: the door keys its
// hints by it, and the harness's own loopback peer gets none.
func (h *entryHarness) fakeTLSAttemptFrom(t *testing.T, hello []byte, addr net.Addr) (*streamContext, bool) {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	defer listener.Close() //nolint: errcheck

	client, err := net.Dial("tcp", listener.Addr().String())
	require.NoError(t, err)

	t.Cleanup(func() { client.Close() }) //nolint: errcheck

	server, err := listener.Accept()
	require.NoError(t, err)

	t.Cleanup(func() { server.Close() }) //nolint: errcheck

	_, err = client.Write(hello)
	require.NoError(t, err)

	ctx := newStreamContext(h.proxy.ctx, h.proxy.logger, remoteAddrConn{Conn: essentials.WrapNetConn(server), addr: addr})
	t.Cleanup(ctx.Close)

	return ctx, h.proxy.doFakeTLSHandshake(ctx)
}

// TestAnOldLinkCompletesARealHandshake is D1. alice is rotated from K1 to K2,
// and K1 is retiring. A K1 client is admitted under alice, its server flight
// is signed with K1 and not with K2, the inner obfuscated2 handshake runs on K1
// and the stream relays. Its whole masked trace is the trace of a proxy whose
// primary is K1: the repo has no deterministic-noise seam, so the masked golden
// trace plus the digest is what "byte-identical" means here.
func TestAnOldLinkCompletesARealHandshake(t *testing.T) {
	t.Parallel()

	k1, k2 := keyFilledFrom(0xa0), keyFilledFrom(0x30)
	old, next := eeSecretOf(k1, candidatesCover), eeSecretOf(k2, candidatesCover)
	bob := eeSecretOf(keyFilledFrom(0x60), candidatesCover)
	until := rotationAt(time.Hour)

	rotated := newEntryHarness(t, map[string]Secret{"alice": old, "bob": bob}, nil)
	rotationClockAt(rotated.proxy, rotationNow)
	set := rotateTo(t, rotated.proxy, map[string]Secret{"alice": next, "bob": bob}, retire("alice", old, until))

	require.Equal(t, 2, set.primaryEnd(), "alice's K2 and bob's key, then K1")
	require.Len(t, set.cands, 3)

	t.Run("the door", func(t *testing.T) {
		hello := freshHello(t, k1, candidatesCover)
		clientRandom := slices.Clone(hello[fake.RandomOffset : fake.RandomOffset+fake.RandomLen])

		ctx, ok, flight := rotated.fakeTLSAttemptFlight(t, hello)
		require.True(t, ok, "the old link is admitted during its overlap")

		assert.Equal(t, "alice", ctx.secretName, "billed to the name")
		assert.Equal(t, k1[:], ctx.matchedSecretKey, "the key the client holds")
		assert.Same(t, &set.retiring[0].secret.Key[0], &ctx.matchedSecretKey[0], "a slice into the set's own entry")
		assert.Equal(t, until, ctx.retiringUntil, "and the entry's until")
		assert.Same(t, set, ctx.attrSet)

		assertFakeTLSDigest(t, k1, clientRandom, flight)
		assert.True(t, flightSignedWith(k1, clientRandom, flight), "the flight is signed with K1")
		assert.False(t, flightSignedWith(k2, clientRandom, flight), "and not with alice's primary, K2")
	})

	t.Run("end to end, against a proxy whose primary is K1", func(t *testing.T) {
		reference := newEntryHarness(t, map[string]Secret{"alice": old, "bob": bob}, nil)

		for _, h := range []*entryHarness{rotated, reference} {
			h.proxy.doppelGanger.Run()
			t.Cleanup(h.proxy.doppelGanger.Shutdown)
		}

		// goldenFlightPhase checks the digest with K1, decodes the frame the
		// proxy hands Telegram (the inner handshake ran on K1, or the client's DC
		// would not survive) and reads relayed traffic back. Each harness has
		// its own replay cache, so the fixed session id it uses is no replay.
		want := goldenFlightPhase(t, reference, k1)
		got := goldenFlightPhase(t, rotated, k1)

		assert.Equal(t, want, got, "the old link's whole masked trace is a K1 primary's")
	})
}

// TestAnOldLinkPastUntilIsFrontedLikeAWrongSecret is D2. Once the clock reaches
// until, with no swap since, the old link matches nothing: the cover site gets
// exactly the bytes a proxy that never knew K1 sends it, and the expired
// candidate, still in the set, is never verified.
func TestAnOldLinkPastUntilIsFrontedLikeAWrongSecret(t *testing.T) {
	t.Parallel()

	ec := fakeTLSDoor()
	old, next := ec.secret(t), ec.secret(t)
	until := rotationAt(time.Hour)

	rotated := ec.harness(t, map[string]Secret{"alice": old}, nil)
	clock := rotationClockAt(rotated.proxy, rotationNow)
	set := rotateTo(t, rotated.proxy, map[string]Secret{"alice": next}, retire("alice", old, until))
	rotatedCover := newCoverSite(t, rotated)

	_, ok := rotated.fakeTLSAttempt(t, freshHello(t, old.Key, govCoverHost))
	require.True(t, ok, "the control: the old link is admitted during its overlap")

	// At until exactly: an overlap ends at its until, as buildRetiring and
	// accepts say.
	clock.set(until)

	wrong := ec.harness(t, map[string]Secret{"alice": next}, nil)
	wrongCover := newCoverSite(t, wrong)

	hello := freshHello(t, old.Key, govCoverHost)

	before := tallyOf(rotated.proxy)
	fromRotated := rotatedCover.front(t, rotated, hello)

	assert.Equal(t, doorTally{verifications: 1, unmatched: 1}, tallyOf(rotated.proxy).minus(before),
		"alice's primary is verified; the expired candidate is passed over unverified")

	fromWrong := wrongCover.front(t, wrong, hello)

	assert.Equal(t, doorTally{verifications: 1, unmatched: 1}, tallyOf(wrong.proxy), "the reference: a wrong secret")
	assert.Equal(t, hello, fromRotated, "the cover site gets the client's own bytes")
	assert.Equal(t, fromWrong, fromRotated, "the same bytes as for a wrong secret")
	assert.Equal(t, 1, rotated.events.frontings())

	assert.Same(t, set, rotated.proxy.secrets.Load(), "no swap ran: the expired candidate is still in the set")
	assert.Len(t, set.candRetiring, 1)
}

// TestARetiringCandidateExpiresByItsOwnEntry: the door judges a retiring
// candidate by the until of the entry it stands for. A dd retiring entry is no
// candidate, so when one sorts before an ee one (same name, later until), the
// candidate's offset past primaryEnd() is not its index into retiring: alice's
// ee old key, expired at +1h, must be fronted unverified even though alice's dd
// old key, at index 0, runs to +2h; and bob's ee old key, unexpired until +3h,
// must still be admitted though the entry at its offset (alice's ee) has
// expired.
func TestARetiringCandidateExpiresByItsOwnEntry(t *testing.T) {
	t.Parallel()

	ec := fakeTLSDoor()
	alice, bob := ec.secret(t), ec.secret(t)
	aliceOldEE, bobOldEE := ec.secret(t), ec.secret(t)
	aliceOldDD := ddSecretOf(keyFilledFrom(0x91))

	h := newEntryHarness(t, map[string]Secret{"alice": aliceOldEE, "bob": bobOldEE}, nil)
	clock := rotationClockAt(h.proxy, rotationNow)
	set := rotateTo(t, h.proxy, map[string]Secret{"alice": alice, "bob": bob},
		retire("alice", aliceOldDD, rotationAt(2*time.Hour)),
		retire("alice", aliceOldEE, rotationAt(time.Hour)),
		retire("bob", bobOldEE, rotationAt(3*time.Hour)))

	require.Equal(t, []int{1, 2}, set.candRetiring, "alice's dd entry is retiring[0] and no candidate")

	clock.set(rotationAt(time.Hour))

	before := tallyOf(h.proxy)
	_, ok := h.fakeTLSAttempt(t, freshHello(t, aliceOldEE.Key, govCoverHost))
	assert.False(t, ok, "alice's ee old key has reached its own until")
	assert.Equal(t, doorTally{verifications: 3, unmatched: 1}, tallyOf(h.proxy).minus(before),
		"two primaries and bob's old key; alice's expired one is never verified")

	ctx, ok := h.fakeTLSAttempt(t, freshHello(t, bobOldEE.Key, govCoverHost))
	require.True(t, ok, "bob's old key runs to +3h")
	assert.Equal(t, "bob", ctx.secretName)
}

// TestAPrimaryMatchCostsTheSameWithRetiringEntries is D3: retiring candidates
// come after every primary, so a primary's hello is verified as many times with
// retiring entries as without, and an old link after every primary.
func TestAPrimaryMatchCostsTheSameWithRetiringEntries(t *testing.T) {
	t.Parallel()

	ec := fakeTLSDoor()
	primaries := map[string]Secret{"alice": ec.secret(t), "bob": ec.secret(t), "carol": ec.secret(t)}
	oldAlice, oldBob := ec.secret(t), ec.secret(t)

	plain := newEntryHarness(t, primaries, nil)
	rotated := newEntryHarness(t, primaries, nil)
	rotationClockAt(rotated.proxy, rotationNow)
	set := rotateTo(t, rotated.proxy, primaries,
		retire("alice", oldAlice, rotationAt(time.Hour)), retire("bob", oldBob, rotationAt(2*time.Hour)))

	require.Len(t, set.cands, 5)

	verificationsOf := func(h *entryHarness, key [SecretKeyLength]byte) int64 {
		t.Helper()

		before := tallyOf(h.proxy)

		_, ok := h.fakeTLSAttempt(t, freshHello(t, key, govCoverHost))
		require.True(t, ok)

		return tallyOf(h.proxy).minus(before).verifications
	}

	for i, name := range []string{"alice", "bob", "carol"} {
		key := primaries[name].Key

		assert.EqualValues(t, i+1, verificationsOf(plain, key), "%s without retiring entries", name)
		assert.EqualValues(t, i+1, verificationsOf(rotated, key), "%s costs the same with them", name)
	}

	assert.EqualValues(t, 4, verificationsOf(rotated, oldAlice.Key), "alice's old key comes after every primary")
	assert.EqualValues(t, 5, verificationsOf(rotated, oldBob.Key), "and bob's after it")
}

// hintedRotation is a budget harness with hints on, hosting decoys and alice,
// with alice rotated from old to primary at the proxy's clock. Every key is ee
// on govCoverHost unless primary says otherwise.
func hintedRotation(t *testing.T, decoys int, old, primary Secret) (*entryHarness, *secretSet) {
	t.Helper()

	ec := fakeTLSDoor()
	secrets := map[string]Secret{"alice": old}

	for i := range decoys {
		secrets[fmt.Sprintf("d%02d", i)] = ec.secret(t)
	}

	h, _ := budgetHarness(t, secrets, nil, roomyBudget())
	h.proxy.hints = newMatchHints(h.proxy.ctx)
	rotationClockAt(h.proxy, rotationNow)

	rotated := maps.Clone(secrets)
	rotated["alice"] = primary

	return h, rotateTo(t, h.proxy, rotated, retire("alice", old, rotationAt(time.Hour)))
}

// spendBudget spends both the place's bucket and the process's, so that from
// here on no scan can be paid for and only a hinted hello gets in.
func spendBudget(t *testing.T, h *entryHarness, place string) {
	t.Helper()

	b := h.proxy.scanBudget

	require.Equal(t, budgetDeniedIP, drainBudget(t, b, net.ParseIP(place), 12, 1))
	require.Equal(t, budgetDeniedGlobal, drainBudget(t, b, nil, 12, 1))
}

// TestAHintedOldLinkMatchesInTwoVerifications is D4. An old-link client admitted
// once leaves the hint "alice". Next time it is verified against alice's primary
// (a miss) and then her retiring key (the match): two verifications and no
// scan, so it gets in with every bucket spent.
func TestAHintedOldLinkMatchesInTwoVerifications(t *testing.T) {
	t.Parallel()

	const (
		place  = "203.0.113.90"
		decoys = 20
	)

	ec := fakeTLSDoor()
	old, next := ec.secret(t), ec.secret(t)
	h, set := hintedRotation(t, decoys, old, next)

	require.Len(t, set.cands, decoys+2)

	assert.Equal(t, doorTally{verifications: decoys + 2, scanned: 1},
		connectFrom(t, h, ec, tcpFrom(place, 55001), "alice", old.Key),
		"unhinted, the old link is found by the scan, after every primary")
	assert.Equal(t, []string{"alice"}, h.proxy.hints.recall(net.ParseIP(place)), "the hint is the name")

	spendBudget(t, h, place)

	assert.Equal(t, doorTally{verifications: 2, hinted: 1},
		connectFrom(t, h, ec, tcpFrom(place, 55002), "alice", old.Key),
		"alice's primary, a miss, then her retiring key: no scan, no charge")

	assert.Equal(t, doorTally{verifications: 1, hinted: 1},
		connectFrom(t, h, ec, tcpFrom(place, 55003), "alice", next.Key),
		"and the new link from the same place is found first")
}

// TestAnEeToDdRotationKeepsTheOldLinksHint is D4b. alice's new primary is dd,
// which is no FakeTLS candidate, and her old ee key is retiring. A returning
// old-link client is still found through its hint, in one verification with no
// scan: the hint is resolved to the name's retiring positions whether or not
// its primary is a candidate.
func TestAnEeToDdRotationKeepsTheOldLinksHint(t *testing.T) {
	t.Parallel()

	const (
		place  = "203.0.113.91"
		decoys = 20
	)

	ec := fakeTLSDoor()
	old := ec.secret(t)
	h, set := hintedRotation(t, decoys, old, ddSecretOf(keyFilledFrom(0x77)))

	_, candidate := set.candByName["alice"]
	require.False(t, candidate, "a dd primary is no candidate")
	require.Len(t, set.retiringCands["alice"], 1)

	assert.Equal(t, doorTally{verifications: decoys + 1, scanned: 1},
		connectFrom(t, h, ec, tcpFrom(place, 55101), "alice", old.Key),
		"unhinted, the old link is found by the scan, after every primary")
	require.Equal(t, []string{"alice"}, h.proxy.hints.recall(net.ParseIP(place)))

	spendBudget(t, h, place)

	assert.Equal(t, doorTally{verifications: 1, hinted: 1},
		connectFrom(t, h, ec, tcpFrom(place, 55102), "alice", old.Key),
		"the hint resolves to alice's retiring position alone: one verification, no scan")
}

// TestAHintedOldLinkPastUntilIsNotVerified: the hinted path passes over an
// expired retiring candidate at primaryEnd() itself, the first retiring
// position, as it does any later one.
func TestAHintedOldLinkPastUntilIsNotVerified(t *testing.T) {
	t.Parallel()

	const place = "198.51.100.91"

	ec := fakeTLSDoor()
	old := ec.secret(t)

	h, _ := budgetHarness(t, map[string]Secret{"alice": old, "bob": ec.secret(t)}, nil, roomyBudget())
	h.proxy.hints = newMatchHints(h.proxy.ctx)

	clock := rotationClockAt(h.proxy, rotationNow)
	set := rotateTo(t, h.proxy, map[string]Secret{"alice": ec.secret(t), "bob": ec.secret(t)},
		retire("alice", old, rotationAt(time.Hour)))

	require.Equal(t, []int{set.primaryEnd()}, set.retiringCands["alice"], "alice's old key is the first retiring position")

	h.proxy.hints.remember(net.ParseIP(place), "alice")
	clock.set(rotationAt(time.Hour))

	assert.Equal(t, doorTally{verifications: 2, unmatched: 1}, refusedFrom(t, h, tcpFrom(place, 56101), old.Key),
		"alice's primary from the hint, bob's from the scan; the expired old key is never verified")
}

// TestABannedPlaceIsNotHintedToARetiringKey: a ban skips the hinted name
// whole -- its primary and its retiring keys -- so a banned place holding an
// old link is scanned (and charged), not hinted.
func TestABannedPlaceIsNotHintedToARetiringKey(t *testing.T) {
	t.Parallel()

	const place = "203.0.113.32"

	ec := fakeTLSDoor()
	old := ec.secret(t)

	h, _ := budgetHarness(t, map[string]Secret{"alice": old, "bob": ec.secret(t)}, nil, roomyBudget())
	h.proxy.hints = newMatchHints(h.proxy.ctx)
	rotationClockAt(h.proxy, rotationNow)
	set := rotateTo(t, h.proxy, map[string]Secret{"alice": ec.secret(t), "bob": ec.secret(t)},
		retire("alice", old, rotationAt(time.Hour)))

	require.Len(t, set.cands, 3)

	mustBan(t, h.proxy, "alice", `{"ips":["`+place+`"]}`)

	// A hint the ban could not forget: written after it.
	h.proxy.hints.remember(net.ParseIP(place), "alice")

	assert.Equal(t, doorTally{verifications: 3, scanned: 1}, refusedFrom(t, h, tcpFrom(place, 53101), old.Key),
		"scanned to the old key and refused as banned; never verified on the hint")
}

// TestHintedPositionsAreCappedAt32: sixteen hinted names, each with a primary
// and four retiring keys, resolve to their first 32 positions in hint order,
// each name's primary first. A key past the cap is still found, by the scan.
func TestHintedPositionsAreCappedAt32(t *testing.T) {
	t.Parallel()

	const (
		place = "203.0.113.95"
		names = 16
	)

	ec := fakeTLSDoor()
	primaries := make(map[string]Secret, names)

	var retiring []RetiringSecret

	for i := range names {
		name := fmt.Sprintf("n%02d", i)
		primaries[name] = ec.secret(t)

		for j := range MaxRetiringPerSecret {
			retiring = append(retiring, retire(name, ec.secret(t), rotationAt(time.Duration(j+1)*time.Hour)))
		}
	}

	h := newEntryHarness(t, primaries, nil)
	h.proxy.hints = newMatchHints(h.proxy.ctx)
	rotationClockAt(h.proxy, rotationNow)
	set := rotateTo(t, h.proxy, primaries, retiring...)

	require.Len(t, set.cands, names*(1+MaxRetiringPerSecret))

	ip := net.ParseIP(place)

	for i := range names {
		h.proxy.hints.remember(ip, fmt.Sprintf("n%02d", i))
	}

	recalled := h.proxy.hints.recall(ip)
	require.Len(t, recalled, names, "sixteen names, most recent first")

	var all []int

	for _, name := range recalled {
		all = append(all, set.candByName[name])
		all = append(all, set.retiringCands[name]...)
	}

	want := all[:32]

	ctx := &streamContext{clientSocket: remoteAddrConn{addr: tcpFrom(place, 57000)}}
	stranger := parsedHello(t, freshHello(t, ec.secret(t).Key, govCoverHost), govCoverHost)

	assert.Equal(t, want, h.proxy.hintedPositions(ctx, stranger, set),
		"the first 32 positions, in hint order, each name's primary before its retiring keys")

	// Six names of five positions are 30; the seventh name's primary and first
	// retiring key make 32, and its last retiring key is past the cap.
	seventh := set.retiringCands[recalled[6]]
	require.Equal(t, []int{set.candByName[recalled[6]], seventh[0]}, want[30:])

	target := seventh[len(seventh)-1]
	require.NotContains(t, want, target, "the key is past the cap")

	scanned := 0

	for pos := 0; pos <= target; pos++ {
		if !slices.Contains(want, pos) {
			scanned++
		}
	}

	key := set.retiring[set.candRetiring[target-set.primaryEnd()]].secret.Key
	before := tallyOf(h.proxy)

	ctx2, ok := h.fakeTLSAttemptFrom(t, freshHello(t, key, govCoverHost), tcpFrom(place, 57001))
	require.True(t, ok)

	assert.Equal(t, recalled[6], ctx2.secretName)
	assert.Equal(t, doorTally{verifications: int64(32 + scanned), scanned: 1}, tallyOf(h.proxy).minus(before),
		"32 hinted verifications that miss, then the scan finds it")
}

// TestAHostChangingRotationPassesTheOldHostUntilItsEntryLeaves is D7. alice moves
// from an old cover host to a new one. During the overlap the old host passes
// the SNI gate. Past until, before any swap, it still passes it (the expired key
// matches nothing and is fronted to the host it named). The swap that drops the
// entry takes the host off the gate: the hello is then fronted to frontHost.
func TestAHostChangingRotationPassesTheOldHostUntilItsEntryLeaves(t *testing.T) {
	t.Parallel()

	// IP literals, so nothing is resolved; the host asked for is the host
	// dialled (dialRecorder).
	const newHost, oldHost = "127.0.0.2", "127.0.0.3"

	old := eeSecretOf(keyFilledFrom(15), oldHost)
	next := eeSecretOf(keyFilledFrom(75), newHost)
	until := rotationAt(time.Hour)

	h := newEntryHarness(t, map[string]Secret{"alice": old}, nil)

	recorder := &dialRecorder{fakeNetwork: h.network}
	h.proxy.network = recorder
	h.proxy.domainFrontingHost = ""
	h.proxy.domainFrontingPort = 443

	clock := rotationClockAt(h.proxy, rotationNow)
	set := rotateTo(t, h.proxy, map[string]Secret{"alice": next}, retire("alice", old, until))

	require.Equal(t, newHost, set.frontHost)
	require.Equal(t, []string{newHost, oldHost}, set.hostnames)

	ctx, ok := h.fakeTLSAttempt(t, freshHello(t, old.Key, oldHost))
	require.True(t, ok, "during the overlap the old host passes the gate and the old key is admitted")
	assert.Equal(t, "alice", ctx.secretName)
	assert.Empty(t, recorder.dialed())

	clock.set(until)

	_, ok = h.fakeTLSAttempt(t, freshHello(t, old.Key, oldHost))
	assert.False(t, ok)
	assert.Equal(t, []string{oldHost + ":443"}, recorder.dialed(),
		"past until, before the swap: past the gate, matching nothing, fronted to the host it named")

	require.NoError(t, h.proxy.ReplaceSecrets(h.proxy.secrets.Load().toConfig()))
	require.Empty(t, h.proxy.secrets.Load().retiring, "the swap at until drops the entry")

	_, ok = h.fakeTLSAttempt(t, freshHello(t, old.Key, oldHost))
	assert.False(t, ok)
	assert.Equal(t, []string{oldHost + ":443", newHost + ":443"}, recorder.dialed(),
		"after the swap the old host fails the gate: fronted to frontHost")
}

// TestRetiringCandidatesAreChargedLikeAnyOther is D13: the scan is charged for
// len(cands) - tried candidates, retiring ones included. An expired candidate
// still in the set is charged and never verified, whether the scan reaches it
// or a hint does.
func TestRetiringCandidatesAreChargedLikeAnyOther(t *testing.T) {
	t.Parallel()

	const place = "198.51.100.90"

	ec := fakeTLSDoor()
	alice, bob := ec.secret(t), ec.secret(t)

	h, _ := budgetHarness(t, map[string]Secret{"alice": alice, "bob": bob}, nil, roomyBudget())
	h.proxy.hints = newMatchHints(h.proxy.ctx)

	clock := rotationClockAt(h.proxy, rotationNow)
	set := rotateTo(t, h.proxy, map[string]Secret{"alice": ec.secret(t), "bob": ec.secret(t)},
		retire("alice", alice, rotationAt(2*time.Hour)), retire("bob", bob, rotationAt(time.Hour)))

	require.Len(t, set.cands, 4, "two primaries, then alice's and bob's old keys")

	// bob's old key expires; no swap runs, so it is still a candidate.
	clock.set(rotationAt(time.Hour))

	// What one candidate costs for this hello, as reserve prices it.
	stranger := ec.secret(t).Key
	blocks := min(max(parsedHello(t, freshHello(t, stranger, govCoverHost), govCoverHost).Blocks(), minCostBlocks), maxScanBlocks)

	charged := func(t *testing.T, port int) (doorTally, float64, float64) {
		t.Helper()

		global0, address0 := budgetLevels(t, h, place)
		tally := refusedFrom(t, h, tcpFrom(place, port), stranger)
		global1, address1 := budgetLevels(t, h, place)

		return tally, global0 - global1, address0 - address1
	}

	tally, global, address := charged(t, 56001)

	assert.Equal(t, doorTally{verifications: 3, unmatched: 1}, tally,
		"unhinted: every candidate but the expired one is verified")
	assert.InDelta(t, float64(4*blocks), global, 1e-9, "and all four are charged, retiring and expired included")
	assert.InDelta(t, float64(4*blocks), address, 1e-9)

	h.proxy.hints.remember(net.ParseIP(place), "bob")

	tally, global, address = charged(t, 56002)

	assert.Equal(t, doorTally{verifications: 3, unmatched: 1}, tally,
		"bob's primary from the hint, then alice's two keys from the scan; bob's expired key is never verified")
	assert.InDelta(t, float64(3*blocks), global, 1e-9,
		"the one hinted verification is not charged; the expired hinted candidate is")
	assert.InDelta(t, float64(3*blocks), address, 1e-9)
}

// countReads gives p a rotation clock that counts its reads, always at
// rotationNow.
func countReads(p *Proxy) *atomic.Int64 {
	var reads atomic.Int64

	p.rotation = NewRotationClock(func() time.Time {
		reads.Add(1)

		return rotationNow
	}, nil)

	return &reads
}

// TestAScanWithoutRetiringNeverReadsTheClock: on a set with no retiring entry
// the door never reads the rotation clock, whatever the hello does. On a set
// with them it reads it once for a hello that reaches a retiring position,
// however many it reaches, through the hints and the scan alike, and never for
// one that does not.
func TestAScanWithoutRetiringNeverReadsTheClock(t *testing.T) {
	t.Parallel()

	const place = "203.0.113.97"

	ec := fakeTLSDoor()
	alice, bob, carol := ec.secret(t), ec.secret(t), ec.secret(t)
	primaries := map[string]Secret{"alice": alice, "bob": bob, "carol": carol}

	type hello struct {
		name   string
		key    [SecretKeyLength]byte
		hinted bool
		ok     bool
		reads  int64
	}

	run := func(t *testing.T, h *entryHarness, reads *atomic.Int64, hellos []hello) {
		t.Helper()

		h.proxy.hints.remember(net.ParseIP(place), "alice")

		for i, tc := range hellos {
			before := reads.Load()

			var ok bool

			if tc.hinted {
				_, ok = h.fakeTLSAttemptFrom(t, freshHello(t, tc.key, govCoverHost), tcpFrom(place, 58000+i))
			} else {
				_, ok = h.fakeTLSAttempt(t, freshHello(t, tc.key, govCoverHost))
			}

			assert.Equal(t, tc.ok, ok, tc.name)
			assert.Equal(t, tc.reads, reads.Load()-before, "clock reads, %s", tc.name)
		}
	}

	stranger := ec.secret(t).Key

	t.Run("no retiring entry", func(t *testing.T) {
		t.Parallel()

		h := newEntryHarness(t, primaries, nil)
		h.proxy.hints = newMatchHints(h.proxy.ctx)
		reads := countReads(h.proxy)

		run(t, h, reads, []hello{
			{"a match", carol.Key, false, true, 0},
			{"a miss", stranger, false, false, 0},
			{"a hinted match", alice.Key, true, true, 0},
			{"a hinted miss, then the scan's match", bob.Key, true, true, 0},
			{"a hinted miss, then the scan's miss", stranger, true, false, 0},
		})
	})

	t.Run("retiring entries", func(t *testing.T) {
		t.Parallel()

		h := newEntryHarness(t, primaries, nil)
		h.proxy.hints = newMatchHints(h.proxy.ctx)
		reads := countReads(h.proxy)

		oldAlice, oldBob := ec.secret(t), ec.secret(t)
		next := maps.Clone(primaries)
		next["alice"] = ec.secret(t)

		rotateTo(t, h.proxy, next,
			retire("alice", oldAlice, rotationAt(time.Hour)), retire("bob", oldBob, rotationAt(time.Hour)))

		run(t, h, reads, []hello{
			{"a primary match", carol.Key, false, true, 0},
			{"a miss, past two retiring positions", stranger, false, false, 1},
			{"an old link", oldBob.Key, false, true, 1},
			{"a hinted old link", oldAlice.Key, true, true, 1},
			{"a hinted miss, then the scan past a retiring position", stranger, true, false, 1},
		})
	})
}
