package mtglib

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The lifecycle of a rotation (spec §4, tests L1-L9): a swap closes exactly the
// streams whose key the new set no longer accepts, judged stream by stream; its
// fast path compares the keys the two sets HOLD, never what they accept at the
// swap's instant; the expiry sweep ends an overlap through that same swap and
// never waits for a reload; and registration refuses a key that expired with no
// swap at all.

// matchOfKey is what a door matches when a client of name holds key in set: the
// name's primary, or one of its retiring entries. The test fails when the set
// holds no such key for the name.
func matchOfKey(t testing.TB, set *secretSet, name string, key [SecretKeyLength]byte) secretMatch {
	t.Helper()

	i, ok := set.indexOf(name)
	require.True(t, ok, "the set holds %s", name)

	if set.secrets[i].Key == key {
		return set.primaryMatch(i)
	}

	for _, r := range set.retiringOf[i] {
		if set.retiring[r].secret.Key == key {
			return set.retiringMatch(r)
		}
	}

	t.Fatalf("the set holds no such key for %s", name)

	return secretMatch{}
}

// attributeOnKey attributes sc to name's key as a door that matched it in set
// does, and requires that attribution let it on.
func attributeOnKey(t testing.TB, p *Proxy, set *secretSet, sc *streamContext, name string, key [SecretKeyLength]byte) {
	t.Helper()

	require.Equal(t, DenyNone, p.attributeMatch(sc, set, matchOfKey(t, set, name, key)))
}

// registerOnKey registers a stream with no socket and no handshake that holds
// key under name, attributed from the set in force as a door would attribute
// it, and requires that it registered. Like registerFakeStream's, a stream
// closed here stays in the registry: there is no ServeConn to unregister it.
func registerOnKey(t testing.TB, p *Proxy, name string, key [SecretKeyLength]byte) *streamContext {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	sc := &streamContext{ctx: ctx, ctxCancel: cancel, logger: testLogger()}

	attributeOnKey(t, p, p.secrets.Load(), sc, name, key)
	require.Equal(t, DenyNone, p.tryRegisterConn(sc), "the stream of %s must register", name)

	return sc
}

// heldRetiring is how many retiring entries the set in force holds. A count,
// never the entries: a failed assertion on them would print their keys.
func heldRetiring(p *Proxy) int {
	return len(p.secrets.Load().retiring)
}

// installAfterSecretStoreHook replaces the seam a swap calls right after it
// stores its set, and puts it back. The seam is a package variable, so a test
// that uses it is not parallel.
func installAfterSecretStoreHook(t *testing.T, hook func(*secretSet)) {
	t.Helper()

	previous := afterSecretStoreHook
	afterSecretStoreHook = hook

	t.Cleanup(func() { afterSecretStoreHook = previous })
}

// skipRecord keeps the names closeStaleConns' fast path skipped, written from
// whichever goroutine ran the swap.
type skipRecord struct {
	mu    sync.Mutex
	names []string
}

func (r *skipRecord) add(name string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.names = append(r.names, name)
}

func (r *skipRecord) skipped() []string {
	r.mu.Lock()
	defer r.mu.Unlock()

	return slices.Clone(r.names)
}

// lifecycle is alice, rotated or about to be, and bob, who is never rotated,
// on a hand-built proxy with a rotation clock the test moves and a log it
// reads.
type lifecycle struct {
	p     *Proxy
	clock *steppedClock
	log   *rotationLog
	old   Secret    // alice's key before the rotation: K1
	next  Secret    // alice's key after it: K2
	bob   Secret    // bob's one key
	until time.Time // when K1's overlap ends
}

func newLifecycle(t *testing.T) *lifecycle {
	t.Helper()

	l := &lifecycle{
		old:   GenerateSecret("alice.example.com"),
		next:  GenerateSecret("alice.example.com"),
		bob:   GenerateSecret("bob.example.com"),
		log:   &rotationLog{},
		until: rotationAt(time.Hour),
	}

	l.p = newReloadTestProxy(map[string]Secret{"alice": l.old, "bob": l.bob})
	l.p.logger = rotationLogger{log: l.log}
	l.clock = rotationClockAt(l.p, rotationNow)

	return l
}

// rotated is the file after the rotation: alice on K2, K1 retiring until
// l.until, and bob as he was.
func (l *lifecycle) rotated() SecretConfig {
	return SecretConfig{
		Secrets:  map[string]Secret{"alice": l.next, "bob": l.bob},
		Retiring: []RetiringSecret{retire("alice", l.old, l.until)},
	}
}

// ended is the same file with the block gone: an overlap ended early, or a
// file the config layer read after until and left the expired block out of.
func (l *lifecycle) ended() SecretConfig {
	cfg := l.rotated()
	cfg.Retiring = nil

	return cfg
}

// rotate swaps the rotated file in and returns the set it built.
func (l *lifecycle) rotate(t *testing.T) *secretSet {
	t.Helper()

	cfg := l.rotated()

	return rotateTo(t, l.p, cfg.Secrets, cfg.Retiring...)
}

// stream registers a stream of name holding secret's key.
func (l *lifecycle) stream(t *testing.T, name string, secret Secret) *streamContext {
	t.Helper()

	return registerOnKey(t, l.p, name, secret.Key)
}

// reloadWith makes the proxy's reloader hand back cfg.
func (l *lifecycle) reloadWith(cfg SecretConfig) {
	l.p.reloader = func() (SecretConfig, error) { return cfg, nil }
}

// L1. A rotation keeps every live stream: the K1 streams from before it (K1
// is now retiring and still accepted), bob's, and the K2 streams that come
// after it, also across a reload of the unchanged file during the overlap.
func TestARotationKeepsEveryLiveStream(t *testing.T) {
	t.Parallel()

	l := newLifecycle(t)

	olds := []*streamContext{l.stream(t, "alice", l.old), l.stream(t, "alice", l.old)}
	bob := l.stream(t, "bob", l.bob)

	l.rotate(t)

	for i, sc := range olds {
		assert.NoError(t, sc.Err(), "K1 stream %d is kept: the new set accepts K1 until its until", i)
	}

	assert.NoError(t, bob.Err(), "bob's stream is kept")

	next := l.stream(t, "alice", l.next)
	onRetiring := l.stream(t, "alice", l.old)

	l.reloadWith(l.rotated())
	require.NoError(t, l.p.ReloadSecrets())

	for i, sc := range append(olds, next, onRetiring, bob) {
		assert.NoError(t, sc.Err(), "stream %d survives a reload of the unchanged file", i)
	}
}

// L2. The expiry sweep closes exactly the K1 streams, through the swap it runs
// and closeStaleConns' held-key judgment: the K2 streams and bob's stay, and the
// name never takes the fast path. Nothing but the clock moves: no reload, no
// mutation, only the maintenance loop on a shortened sweep.
func TestTheExpirySweepClosesExactlyTheOldKeyStreams(t *testing.T) {
	t.Parallel()

	l := newLifecycle(t)
	l.rotate(t)

	olds := []*streamContext{l.stream(t, "alice", l.old), l.stream(t, "alice", l.old)}
	next := l.stream(t, "alice", l.next)
	bob := l.stream(t, "bob", l.bob)

	skips := &skipRecord{}
	l.p.staleSkipHook = skips.add

	// The overlap ends at its until exactly.
	l.clock.set(l.until)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	l.p.startMaintenanceEvery(ctx, 10*time.Millisecond, time.Hour, time.Hour)

	for i, sc := range olds {
		require.True(t, awaitClosed(sc, 3*time.Second), "the sweep closes K1 stream %d", i)
	}

	assert.NoError(t, next.Err(), "the K2 stream stays")
	assert.NoError(t, bob.Err(), "bob's stream stays")

	set := l.p.secrets.Load()
	assert.Zero(t, len(set.retiring), "the sweep's swap dropped the expired entry")
	assert.True(t, set.retiringNext.IsZero())

	assert.NotContains(t, skips.skipped(), "alice", "alice's held keys changed: never the fast path")
	assert.Contains(t, skips.skipped(), "bob", "the seam is wired: bob's held keys did not change")
}

// L2b (B1 of the review). The unchanged file reloaded after until, before any
// sweep, closes exactly the K1 streams, and so does the sweep alone, and so
// does the sweep after a reload that held the lock and failed. In every variant
// no K1 stream survives, and a later unrelated swap leaves the K2 streams open.
func TestAReloadAfterUntilClosesTheOldKeyStreams(t *testing.T) {
	t.Parallel()

	type streams struct {
		olds      []*streamContext
		next, bob *streamContext
	}

	setup := func(t *testing.T) (*lifecycle, streams) {
		t.Helper()

		l := newLifecycle(t)
		l.rotate(t)

		return l, streams{
			olds: []*streamContext{l.stream(t, "alice", l.old), l.stream(t, "alice", l.old)},
			next: l.stream(t, "alice", l.next),
			bob:  l.stream(t, "bob", l.bob),
		}
	}

	verify := func(t *testing.T, l *lifecycle, s streams) {
		t.Helper()

		for i, sc := range s.olds {
			assert.ErrorIs(t, sc.Err(), context.Canceled, "no K1 stream survives: stream %d", i)
		}

		assert.NoError(t, s.next.Err(), "the K2 stream stays")
		assert.NoError(t, s.bob.Err(), "bob's stream stays")
		assert.Zero(t, heldRetiring(l.p), "K1 left the set")

		// A later swap that changes nothing about alice's keys.
		cfg := l.p.secrets.Load().toConfig()
		cfg.SecretAdTags = map[string][AdTagLength]byte{"alice": adTagFilled(7)}
		require.NoError(t, l.p.ReplaceSecrets(cfg))

		assert.NoError(t, s.next.Err(), "a later unrelated swap leaves the K2 stream open")
		assert.NoError(t, s.bob.Err())
	}

	t.Run("reload only, the expired block left out by the config layer", func(t *testing.T) {
		t.Parallel()

		l, s := setup(t)
		l.reloadWith(l.ended())
		l.clock.set(l.until.Add(time.Minute))

		require.NoError(t, l.p.ReloadSecrets())

		assert.Empty(t, ignoredLines(t, l.log), "the engine was never handed the entry, so it dropped nothing")
		verify(t, l, s)
	})

	t.Run("reload only, the expired block handed to the engine", func(t *testing.T) {
		t.Parallel()

		l, s := setup(t)
		l.reloadWith(l.rotated())
		l.clock.set(l.until.Add(time.Minute))

		require.NoError(t, l.p.ReloadSecrets())

		assert.Equal(t, []string{"info|alice|expired"}, ignoredLines(t, l.log), "the engine dropped it as expired")
		verify(t, l, s)
	})

	t.Run("sweep only", func(t *testing.T) {
		t.Parallel()

		l, s := setup(t)
		l.clock.set(l.until.Add(time.Minute))

		l.p.expireRetiring()

		verify(t, l, s)
	})

	t.Run("a failed reload holds the lock, then the sweep", func(t *testing.T) {
		t.Parallel()

		l, s := setup(t)

		entered, release := make(chan struct{}), make(chan struct{})
		l.p.reloader = func() (SecretConfig, error) {
			close(entered)
			<-release

			return SecretConfig{}, errors.New("the file does not parse")
		}

		l.clock.set(l.until.Add(time.Minute))

		reloaded := make(chan error, 1)

		go func() { reloaded <- l.p.ReloadSecrets() }()

		if !govAwait(entered, 5*time.Second) {
			close(release)
			t.Fatal("the reload never reached its reader")
		}

		swept := make(chan struct{})

		go func() {
			defer close(swept)

			l.p.expireRetiring()
		}()

		if !govAwait(swept, 2*time.Second) {
			close(release)
			t.Fatal("the sweep waited for the reload's lock")
		}

		for i, sc := range s.olds {
			assert.NoError(t, sc.Err(), "nothing is closed while the reload holds the lock: stream %d", i)
		}

		assert.Equal(t, 1, heldRetiring(l.p), "and K1 is still in the set")

		close(release)
		require.Error(t, <-reloaded, "the reload failed without swapping")

		l.p.expireRetiring()

		verify(t, l, s)
	})
}

// L3. A reload that ends the overlap before its until -- rotate-secret
// --end-overlap -- closes the K1 streams at once, and only those.
func TestAnEndOverlapReloadClosesThemAtOnce(t *testing.T) {
	t.Parallel()

	l := newLifecycle(t)
	l.rotate(t)

	olds := []*streamContext{l.stream(t, "alice", l.old), l.stream(t, "alice", l.old)}
	next := l.stream(t, "alice", l.next)
	bob := l.stream(t, "bob", l.bob)

	l.reloadWith(l.ended())
	require.NoError(t, l.p.ReloadSecrets())

	for i, sc := range olds {
		assert.ErrorIs(t, sc.Err(), context.Canceled, "K1 stream %d is closed at once", i)
	}

	assert.NoError(t, next.Err())
	assert.NoError(t, bob.Err())
	assert.Zero(t, heldRetiring(l.p))
}

// L4. A re-key with no overlap closes every K1 stream registered before the
// swap, as it always did, and keeps a K2 stream that registered between the
// swap's Store and its walk: that stream loaded the new set under liveMu and
// holds a key the new set accepts.
func TestARekeyWithoutOverlapClosesOnlyStreamsFromBeforeTheSwap(t *testing.T) { //nolint: paralleltest // swaps a package variable
	l := newLifecycle(t)

	olds := []*streamContext{l.stream(t, "alice", l.old), l.stream(t, "alice", l.old)}
	bob := l.stream(t, "bob", l.bob)

	var during *streamContext

	// The hook runs on this goroutine, inside the swap ReplaceSecrets makes.
	installAfterSecretStoreHook(t, func(set *secretSet) {
		if during != nil {
			return
		}

		ctx, cancel := context.WithCancel(context.Background())
		t.Cleanup(cancel)

		during = &streamContext{ctx: ctx, ctxCancel: cancel, logger: testLogger()}

		attributeOnKey(t, l.p, set, during, "alice", l.next.Key)
		require.Equal(t, DenyNone, l.p.tryRegisterConn(during), "the set stored is the set in force")
	})

	require.NoError(t, l.p.ReplaceSecrets(l.ended()))
	require.NotNil(t, during, "a K2 stream registered between the Store and the walk")

	for i, sc := range olds {
		assert.ErrorIs(t, sc.Err(), context.Canceled, "K1 stream %d, registered before the swap, is closed", i)
	}

	assert.NoError(t, during.Err(), "the K2 stream registered inside the window is kept")
	assert.True(t, streamRegistered(l.p, during))
	assert.NoError(t, bob.Err())
}

// L5, the retiring variant, through the real doors: the swap after attribution
// ends the overlap of the very key the stream matched. It is refused at
// registration as key_revoked and never enters the registry.
func TestARetiringKeyRevokedAfterAttributionIsRefused(t *testing.T) { //nolint: paralleltest // swaps a package variable
	for _, ec := range govEntryCases() {
		t.Run(ec.name, func(t *testing.T) {
			old, next := ec.secret(t), ec.secret(t)
			until := rotationAt(time.Hour)

			h := ec.harness(t, map[string]Secret{"alice": old}, nil)

			record := &denyProbeRecord{}
			h.proxy.logger = denyProbeLogger{record: record}

			rotationClockAt(h.proxy, rotationNow)
			set := rotateTo(t, h.proxy, map[string]Secret{"alice": next}, retire("alice", old, until))

			// Minted here: the hook runs on the stream's goroutine.
			cfg := set.toConfig()
			cfg.Retiring = nil

			var (
				fired      atomic.Bool
				hookedWith time.Time
				swapErr    error
			)

			installAfterAttributeHook(t, func(sc *streamContext) {
				if !fired.CompareAndSwap(false, true) {
					return
				}

				hookedWith = sc.retiringUntil
				swapErr = h.proxy.ReplaceSecrets(cfg)
			})

			client, done := dialProxyFrom(t, h, ec.policy, tcpFrom("203.0.113.9", 50001))
			ec.openEntry(t, client, old.Key)

			require.True(t, govAwait(done, govDenyBudget),
				"a stream whose retiring key was taken away after attribution must be refused, not relayed")

			require.True(t, fired.Load(), "the swap ran between attribution and admission")
			require.NoError(t, swapErr)
			require.True(t, until.Equal(hookedWith), "the stream was attributed to the retiring key")
			require.Zero(t, heldRetiring(h.proxy), "and the swap ended its overlap")

			assert.Equal(t, []string{"key_revoked"}, record.denyReasons())
			assert.Zero(t, liveStreamsOf(h.proxy, "alice"), "the stream never entered the registry")
			assert.Zero(t, h.network.telegramDials())
			assert.Zero(t, h.events.frontings(), "refused after the door's exchange, not fronted")
		})
	}
}

// L5b, the expiry variant: a complete swap that ends the stream's retiring key
// runs just before the registration takes liveMu. The stream is refused as
// key_revoked, is not in liveConns, and leaves the ledger as it found it.
//
// Two ways to end it. The clock reaching until with the sweep swapping is the
// plain one, but there the key is refused whichever set registration reads:
// the set the stream matched against judges the key at a fresh instant, past
// until, too. A swap that moves until into the past is the one that tells a set
// loaded above the hook from one loaded under the lock: the set the stream
// matched against still holds the key with its old, later until, and accepts
// it.
func TestAnExpiringKeyJustBeforeTheRegistrationLockIsRefused(t *testing.T) { //nolint: paralleltest // swaps a package variable
	for _, variant := range []struct {
		name   string
		expire func(t *testing.T, p *Proxy, clock *steppedClock, old Secret, until time.Time)
	}{
		{"the clock reaches until and the sweep swaps", func(_ *testing.T, p *Proxy, clock *steppedClock, _ Secret, until time.Time) {
			clock.set(until)
			p.expireRetiring()
		}},
		{"a swap moves until into the past", func(t *testing.T, p *Proxy, _ *steppedClock, old Secret, _ time.Time) {
			cfg := p.secrets.Load().toConfig()
			cfg.Retiring = []RetiringSecret{retire("alice", old, rotationAt(-time.Minute))}

			require.NoError(t, p.ReplaceSecrets(cfg))
		}},
	} {
		t.Run(variant.name, func(t *testing.T) {
			probe := newClientTableProbe(t, false)
			p := probe.proxy
			clock := rotationClockAt(p, rotationNow)

			old := p.secrets.Load().secrets[0]
			until := rotationAt(time.Hour)
			set := rotateTo(t, p, map[string]Secret{"alice": GenerateSecret("alice.example.com")}, retire("alice", old, until))

			// A place already held under K1: the swap's walk closes it.
			held := probe.stream(t, tcpFrom("198.51.100.7", 50001), 0)
			attributeOnKey(t, p, set, held, "alice", old.Key)
			require.Equal(t, DenyNone, p.tryRegisterConn(held))

			sc := probe.stream(t, tcpFrom("203.0.113.9", 50002), 0)
			attributeOnKey(t, p, set, sc, "alice", old.Key)
			require.True(t, until.Equal(sc.retiringUntil), "the stream holds K1 as a retiring key")

			before := probe.ledgerCounts()
			require.Equal(t, map[addressKey]int{"198.51.100.7": 1}, before)

			swapped := false

			installBeforeRegisterLockHook(t, func(hooked *streamContext) {
				if hooked != sc || swapped {
					return
				}

				swapped = true

				variant.expire(t, p, clock, old, until)
			})

			assert.Equal(t, DenyKeyRevoked, p.tryRegisterConn(sc))

			require.True(t, swapped, "the swap ran just before the registration lock")
			require.Zero(t, heldRetiring(p), "and took K1 out of the set")

			assert.ErrorIs(t, held.Err(), context.Canceled, "the swap's walk had run by then")
			assert.False(t, streamRegistered(p, sc), "the refused stream is not in liveConns")
			assert.Equal(t, 1, probe.registered(), "only the stream registered before the swap is")
			assert.False(t, sc.addrCounted)
			assert.Nil(t, sc.addrEntry.Load())
			assert.Equal(t, before, probe.ledgerCounts(), "the ledger is as it was")
		})
	}
}

// A key that expires with no swap at all -- the set in force is the set the
// stream was attributed from -- is refused at registration all the same: the
// re-check judges a retiring key at its own, fresh instant, so a hello verified
// just before until (or judged at an instant the budget wait made stale) does
// not register just after it. A moment before until the same key registers.
func TestAKeyThatExpiresWithoutASwapIsRefusedAtRegistration(t *testing.T) {
	t.Parallel()

	probe := newClientTableProbe(t, false)
	p := probe.proxy
	clock := rotationClockAt(p, rotationNow)

	old := p.secrets.Load().secrets[0]
	until := rotationAt(time.Hour)
	set := rotateTo(t, p, map[string]Secret{"alice": GenerateSecret("alice.example.com")}, retire("alice", old, until))

	early := probe.stream(t, tcpFrom("198.51.100.7", 50001), 0)
	attributeOnKey(t, p, set, early, "alice", old.Key)

	late := probe.stream(t, tcpFrom("203.0.113.9", 50002), 0)
	attributeOnKey(t, p, set, late, "alice", old.Key)

	// The control: a second before until the key is accepted.
	clock.set(until.Add(-time.Second))
	require.Equal(t, DenyNone, p.tryRegisterConn(early))

	clock.set(until)

	// Compared as pointers: on failure Same would print the whole set.
	require.True(t, p.secrets.Load() == set, "no swap ran")
	require.True(t, late.attrSet == set, "the set in force is the one the stream was attributed from")

	assert.Equal(t, DenyKeyRevoked, p.tryRegisterConn(late))
	assert.False(t, streamRegistered(p, late))
	assert.True(t, streamRegistered(p, early))
	assert.Equal(t, map[addressKey]int{"198.51.100.7": 1}, probe.ledgerCounts(), "the refusal left the ledger as it found it")
}

// L6. closeStaleConns' fast path follows what the two sets hold for a name: a
// swap that leaves them alone skips the name, a swap that changes them never
// skips it -- even when both sets accept the same keys at the swap's instant --
// and a name the old set did not have holds nothing there, so it never skips.
func TestTheFastPathFollowsHeldKeys(t *testing.T) {
	t.Parallel()

	t.Run("an unrelated change skips the name", func(t *testing.T) {
		t.Parallel()

		l := newLifecycle(t)
		before := l.rotate(t)
		k1, k2 := l.stream(t, "alice", l.old), l.stream(t, "alice", l.next)

		cfg := l.rotated()
		cfg.SecretAdTags = map[string][AdTagLength]byte{"alice": adTagFilled(7)}

		after, drops := buildSecretSetAt(cfg.Secrets, cfg.SecretAdTags, nil, nil, cfg.Retiring, rotationNow)
		require.Empty(t, drops)

		skips := &skipRecord{}
		l.p.staleSkipHook = skips.add

		closed := l.p.closeStaleConns(before, after, rotationNow)

		assert.Equal(t, []string{"alice"}, skips.skipped(), "the same held keys: the fast path")
		assert.Empty(t, closed)
		assert.NoError(t, k1.Err())
		assert.NoError(t, k2.Err())
	})

	t.Run("a held change whose accepted sets are equal at now never skips it", func(t *testing.T) {
		t.Parallel()

		l := newLifecycle(t)
		before := l.rotate(t)
		olds := []*streamContext{l.stream(t, "alice", l.old), l.stream(t, "alice", l.old)}
		next := l.stream(t, "alice", l.next)

		now := l.until

		// What a swap at now builds from the unchanged file: K1 dropped as expired.
		cfg := l.rotated()
		after, drops := buildSecretSetAt(cfg.Secrets, nil, nil, nil, cfg.Retiring, now)
		require.Equal(t, []retiringDrop{dropOf("alice", l.until, retiringExpired)}, drops)

		// At now both sets accept K2 alone for alice. Only what they hold tells
		// them apart: the old one still holds K1.
		for _, set := range []*secretSet{before, after} {
			require.False(t, set.accepts("alice", l.old.Key[:], now))
			require.True(t, set.accepts("alice", l.next.Key[:], now))
		}

		require.False(t, sameHeldKeys(before, after, "alice"))

		skips := &skipRecord{}
		l.p.staleSkipHook = skips.add

		closed := l.p.closeStaleConns(before, after, now)

		assert.Empty(t, skips.skipped(), "the held keys changed: never the fast path")
		assert.Equal(t, map[string]int{"alice": 2}, closed)

		for i, sc := range olds {
			assert.ErrorIs(t, sc.Err(), context.Canceled, "K1 stream %d is closed", i)
		}

		assert.NoError(t, next.Err())
	})

	t.Run("a name absent from the old set never skips", func(t *testing.T) {
		t.Parallel()

		l := newLifecycle(t)
		carolBefore, carolNow := GenerateSecret("carol.example.com"), GenerateSecret("carol.example.com")

		withCarol := func(carol Secret) *secretSet {
			return buildSecretSet(map[string]Secret{"alice": l.old, "bob": l.bob, "carol": carol}, nil, nil, nil)
		}

		// carol's streams, registered while sets that had her were in force:
		// one on a key she had once, one on the key she has now.
		l.p.secrets.Store(withCarol(carolBefore))
		stale := l.stream(t, "carol", carolBefore)

		l.p.secrets.Store(withCarol(carolNow))
		kept := l.stream(t, "carol", carolNow)

		// The old set handed in has no carol: it holds nothing for her.
		before := buildSecretSet(map[string]Secret{"alice": l.old, "bob": l.bob}, nil, nil, nil)
		after := withCarol(carolNow)

		skips := &skipRecord{}
		l.p.staleSkipHook = skips.add

		closed := l.p.closeStaleConns(before, after, rotationNow)

		assert.Empty(t, skips.skipped(), "a name the old set lacks never takes the fast path")
		assert.Equal(t, map[string]int{"carol": 1}, closed)
		assert.ErrorIs(t, stale.Err(), context.Canceled, "the key the new set does not accept is closed")
		assert.NoError(t, kept.Err(), "the key it accepts is kept")
	})

	t.Run("a name absent from the new set closes every stream", func(t *testing.T) {
		t.Parallel()

		l := newLifecycle(t)
		before := l.p.secrets.Load()
		streams := []*streamContext{l.stream(t, "bob", l.bob), l.stream(t, "bob", l.bob)}

		after := buildSecretSet(map[string]Secret{"alice": l.old}, nil, nil, nil)

		skips := &skipRecord{}
		l.p.staleSkipHook = skips.add

		closed := l.p.closeStaleConns(before, after, rotationNow)

		assert.Empty(t, skips.skipped())
		assert.Equal(t, map[string]int{"bob": 2}, closed)

		for i, sc := range streams {
			assert.ErrorIs(t, sc.Err(), context.Canceled, "bob's stream %d", i)
		}
	})
}

// L7, its first half: a ban and a kick are by name and place, so they end the
// streams of both keys at that place, and a ban refuses either key from it.
func TestBanAndKickReachBothKeys(t *testing.T) {
	t.Parallel()

	probe, _ := banProbe(t, false)
	p := probe.proxy
	rotationClockAt(p, rotationNow)

	cfg := p.secrets.Load().toConfig()
	old, next := cfg.Secrets["alice"], GenerateSecret("alice.example.com")
	cfg.Secrets["alice"] = next
	cfg.Retiring = []RetiringSecret{retire("alice", old, rotationAt(time.Hour))}

	require.NoError(t, p.ReplaceSecrets(cfg))

	set := p.secrets.Load()
	require.Equal(t, 1, heldRetiring(p))

	banned, kicked := netip.MustParseAddr("203.0.113.9"), netip.MustParseAddr("198.51.100.7")

	on := func(place netip.Addr, port int, key Secret) *streamContext {
		t.Helper()

		sc := probe.stream(t, tcpFrom(place.String(), port), 0)
		attributeOnKey(t, p, set, sc, "alice", key.Key)
		require.Equal(t, DenyNone, p.tryRegisterConn(sc))

		return sc
	}

	oldAtBanned, nextAtBanned := on(banned, 50001, old), on(banned, 50002, next)
	oldAtKicked, nextAtKicked := on(kicked, 50003, old), on(kicked, 50004, next)

	result, err := p.Ban("alice", []netip.Addr{banned}, time.Hour)
	require.NoError(t, err)

	assert.Equal(t, 2, result.Closed, "the ban ends the place's streams on either key")
	assert.ErrorIs(t, oldAtBanned.Err(), context.Canceled, "the K1 stream at the banned place")
	assert.ErrorIs(t, nextAtBanned.Err(), context.Canceled, "the K2 stream at the banned place")
	assert.NoError(t, oldAtKicked.Err())
	assert.NoError(t, nextAtKicked.Err())

	for _, key := range []Secret{old, next} {
		sc := probe.stream(t, tcpFrom(banned.String(), 50005), 0)
		assert.Equal(t, DenyBanned, p.attributeMatch(sc, set, matchOfKey(t, set, "alice", key.Key)),
			"either key is refused from the banned place")
	}

	closed, err := p.Kick("alice", []netip.Addr{kicked})
	require.NoError(t, err)

	assert.Equal(t, 2, closed, "the kick ends the place's streams on either key")
	assert.ErrorIs(t, oldAtKicked.Err(), context.Canceled, "the K1 stream at the kicked place")
	assert.ErrorIs(t, nextAtKicked.Err(), context.Canceled, "the K2 stream at the kicked place")
}

// L8. Both keys draw on the name's one quota, on every door: what a K1 stream
// moves and what a K2 stream moves is one counter, a ceiling lowered to what
// they moved together closes the streams of both, and neither key is let in
// again.
func TestBothKeysShareTheQuota(t *testing.T) {
	t.Parallel()

	for _, ec := range govEntryCases() {
		t.Run(ec.name, func(t *testing.T) {
			t.Parallel()

			old, next, bob := ec.secret(t), ec.secret(t), ec.secret(t)
			h := ec.harness(t, map[string]Secret{"alice": old, "bob": bob}, nil)
			rotationClockAt(h.proxy, rotationNow)

			require.NoError(t, h.proxy.ReplaceSecrets(SecretConfig{
				Secrets:  map[string]Secret{"alice": next, "bob": bob},
				Limits:   map[string]SecretLimits{"alice": {QuotaBytes: 1 << 20}},
				Retiring: []RetiringSecret{retire("alice", old, rotationAt(time.Hour))},
			}))

			h.proxy.stats.mu.RLock()
			aliceStats, bobStats := h.proxy.stats.users["alice"], h.proxy.stats.users["bob"]
			h.proxy.stats.mu.RUnlock()

			var moved int64

			send := func(s *govStream, n int) {
				t.Helper()

				_, err := s.client.Write(ec.framePayload(bytes.Repeat([]byte{0x5a}, n)))
				require.NoError(t, err)

				require.NoError(t, s.upstream.SetReadDeadline(time.Now().Add(5*time.Second)))

				_, err = io.ReadFull(s.upstream, make([]byte, n))
				require.NoError(t, err)

				moved += int64(n)

				require.Eventually(t, func() bool { return aliceStats.quotaUsed.Load() == moved },
					3*time.Second, 5*time.Millisecond, "every byte is charged to alice's one counter")
			}

			oldStream := ec.connect(t, h, "alice", old.Key)
			send(oldStream, 700)

			nextStream := ec.connect(t, h, "alice", next.Key)
			send(nextStream, 300)

			assert.Zero(t, bobStats.quotaUsed.Load(), "and to no one else")

			// A ceiling lowered to what the two keys moved together.
			cfg := h.proxy.secrets.Load().toConfig()
			cfg.Limits = map[string]SecretLimits{"alice": {QuotaBytes: moved}}
			require.NoError(t, h.proxy.ReplaceSecrets(cfg))
			require.Equal(t, 1, heldRetiring(h.proxy), "the overlap goes on")

			require.True(t, govAwait(oldStream.done, govDenyBudget), "the K1 stream is closed at the shared ceiling")
			require.True(t, govAwait(nextStream.done, govDenyBudget), "and so is the K2 stream")

			for _, key := range []Secret{old, next} {
				client, done := h.dialProxy(t, ec.policy)
				ec.openEntry(t, client, key.Key)

				require.True(t, govAwait(done, govDenyBudget), "a key of a name at its quota is refused, not relayed")
			}

			assert.Equal(t, 2, h.network.telegramDials(), "only the two streams before the ceiling reached Telegram")
		})
	}
}

// L9. The expiry sweep takes reloadMu with TryLock. With the lock held, a sweep
// that has an expired entry to drop returns at once, and the maintenance loop
// goes on with its tick: a disabled user's stream is still closed by
// closeDeniedConns. The K1 stream waits, and is closed on a tick once the lock
// is free.
func TestTheExpirySweepNeverWaitsForReloadMu(t *testing.T) {
	t.Parallel()

	l := newLifecycle(t)
	l.rotate(t)

	old := l.stream(t, "alice", l.old)
	bob := l.stream(t, "bob", l.bob)

	// bob disabled in the set in force, put there without a swap: a swap would
	// close his stream itself, and only closeDeniedConns is to.
	cfg := l.rotated()
	disabled, drops := buildSecretSetAt(cfg.Secrets, nil, nil, map[string]SecretLimits{"bob": {Disabled: true}},
		cfg.Retiring, rotationNow)
	require.Empty(t, drops)
	l.p.secrets.Store(disabled)

	// K1 has expired: the sweep has a swap to make, and wants the lock for it.
	l.clock.set(l.until)

	l.p.reloadMu.Lock()

	held := true

	unlock := func() {
		if held {
			held = false

			l.p.reloadMu.Unlock()
		}
	}

	t.Cleanup(unlock)

	returned := make(chan struct{})

	go func() {
		defer close(returned)

		l.p.expireRetiring()
	}()

	if !govAwait(returned, 2*time.Second) {
		unlock()
		t.Fatal("the sweep waited for reloadMu")
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	l.p.startMaintenanceEvery(ctx, 10*time.Millisecond, time.Hour, time.Hour)

	if !awaitClosed(bob, 3*time.Second) {
		unlock()
		t.Fatal("the loop's closeDeniedConns must run on a tick whose sweep could not take the lock")
	}

	assert.NoError(t, old.Err(), "the K1 stream waits for the lock")
	assert.True(t, l.p.secrets.Load() == disabled, "no swap ran while the lock was held")

	unlock()

	require.True(t, awaitClosed(old, 3*time.Second), "a tick after the lock is free ends the overlap")
}

// A swap reads the rotation clock once even when it has live streams to judge
// one by one and an overlap's end to classify: closeStaleConns and the change
// log take the swap's own instant.
func TestASwapStillReadsTheClockOnce(t *testing.T) {
	t.Parallel()

	for _, route := range []struct {
		name string
		swap func(*lifecycle) error
	}{
		{"an overlap ended early, through ReplaceSecrets", func(l *lifecycle) error {
			return l.p.ReplaceSecrets(l.ended())
		}},
		{"an overlap ended early, through ReloadSecrets", func(l *lifecycle) error {
			l.reloadWith(l.ended())

			return l.p.ReloadSecrets()
		}},
		{"the unchanged file reloaded after until", func(l *lifecycle) error {
			l.clock.set(l.until.Add(time.Minute))
			l.reloadWith(l.rotated())

			return l.p.ReloadSecrets()
		}},
	} {
		t.Run(route.name, func(t *testing.T) {
			t.Parallel()

			l := newLifecycle(t)

			var reads atomic.Int64

			l.p.rotation = NewRotationClock(func() time.Time {
				reads.Add(1)

				return l.clock.now()
			}, nil)

			l.rotate(t)

			k1, k2 := l.stream(t, "alice", l.old), l.stream(t, "alice", l.next)

			before := reads.Load()

			require.NoError(t, route.swap(l))

			assert.Equal(t, before+1, reads.Load(), "one read for the whole swap")
			assert.ErrorIs(t, k1.Err(), context.Canceled, "the per-stream judgment ran: K1 is no longer accepted")
			assert.NoError(t, k2.Err())
		})
	}
}
