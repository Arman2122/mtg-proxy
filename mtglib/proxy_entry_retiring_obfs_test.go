package mtglib

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"maps"
	"net"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Arman2122/mtg-proxy/essentials"
	"github.com/Arman2122/mtg-proxy/mtglib/obfuscation"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The obfuscated door with retiring keys (spec §3.2, tests D5 and D6): a client
// that holds an old dd or plain key is tried after every primary, billed to its
// own name, and refused through the door's one exit from its until on.

// obfuscatedAttemptFrom runs one 64-byte obfuscated2 frame through the obfuscated
// entry from the address addr (the harness's own loopback peer when nil) and
// reports whether it was admitted. doObfuscatedEntry is called directly, so
// nothing past attribution runs: no registration, no Telegram dial.
func (h *entryHarness) obfuscatedAttemptFrom(
	t *testing.T, frame []byte, policy ListenerPolicy, addr net.Addr,
) (*streamContext, bool) {
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

	_, err = client.Write(frame)
	require.NoError(t, err)

	conn := essentials.WrapNetConn(server)
	if addr != nil {
		conn = remoteAddrConn{Conn: conn, addr: addr}
	}

	ctx := newStreamContext(h.proxy.ctx, h.proxy.logger, conn)
	t.Cleanup(ctx.Close)

	return ctx, h.proxy.doObfuscatedEntry(ctx, policy)
}

// obfuscatedAttempt is obfuscatedAttemptFrom for a fresh frame made with key,
// from the harness's loopback peer.
func (h *entryHarness) obfuscatedAttempt(
	t *testing.T, key [SecretKeyLength]byte, policy ListenerPolicy,
) (*streamContext, bool) {
	t.Helper()

	return h.obfuscatedAttemptFrom(t, obfuscatedFrame(t, key, obfuscation.TagPaddedIntermediate, 2), policy, nil)
}

// obfsTally is the obfuscated door's own counters.
type obfsTally struct{ trials, misses, denied, rateLimited int64 }

func obfsTallyOf(p *Proxy) obfsTally {
	return obfsTally{
		trials:      p.obfsStats.trials.Load(),
		misses:      p.obfsStats.misses.Load(),
		denied:      p.obfsStats.denied.Load(),
		rateLimited: p.obfsStats.rateLimited.Load(),
	}
}

func (a obfsTally) minus(b obfsTally) obfsTally {
	return obfsTally{
		trials:      a.trials - b.trials,
		misses:      a.misses - b.misses,
		denied:      a.denied - b.denied,
		rateLimited: a.rateLimited - b.rateLimited,
	}
}

// obfuscatedName is one rotated name of a door: the key it now has, the key it
// had, and when the old one stops, with what an attribution of either must carry.
type obfuscatedName struct {
	name      string
	next, old Secret
	until     time.Time
	adTag     *[AdTagLength]byte
	limits    SecretLimits
}

// obfuscatedRotation is a dd/plain door over four names, each rotated from an
// old key (dd or plain) to a new one, with the old key retiring until its own
// hour. The proxy runs on a clock the test moves.
type obfuscatedRotation struct {
	h      *entryHarness
	clock  *steppedClock
	set    *secretSet
	names  []obfuscatedName
	policy ListenerPolicy
}

func adTagFilledWith(b byte) *[AdTagLength]byte {
	var tag [AdTagLength]byte

	for i := range tag {
		tag[i] = b
	}

	return &tag
}

// newObfuscatedRotation rotates alice, bob, carol and dave. governed gives them
// ad tags (carol takes the global one) and distinct limits; the ungoverned door
// has none, so a stream admitted on it reaches Telegram directly.
func newObfuscatedRotation(t *testing.T, governed bool) *obfuscatedRotation {
	t.Helper()

	names := []obfuscatedName{
		{name: "alice", next: ddSecretOf(keyFilledFrom(0x10)), old: ddSecretOf(keyFilledFrom(0x20)), until: rotationAt(1 * time.Hour)},
		{name: "bob", next: plainSecretOf(keyFilledFrom(0x30)), old: plainSecretOf(keyFilledFrom(0x40)), until: rotationAt(2 * time.Hour)},
		{name: "carol", next: ddSecretOf(keyFilledFrom(0x50)), old: plainSecretOf(keyFilledFrom(0x60)), until: rotationAt(3 * time.Hour)},
		{name: "dave", next: ddSecretOf(keyFilledFrom(0x70)), old: ddSecretOf(keyFilledFrom(0x80)), until: rotationAt(4 * time.Hour)},
	}

	global := adTagFilledWith(0xee)
	perName := map[string][AdTagLength]byte{}
	limits := map[string]SecretLimits{}

	if governed {
		for i, tag := range []byte{0xa1, 0xb2, 0, 0xd4} {
			names[i].adTag = global

			if tag != 0 {
				names[i].adTag = adTagFilledWith(tag)
				perName[names[i].name] = *names[i].adTag
			}

			names[i].limits = SecretLimits{IPLimit: 3 + i, ClientConns: 9 - i}
			limits[names[i].name] = names[i].limits
		}
	}

	before, after := map[string]Secret{}, map[string]Secret{}

	var retiring []RetiringSecret

	for _, n := range names {
		before[n.name], after[n.name] = n.old, n.next
		retiring = append(retiring, retire(n.name, n.old, n.until))
	}

	ec := govEntryCases()[1]
	h := ec.harness(t, before, nil)
	clock := rotationClockAt(h.proxy, rotationNow)

	cfg := SecretConfig{Secrets: after, Retiring: retiring}
	if governed {
		cfg.SecretAdTags, cfg.GlobalAdTag, cfg.Limits = perName, global, limits
	}

	require.NoError(t, h.proxy.ReplaceSecrets(cfg))

	set := h.proxy.secrets.Load()
	require.Len(t, set.retiring, len(names), "every old key is kept")

	for i, n := range names {
		require.Equal(t, n.name, set.names[set.retiring[i].nameIdx], "retiring[%d] is %s's", i, n.name)
	}

	return &obfuscatedRotation{
		h:     h,
		clock: clock,
		set:   set,
		names: names,
		policy: ListenerPolicy{
			Modes:           ModeSetOf(SecretModeDD, SecretModePlain),
			OnUnknownSecret: UnknownSecretClose,
		},
	}
}

// relayRoundTrip carries a client of key through the whole proxy and back: the
// client's side speaks obfuscated2 under key, Telegram's side reads the
// handshake the proxy sent it, and a payload crosses each way. It would not
// arrive intact if the proxy had decrypted the stream under any key but key.
func (h *entryHarness) relayRoundTrip(t *testing.T, policy *ListenerPolicy, key [SecretKeyLength]byte, name string) {
	t.Helper()

	const clientDC = 4

	client, done := h.dialProxy(t, policy)

	deadline := time.Now().Add(5 * time.Second)
	require.NoError(t, client.SetDeadline(deadline))

	wrapped, err := obfuscation.Obfuscator{Secret: key[:]}.SendHandshake(
		essentials.WrapNetConn(client), clientDC, obfuscation.TagPaddedIntermediate)
	require.NoError(t, err)

	upstream, err := h.upstream.Accept()
	require.NoError(t, err, "an admitted stream must dial Telegram")
	require.NoError(t, upstream.SetDeadline(deadline))

	// Default DC addresses carry a nil obfuscator secret: this is the derivation
	// the far end performs.
	telegramDC, _, far, err := obfuscation.Obfuscator{}.ReadHandshake(
		essentials.WrapNetConn(upstream), obfuscation.TagSetOf(obfuscation.TagPaddedIntermediate))
	require.NoError(t, err, "the proxy hands Telegram a readable obfuscated2 handshake")
	assert.Equal(t, clientDC, telegramDC, "the client's own DC reaches Telegram")

	up, down := []byte("from the holder of the old key"), []byte("and back to the same holder")

	// The obfuscated2 conn encrypts in place, so each side writes a copy.
	_, err = wrapped.Write(slices.Clone(up))
	require.NoError(t, err)

	got := make([]byte, len(up))
	_, err = io.ReadFull(far, got)
	require.NoError(t, err)
	assert.Equal(t, up, got, "client to Telegram, decrypted under the client's key")

	_, err = far.Write(slices.Clone(down))
	require.NoError(t, err)

	got = make([]byte, len(down))
	_, err = io.ReadFull(wrapped, got)
	require.NoError(t, err)
	assert.Equal(t, down, got, "Telegram to client, encrypted under the client's key")

	stream := h.liveStream(t, name)
	require.NotNil(t, stream, "registered under the name the key belongs to")

	h.proxy.liveMu.Lock()
	matched := slices.Clone(stream.matchedSecretKey)
	h.proxy.liveMu.Unlock()

	assert.Equal(t, key[:], matched, "and it holds the key it matched")

	stats := h.proxy.stats.getOrCreate(name)

	require.Eventually(t, func() bool {
		return stats.bytesIn.Load() == int64(len(up)) && stats.bytesOut.Load() == int64(len(down))
	}, 5*time.Second, time.Millisecond, "the bytes are the name's")

	endStream(client, upstream, done)
}

// TestOldDdAndPlainKeysAttributeToTheirName is D5. Four names are rotated, each
// with an old key of its own (dd or plain); each old key is billed to its own
// name with that name's ad tag and limits, relays under itself, and is refused
// through the door's one exit once the clock reaches its until.
func TestOldDdAndPlainKeysAttributeToTheirName(t *testing.T) {
	t.Parallel()

	t.Run("each old key is billed to its own name", func(t *testing.T) {
		t.Parallel()

		f := newObfuscatedRotation(t, true)

		for i, n := range f.names {
			ctx, ok := f.h.obfuscatedAttempt(t, n.old.Key, f.policy)
			require.True(t, ok, "%s's old key is admitted during its overlap", n.name)

			assert.Equal(t, n.name, ctx.secretName, "billed to the name")
			assert.Equal(t, n.old.Key[:], ctx.matchedSecretKey, "the key the client holds")
			assert.Same(t, &f.set.retiring[i].secret.Key[0], &ctx.matchedSecretKey[0], "a slice into the set's own entry")
			assert.True(t, n.until.Equal(ctx.retiringUntil), "and the entry's until")
			assert.Same(t, f.set, ctx.attrSet)
			assert.Equal(t, n.adTag, ctx.adTag, "%s's ad tag", n.name)
			assert.Equal(t, n.limits.IPLimit, ctx.ipLimit, "%s's address limit", n.name)
			assert.Equal(t, n.limits.ClientConns, ctx.clientConns, "%s's connection cap", n.name)

			// The control: the name's new key, on the same door.
			ctx, ok = f.h.obfuscatedAttempt(t, n.next.Key, f.policy)
			require.True(t, ok, "%s's new key", n.name)
			assert.Equal(t, n.name, ctx.secretName)
			assert.Equal(t, n.next.Key[:], ctx.matchedSecretKey)
			assert.True(t, ctx.retiringUntil.IsZero(), "a primary has no until")
		}
	})

	t.Run("each old key relays under itself", func(t *testing.T) {
		t.Parallel()

		f := newObfuscatedRotation(t, false)

		for _, n := range f.names {
			f.h.relayRoundTrip(t, &f.policy, n.old.Key, n.name)
		}
	})

	t.Run("each old key is refused from its until on, and only that one", func(t *testing.T) {
		t.Parallel()

		f := newObfuscatedRotation(t, true)

		refused := func(n obfuscatedName) {
			t.Helper()

			before := obfsTallyOf(f.h.proxy)
			_, ok := f.h.obfuscatedAttempt(t, n.old.Key, f.policy)

			assert.False(t, ok, "%s's old key is refused", n.name)
			assert.Equal(t, obfsTally{trials: 1, misses: 1, denied: 1}, obfsTallyOf(f.h.proxy).minus(before),
				"through the one exit: a trial that matched nothing, and denied")
		}

		for j, n := range f.names {
			// Exactly its until, and no swap since: the entry is still in the set.
			f.clock.set(n.until)
			require.Same(t, f.set, f.h.proxy.secrets.Load())

			refused(n)

			for _, earlier := range f.names[:j] {
				refused(earlier)
			}

			for _, later := range f.names[j+1:] {
				ctx, ok := f.h.obfuscatedAttempt(t, later.old.Key, f.policy)
				require.True(t, ok, "%s's old key is still inside its overlap", later.name)
				assert.Equal(t, later.name, ctx.secretName)
			}

			ctx, ok := f.h.obfuscatedAttempt(t, n.next.Key, f.policy)
			require.True(t, ok, "%s's new key is not affected", n.name)
			assert.Equal(t, n.name, ctx.secretName)
		}
	})

	t.Run("a refused old key is disposed of silently by the whole proxy", func(t *testing.T) {
		t.Parallel()

		f := newObfuscatedRotation(t, false)
		alice := f.names[0]

		f.clock.set(alice.until)

		before := obfsTallyOf(f.h.proxy)

		client, done := f.h.dialProxy(t, &f.policy)
		_, err := client.Write(obfuscatedFrame(t, alice.old.Key, obfuscation.TagPaddedIntermediate, 2))
		require.NoError(t, err)

		// Bounded: a key wrongly admitted is relayed, and a relayed stream never
		// returns by itself.
		require.True(t, govAwait(done, govDenyBudget), "the old key must be refused, not relayed")

		assertDeniedSilently(t, client)
		assert.Equal(t, obfsTally{trials: 1, misses: 1, denied: 1}, obfsTallyOf(f.h.proxy).minus(before))
		assert.Zero(t, f.h.network.telegramDials(), "nothing was dialled")
		assert.Zero(t, f.h.events.frontings(), "and the obfuscated door never fronts")

		f.h.proxy.liveMu.Lock()
		assert.Empty(t, f.h.proxy.liveConns, "and nothing was registered")
		f.h.proxy.liveMu.Unlock()
	})
}

// TestAnOldKeyCarriesItsNamesLimits: an old key is its name's, so the name's
// limits refuse it as they refuse the primary, through the same exit, and after
// the key matched (it is no miss).
func TestAnOldKeyCarriesItsNamesLimits(t *testing.T) {
	t.Parallel()

	oldOf := func(first byte) Secret { return ddSecretOf(keyFilledFrom(first)) }

	before := map[string]Secret{"erin": oldOf(0x20), "frank": oldOf(0x40), "gina": oldOf(0x60)}
	after := map[string]Secret{"erin": oldOf(0x10), "frank": oldOf(0x30), "gina": oldOf(0x50)}
	limits := map[string]SecretLimits{"erin": {Disabled: true}, "frank": {QuotaBytes: 100}}

	h := govEntryCases()[1].harness(t, before, nil)
	rotationClockAt(h.proxy, rotationNow)

	require.NoError(t, h.proxy.ReplaceSecrets(SecretConfig{
		Secrets: after,
		Limits:  limits,
		Retiring: []RetiringSecret{
			retire("erin", before["erin"], rotationAt(time.Hour)),
			retire("frank", before["frank"], rotationAt(time.Hour)),
			retire("gina", before["gina"], rotationAt(time.Hour)),
		},
	}))

	h.proxy.stats.users["frank"].quotaUsed.Store(500)

	policy := ListenerPolicy{Modes: ModeSetOf(SecretModeDD), OnUnknownSecret: UnknownSecretClose}

	for _, tc := range []struct {
		name  string
		key   Secret
		admit bool
	}{
		{"erin", before["erin"], false},
		{"erin", after["erin"], false},
		{"frank", before["frank"], false},
		{"frank", after["frank"], false},
		{"gina", before["gina"], true},
		{"gina", after["gina"], true},
	} {
		tally := obfsTallyOf(h.proxy)
		ctx, ok := h.obfuscatedAttempt(t, tc.key.Key, policy)

		assert.Equal(t, tc.admit, ok, "%s, key %x", tc.name, tc.key.Key[:2])
		assert.Equal(t, tc.name, ctx.secretName, "the key matched, so it is billed to its name")

		want := obfsTally{trials: 1}
		if !tc.admit {
			want.denied = 1
		}

		assert.Equal(t, want, obfsTallyOf(h.proxy).minus(tally), "%s: a refusal by a limit is no miss", tc.name)
	}
}

// TestTheObfuscatedIndexMappingIsExact: the key list is the primaries, then the
// unexpired retiring keys of any mode in the set's order; an index below
// len(secrets) is a primary and index len(secrets)+j is keyRetiring[j]. The
// set holds five entries and the clock has passed two of them, the first and
// one in the middle, so a list that kept expired keys, or a mapping that is off
// by one in either direction, bills the wrong name.
func TestTheObfuscatedIndexMappingIsExact(t *testing.T) {
	t.Parallel()

	const cover = "cover.example.com"

	primaries := map[string]Secret{
		"a": ddSecretOf(keyFilledFrom(0x10)),
		"b": eeSecretOf(keyFilledFrom(0x20), cover),
		"c": ddSecretOf(keyFilledFrom(0x30)),
		"d": plainSecretOf(keyFilledFrom(0x40)),
		"e": ddSecretOf(keyFilledFrom(0x50)),
	}

	// In the set's order: by name, and within a name by until descending.
	entries := []RetiringSecret{
		retire("a", ddSecretOf(keyFilledFrom(0x60)), rotationAt(1*time.Hour)),        // retiring[0], expired
		retire("b", eeSecretOf(keyFilledFrom(0x70), cover), rotationAt(5*time.Hour)), // retiring[1], an ee key
		retire("c", ddSecretOf(keyFilledFrom(0x80)), rotationAt(4*time.Hour)),        // retiring[2]
		retire("c", plainSecretOf(keyFilledFrom(0x90)), rotationAt(2*time.Hour)),     // retiring[3], expired at its until
		retire("d", plainSecretOf(keyFilledFrom(0xa0)), rotationAt(6*time.Hour)),     // retiring[4]
	}

	h := newEntryHarness(t, primaries, nil)
	source := newSteppedClock(rotationNow)

	var reads atomic.Int64

	h.proxy.rotation = NewRotationClock(func() time.Time {
		reads.Add(1)

		return source.now()
	}, nil)

	set := rotateTo(t, h.proxy, primaries, entries...)

	for i, e := range entries {
		require.Equal(t, e.Name, set.names[set.retiring[i].nameIdx], "retiring[%d]", i)
	}

	source.set(rotationAt(2 * time.Hour))
	reads.Store(0)

	keys, keyRetiring := obfuscatedKeys(set, h.proxy.rotation)

	assert.EqualValues(t, 1, reads.Load(), "one read of the clock for the whole list")
	assert.Equal(t, []int{1, 2, 4}, keyRetiring, "the unexpired entries, by their index in retiring")
	require.Len(t, keys, len(primaries)+3)
	assert.Equal(t, len(primaries)+len(entries), cap(keys), "room for every entry, expired or not")

	for i := range set.secrets {
		assert.Same(t, &set.secrets[i].Key[0], &keys[i][0], "primary %d comes first, in the set's order", i)
	}

	for j, r := range keyRetiring {
		index := len(set.secrets) + j

		assert.Same(t, &set.retiring[r].secret.Key[0], &keys[index][0], "keys[%d] is retiring[%d]'s key", index, r)

		got := set.obfuscatedMatch(index, keyRetiring)

		assert.Equal(t, set.retiring[r].nameIdx, got.idx, "index %d is billed to retiring[%d]'s name", index, r)
		assert.Equal(t, r, got.retiring)
		assert.Same(t, &set.retiring[r].secret.Key, got.key, "and it holds that entry's own key")
	}

	for i := range set.secrets {
		got := set.obfuscatedMatch(i, keyRetiring)

		assert.Equal(t, i, got.idx)
		assert.Equal(t, -1, got.retiring, "a primary")
		assert.Same(t, &set.secrets[i].Key, got.key)

		// With no list at all, a primary index never reads one.
		assert.Equal(t, i, set.obfuscatedMatch(i, nil).idx)
	}

	policy := ListenerPolicy{Modes: ModeSetOf(SecretModeDD, SecretModePlain), OnUnknownSecret: UnknownSecretClose}

	for r, e := range entries {
		ctx, ok := h.obfuscatedAttempt(t, e.Secret.Key, policy)

		if !slices.Contains(keyRetiring, r) {
			assert.False(t, ok, "retiring[%d] (%s) has reached its until: not in the list, so no match", r, e.Name)

			continue
		}

		require.True(t, ok, "retiring[%d] (%s) is inside its overlap", r, e.Name)
		assert.Equal(t, e.Name, ctx.secretName, "billed to the name the key belongs to")
		assert.Equal(t, e.Secret.Key[:], ctx.matchedSecretKey)
		assert.Same(t, &set.retiring[r].secret.Key[0], &ctx.matchedSecretKey[0])
		assert.True(t, e.Until.Equal(ctx.retiringUntil))
	}

	// Once every entry has expired the list is the primaries' alone, and
	// keyRetiring is still nil, as for a set with none: nothing was made for it.
	source.set(rotationAt(7 * time.Hour))

	keys, keyRetiring = obfuscatedKeys(set, h.proxy.rotation)

	assert.Nil(t, keyRetiring, "every entry has expired: no list, not an empty one")
	assert.Len(t, keys, len(primaries))
	assert.Equal(t, len(primaries)+len(entries), cap(keys))
}

// TestTheTwoKeyListPathsAgree: the door builds the key list of a set with no
// retiring entry itself, inline, so that a one-secret list stays on the stack,
// and takes obfuscatedKeys' for a set that holds an entry. The two must be the
// same list, the primaries' keys in the set's order, or one client would be
// tried and billed differently once a rotation put an entry in the set.
//
// The inline list is local to the door and cannot be read, and a seam that
// handed it out would change the path the plan keeps as it was. So the door's
// behaviour is the witness: the same frames go through a set with no entry
// (the inline list) and through a set whose only entry has already expired (the
// obfuscatedKeys path, with nothing listed past the primaries), and must match
// the same name and the same key. That is also the oracle for the two lists
// against each other, since it is the only thing a client sees of them.
// obfuscatedKeys' own list is compared with the primaries element by element,
// on both sets.
//
// Three rows: one secret (the case the inline list exists for), two, and forty,
// where two names share a key, so that the order of a tie is pinned as well: on
// both paths the first name in the set's order wins.
func TestTheTwoKeyListPathsAgree(t *testing.T) {
	t.Parallel()

	const cover = "cover.example.com"

	policy := ListenerPolicy{Modes: ModeSetOf(SecretModeDD, SecretModePlain), OnUnknownSecret: UnknownSecretClose}

	for _, n := range []int{1, 2, 40} {
		t.Run(fmt.Sprintf("%d secrets", n), func(t *testing.T) {
			t.Parallel()

			primaries := make(map[string]Secret, n)

			for i := range n {
				key := keyFilledFrom(byte(1 + 5*i))
				secret := ddSecretOf(key)

				switch i % 3 {
				case 1:
					secret = plainSecretOf(key)
				case 2:
					secret = eeSecretOf(key, cover)
				}

				primaries[fmt.Sprintf("n%02d", i)] = secret
			}

			if n > 30 {
				primaries["n30"] = primaries["n05"]
			}

			// The set with no entry: the door builds its list inline.
			plain := newEntryHarness(t, primaries, nil)
			plainSet := plain.proxy.secrets.Load()
			require.Empty(t, plainSet.retiring)

			plainReads := countReads(plain.proxy)

			// The set with an entry that has already expired: the door takes
			// obfuscatedKeys' list, and one clock read for each frame says so.
			held := newEntryHarness(t, primaries, nil)
			source := newSteppedClock(rotationNow)

			var heldReads atomic.Int64

			held.proxy.rotation = NewRotationClock(func() time.Time {
				heldReads.Add(1)

				return source.now()
			}, nil)

			heldSet := rotateTo(t, held.proxy, primaries,
				retire("n00", ddSecretOf(keyFilledFrom(250)), rotationAt(time.Hour)))
			source.set(rotationAt(time.Hour))

			for _, set := range []*secretSet{plainSet, heldSet} {
				keys, keyRetiring := obfuscatedKeys(set, held.proxy.rotation)

				require.Len(t, keys, len(set.secrets), "the primaries and nothing past them")
				assert.Nil(t, keyRetiring)

				for i := range set.secrets {
					assert.Same(t, &set.secrets[i].Key[0], &keys[i][0], "obfuscatedKeys' list, position %d", i)
				}
			}

			heldReads.Store(0)

			first := func(key [SecretKeyLength]byte) int {
				return slices.IndexFunc(plainSet.secrets, func(s Secret) bool { return s.Key == key })
			}

			for i := 0; i <= n; i++ {
				stranger := i == n

				key := keyFilledFrom(251)
				if !stranger {
					key = plainSet.secrets[i].Key
				}

				for _, side := range []struct {
					path string
					h    *entryHarness
					set  *secretSet
				}{{"the inline list", plain, plainSet}, {"obfuscatedKeys' list", held, heldSet}} {
					ctx, ok := side.h.obfuscatedAttempt(t, key, policy)

					if stranger {
						assert.False(t, ok, "%s: a stranger", side.path)

						continue
					}

					want := first(key)

					require.True(t, ok, "%s: primary %d", side.path, i)
					assert.Equal(t, plainSet.names[want], ctx.secretName, "%s: primary %d is billed to the first name with its key", side.path, i)
					assert.Same(t, &side.set.secrets[want].Key[0], &ctx.matchedSecretKey[0], "%s: primary %d", side.path, i)
				}
			}

			assert.Zero(t, plainReads.Load(), "the set with no entry never reads the clock")
			assert.EqualValues(t, n+1, heldReads.Load(), "the other set read it once for each frame: it took obfuscatedKeys' list")
		})
	}
}

// TestAnExpiredKeyIsChargedLikeAWrongKey: on a listener that budgets failed
// handshakes per address, an old key past its until costs its holder exactly what
// a wrong key costs -- one token, one miss, one denial -- and an old key still
// inside its overlap costs nothing, as any key that gets in. The expired key is
// not in the list, so the two take the same branch; this pins that the branch
// charges.
func TestAnExpiredKeyIsChargedLikeAWrongKey(t *testing.T) {
	t.Parallel()

	f := newObfuscatedRotation(t, false)
	limiter := f.h.proxy.obfsLimiter

	policy := f.policy
	policy.Public, policy.HandshakesPerIP = true, 5

	const expiredPlace, wrongPlace, livePlace = "198.51.100.21", "198.51.100.22", "198.51.100.23"

	f.clock.set(f.names[0].until)

	attempt := func(key [SecretKeyLength]byte, place string) (bool, obfsTally) {
		before := obfsTallyOf(f.h.proxy)
		_, ok := f.h.obfuscatedAttemptFrom(t, obfuscatedFrame(t, key, obfuscation.TagPaddedIntermediate, 2), policy, tcpFrom(place, 41000))

		return ok, obfsTallyOf(f.h.proxy).minus(before)
	}

	ok, expired := attempt(f.names[0].old.Key, expiredPlace)
	assert.False(t, ok, "alice's old key has reached its until")

	ok, wrong := attempt(keyFilledFrom(251), wrongPlace)
	assert.False(t, ok)

	assert.Equal(t, obfsTally{trials: 1, misses: 1, denied: 1}, expired)
	assert.Equal(t, wrong, expired, "the same counters as a wrong key")

	full := float64(policy.HandshakesPerIP) * handshakeBurstFactor

	for _, place := range []string{expiredPlace, wrongPlace} {
		tokens, charged := obfsTokens(t, limiter, place)

		require.True(t, charged, "%s was charged", place)
		assert.InDelta(t, full-1, tokens, 0, "%s: one token out of a full bucket", place)
	}

	ok, live := attempt(f.names[1].old.Key, livePlace)
	require.True(t, ok, "bob's old key is inside its overlap")
	assert.Equal(t, obfsTally{trials: 1}, live)

	_, charged := obfsTokens(t, limiter, livePlace)
	assert.False(t, charged, "getting in costs nothing")
}

// TestAModeChangingRotationServesBothDoors is D6. A name moves between wire
// forms across an overlap: the old key keeps working on the door it was made
// for and the new one on its own, until the old one's until.
func TestAModeChangingRotationServesBothDoors(t *testing.T) {
	t.Parallel()

	until := rotationAt(time.Hour)
	obfuscated := ListenerPolicy{Modes: ModeSetOf(SecretModeDD), OnUnknownSecret: UnknownSecretClose}
	bobDD := ddSecretOf(keyFilledFrom(0x70))

	t.Run("dd to ee", func(t *testing.T) {
		t.Parallel()

		oldDD := ddSecretOf(keyFilledFrom(0x20))
		newEE := eeSecretOf(keyFilledFrom(0x30), govCoverHost)

		h := newEntryHarness(t, map[string]Secret{"alice": oldDD, "bob": bobDD}, nil)
		clock := rotationClockAt(h.proxy, rotationNow)
		set := rotateTo(t, h.proxy, map[string]Secret{"alice": newEE, "bob": bobDD}, retire("alice", oldDD, until))

		require.Len(t, set.cands, 1, "alice's new key is the only FakeTLS candidate: the old dd key is no candidate")

		ctx, ok := h.obfuscatedAttempt(t, oldDD.Key, obfuscated)
		require.True(t, ok, "the old dd link on the obfuscated listener")
		assert.Equal(t, "alice", ctx.secretName)
		assert.Equal(t, oldDD.Key[:], ctx.matchedSecretKey)
		assert.True(t, until.Equal(ctx.retiringUntil))

		ctx, ok = h.fakeTLSAttempt(t, freshHello(t, newEE.Key, govCoverHost))
		require.True(t, ok, "the new ee link on bind-to")
		assert.Equal(t, "alice", ctx.secretName)
		assert.Equal(t, newEE.Key[:], ctx.matchedSecretKey)
		assert.True(t, ctx.retiringUntil.IsZero())

		ctx, ok = h.obfuscatedAttempt(t, bobDD.Key, obfuscated)
		require.True(t, ok, "bob's primary, after alice's two keys in the list")
		assert.Equal(t, "bob", ctx.secretName)

		_, ok = h.fakeTLSAttempt(t, freshHello(t, oldDD.Key, govCoverHost))
		assert.False(t, ok, "the old dd key does not become a FakeTLS key")

		clock.set(until)

		before := obfsTallyOf(h.proxy)
		_, ok = h.obfuscatedAttempt(t, oldDD.Key, obfuscated)
		assert.False(t, ok, "from its until the old dd link is refused")
		assert.Equal(t, obfsTally{trials: 1, misses: 1, denied: 1}, obfsTallyOf(h.proxy).minus(before))

		ctx, ok = h.fakeTLSAttempt(t, freshHello(t, newEE.Key, govCoverHost))
		require.True(t, ok, "and the new ee link is not")
		assert.Equal(t, "alice", ctx.secretName)
	})

	t.Run("ee to dd", func(t *testing.T) {
		t.Parallel()

		oldEE := eeSecretOf(keyFilledFrom(0x20), govCoverHost)
		newDD := ddSecretOf(keyFilledFrom(0x30))

		h := newEntryHarness(t, map[string]Secret{"alice": oldEE, "bob": bobDD}, nil)
		clock := rotationClockAt(h.proxy, rotationNow)
		rotateTo(t, h.proxy, map[string]Secret{"alice": newDD, "bob": bobDD}, retire("alice", oldEE, until))

		ctx, ok := h.obfuscatedAttempt(t, newDD.Key, obfuscated)
		require.True(t, ok, "the new dd link on the obfuscated listener")
		assert.Equal(t, "alice", ctx.secretName)
		assert.True(t, ctx.retiringUntil.IsZero())

		ctx, ok = h.fakeTLSAttempt(t, freshHello(t, oldEE.Key, govCoverHost))
		require.True(t, ok, "the old ee link on bind-to")
		assert.Equal(t, "alice", ctx.secretName)
		assert.Equal(t, oldEE.Key[:], ctx.matchedSecretKey)
		assert.True(t, until.Equal(ctx.retiringUntil))

		clock.set(until)

		_, ok = h.fakeTLSAttempt(t, freshHello(t, oldEE.Key, govCoverHost))
		assert.False(t, ok, "from its until the old ee link is fronted")

		ctx, ok = h.obfuscatedAttempt(t, newDD.Key, obfuscated)
		require.True(t, ok, "and the new dd link is not refused")
		assert.Equal(t, "alice", ctx.secretName)
	})
}

// Package-level sinks, so that a result the test discards cannot be optimised
// away and its allocation cannot be elided.
var (
	sinkObfuscatedKeys    [][]byte
	sinkObfuscatedRetired []int
)

// TestTheObfuscatedKeyListAllocatesAsBefore measures obfuscatedKeys itself, not
// the door: on a set with no retiring entry it returns the primaries' list in one
// allocation (the list is returned, so it escapes and costs one at any size),
// keyRetiring is nil (a made empty slice would be non-nil, and a made non-empty
// one an allocation), the capacity is the primaries', and the clock is not read.
// The door does not call it for such a set: it builds that list inline, which at
// one secret costs nothing, so what keeps the door's allocations is
// TestTheObfuscatedDoorAllocatesAsBefore, and that the two lists are one list is
// TestTheTwoKeyListPathsAgree. The forty names are the door test's largest row,
// not something this test needs.
//
// Not parallel: AllocsPerRun counts every allocation in the process.
func TestTheObfuscatedKeyListAllocatesAsBefore(t *testing.T) { //nolint: paralleltest // see above
	secrets := make(map[string]Secret, 40)
	for i := range 40 {
		secrets[fmt.Sprintf("n%02d", i)] = ddSecretOf(keyFilledFrom(byte(1 + 5*i)))
	}

	set := buildSecretSet(secrets, nil, nil, nil)
	require.Empty(t, set.retiring, "a set with no retiring entry")

	var reads atomic.Int64

	clock := NewRotationClock(func() time.Time {
		reads.Add(1)

		return rotationNow
	}, nil)

	keys, keyRetiring := obfuscatedKeys(set, clock)

	require.Len(t, keys, len(set.secrets))
	assert.Nil(t, keyRetiring, "nothing retiring: no list, not an empty one")
	assert.Equal(t, len(set.secrets), cap(keys), "the capacity is the primaries'")

	for i := range set.secrets {
		assert.Same(t, &set.secrets[i].Key[0], &keys[i][0])
	}

	assert.InDelta(t, 1, testing.AllocsPerRun(1000, func() {
		sinkObfuscatedKeys, sinkObfuscatedRetired = obfuscatedKeys(set, clock)
	}), 0, "the key list, and nothing else")
	assert.InDelta(t, 1, testing.AllocsPerRun(1000, func() {
		sinkObfuscatedKeys, sinkObfuscatedRetired = obfuscatedKeys(set, nil)
	}), 0, "the same with no clock at all")
	assert.Nil(t, sinkObfuscatedRetired)
	assert.Zero(t, reads.Load(), "and the clock is never read")
}

// frameConn serves one 64-byte frame, again after every reset, and nothing else:
// the client end of a door that is called directly, in memory.
type frameConn struct {
	essentials.Conn

	r     *bytes.Reader
	frame []byte
	addr  net.Addr
}

func (c *frameConn) Read(b []byte) (int, error) { return c.r.Read(b) } //nolint: wrapcheck
func (c *frameConn) RemoteAddr() net.Addr       { return c.addr }
func (c *frameConn) Close() error               { return nil }
func (c *frameConn) reset()                     { c.r.Reset(c.frame) }

// neverReplayed is an anti-replay cache that has seen nothing, so the same frame
// can go through the door again and again.
type neverReplayed struct{}

func (neverReplayed) SeenBefore([]byte) bool { return false }

// TestTheObfuscatedDoorAllocatesAsBefore: the whole door function, on a set with
// no retiring entry, allocates exactly what the door allocated before rotation
// existed, for a frame that matches the last key and for one that matches none.
// "Before" is frozenDoObfuscatedEntry, a copy of the door as it stood at 765ec21
// (proxy_entry_obfs_frozen_test.go), run beside the live door over the same set
// and the same frame, so that what the two share -- MatchHandshake's three or so
// allocations a key tried, and the compiler's rules for the stack -- cancels, and
// a toolchain bump or a cheaper MatchHandshake moves both together.
//
// What it sees, by row:
//   - one secret: the frozen door's list does not escape and stays on the stack
//     (24 bytes), so it costs nothing, while a list returned by obfuscatedKeys
//     costs one. A door that always called it fails here, and only here;
//   - forty: a slice made beside the list is past the 32 bytes the compiler
//     keeps on the stack, so a keyRetiring made for a set with no entry fails
//     here, and not at one or two secrets;
//   - all three: a read of the clock.
//
// On Go 1.26.8 at 765ec21 the counts are 15 (a match) and 6 (a miss) at one
// secret, 19 and 10 at two, 133 and 124 at forty (AllocsPerRun of 500 runs, the
// same with and without -race); the test logs what it measures.
//
// Not parallel: AllocsPerRun counts every allocation in the process.
func TestTheObfuscatedDoorAllocatesAsBefore(t *testing.T) { //nolint: paralleltest // see above
	for _, n := range []int{1, 2, 40} {
		secrets := make(map[string]Secret, n)
		for i := range n {
			secrets[fmt.Sprintf("n%04d", i)] = ddSecretOf(keyFilledFrom(byte(1 + 3*i)))
		}

		h := newEntryHarness(t, secrets, nil)
		h.proxy.antiReplayCache = neverReplayed{}

		var reads atomic.Int64

		h.proxy.rotation = NewRotationClock(func() time.Time {
			reads.Add(1)

			return rotationNow
		}, nil)

		set := h.proxy.secrets.Load()
		require.Empty(t, set.retiring, "a set with no retiring entry")

		policy := ListenerPolicy{Modes: ModeSetOf(SecretModeDD), OnUnknownSecret: UnknownSecretClose}

		for _, frame := range []struct {
			name  string
			key   [SecretKeyLength]byte
			match bool
		}{
			{"a match on the last key", set.secrets[n-1].Key, true},
			{"a miss", keyFilledFrom(250), false},
		} {
			wire := obfuscatedFrame(t, frame.key, obfuscation.TagPaddedIntermediate, 2)
			conn := &frameConn{r: bytes.NewReader(wire), frame: wire, addr: tcpFrom("203.0.113.9", 41000)}

			runner := func(door func(*streamContext, ListenerPolicy) bool) func() bool {
				return func() bool {
					conn.reset()

					return door(&streamContext{ctx: context.Background(), logger: h.proxy.logger, clientSocket: conn}, policy)
				}
			}

			live, frozen := runner(h.proxy.doObfuscatedEntry), runner(h.proxy.frozenDoObfuscatedEntry)

			require.Equal(t, frame.match, live(), "the fixture does what it says")
			require.Equal(t, frame.match, frozen(), "and the frozen door does the same")

			liveAllocs := testing.AllocsPerRun(500, func() { live() })
			frozenAllocs := testing.AllocsPerRun(500, func() { frozen() })

			t.Logf("%d secrets, %s: live %v allocations, frozen %v", n, frame.name, liveAllocs, frozenAllocs)
			require.Positive(t, frozenAllocs, "the frozen door was measured")
			assert.InDelta(t, frozenAllocs, liveAllocs, 0, "%d secrets, %s", n, frame.name)
		}

		assert.Zero(t, reads.Load(), "%d secrets: the door never reads the clock", n)
	}
}

// TestARateLimitedPeerGetsNoKeyList: a peer over its failure budget is read from
// and disposed of without a trial loop, as before, and so builds no key list and
// reads no clock, however many retiring keys the set holds. The frame it sends is
// a valid old key's, so a list built for it would get it in. An unlimited peer on
// the same door is the control: it reads the clock once, for the whole list.
func TestARateLimitedPeerGetsNoKeyList(t *testing.T) {
	t.Parallel()

	f := newObfuscatedRotation(t, false)
	reads := countReads(f.h.proxy)

	policy := f.policy
	policy.Public, policy.HandshakesPerIP = true, 1

	const limited, free = "198.51.100.7", "198.51.100.8"

	limiter := f.h.proxy.obfsLimiter
	for range 3 {
		limiter.Fail(policy, net.ParseIP(limited))
	}

	require.False(t, limiter.Allow(policy, net.ParseIP(limited)), "the burst is spent")
	require.True(t, limiter.Allow(policy, net.ParseIP(free)))

	before := obfsTallyOf(f.h.proxy)
	old := f.names[1].old.Key

	_, ok := f.h.obfuscatedAttemptFrom(t,
		obfuscatedFrame(t, old, obfuscation.TagPaddedIntermediate, 2), policy, tcpFrom(limited, 41000))

	assert.False(t, ok, "the rate-limited peer is refused although its key is valid")
	assert.Zero(t, reads.Load(), "and no key list was built for it: the clock was not read")
	assert.Equal(t, obfsTally{rateLimited: 1, denied: 1}, obfsTallyOf(f.h.proxy).minus(before),
		"it never entered the trial loop")

	before = obfsTallyOf(f.h.proxy)

	ctx, ok := f.h.obfuscatedAttemptFrom(t,
		obfuscatedFrame(t, old, obfuscation.TagPaddedIntermediate, 2), policy, tcpFrom(free, 41000))

	require.True(t, ok, "the control: the same key from a peer with budget")
	assert.Equal(t, "bob", ctx.secretName)
	assert.EqualValues(t, 1, reads.Load(), "one read for its list")
	assert.Equal(t, obfsTally{trials: 1}, obfsTallyOf(f.h.proxy).minus(before))
}

// unservedMessage is the start-up warning for a secret no listener honours.
const unservedMessage = "secret is not served by any listener; no configured listener honours this form"

// TestAnUnservedRetiringKeyIsWarnedAtStart: a retiring dd or plain entry that no
// listener honours is as unreachable as such a primary, and NewProxy says so with
// the same words, once for each kept entry, naming the secret and its mode and
// nothing else. The primaries are all ee, so every line comes from an entry. An
// ee entry is reached on bind-to and an entry the build dropped is not kept, so
// neither is warned about.
func TestAnUnservedRetiringKeyIsWarnedAtStart(t *testing.T) {
	t.Parallel()

	const host = "alice.example.com"

	primaries := map[string]Secret{"alice": GenerateSecret(host), "bob": GenerateSecret("bob.example.com")}

	// alice has three entries in the set's order (until descending): plain, dd and
	// ee. bob's one has expired when the proxy starts.
	entries := []RetiringSecret{
		retire("alice", plainSecretOf(keyFilledFrom(0x10)), rotationAt(3*time.Hour)),
		retire("alice", ddSecretOf(keyFilledFrom(0x20)), rotationAt(2*time.Hour)),
		retire("alice", eeSecretOf(keyFilledFrom(0x30), host), rotationAt(1*time.Hour)),
		retire("bob", ddSecretOf(keyFilledFrom(0x40)), rotationAt(-1*time.Hour)),
	}

	all := []Secret{primaries["alice"], primaries["bob"]}
	for _, e := range entries {
		all = append(all, e.Secret)
	}

	for _, tc := range []struct {
		name      string
		listeners ModeSet
		want      []string
	}{
		{"no listener at all", 0, []string{"alice|plain", "alice|dd"}},
		{"a dd listener serves dd and not plain", ModeSetOf(SecretModeDD), []string{"alice|plain"}},
		{"a plain listener serves both", ModeSetOf(SecretModePlain), nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, record := newRotationProxy(t, func(opts *ProxyOpts) {
				opts.Secrets = primaries
				opts.RetiringSecrets = entries
				opts.ListenerModes = tc.listeners
				opts.RotationClock = NewRotationClock(newSteppedClock(rotationNow).now, nil)
			})

			var got []string

			for _, line := range record.named(unservedMessage) {
				assert.Equal(t, "warning", line.level)
				assert.Equal(t, []string{"mode", "secret_name"}, slices.Sorted(maps.Keys(line.fields)),
					"the name and the mode, and nothing else")

				got = append(got, line.fields["secret_name"]+"|"+line.fields["mode"])
			}

			assert.Equal(t, tc.want, got, "one line for each kept entry nobody serves, in the set's order")
			assert.Equal(t, []string{"info|bob|expired"}, ignoredLines(t, record), "bob's expired entry was dropped, not kept")
			assert.Empty(t, leaks(record.text(), all), "no line carries a key in any spelling")
		})
	}
}
