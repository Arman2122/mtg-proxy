package mtglib

import (
	"context"
	"io"
	"os"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Registration re-checks the key (spec §4.3, D16). A swap stores its set before
// it takes liveMu to walk the live streams, so a stream that matched a key
// before the swap and registers after its walk would hold a key the set no
// longer accepts, and no later swap would look at it. Under liveMu, before the
// ban re-check and before anything a refusal must undo, registration loads the
// set and refuses such a stream as key_revoked. A swap that keeps the stream's
// key admits it as before.

// streamRegistered says whether sc is in the registry, under the lock the
// registry is written under.
func streamRegistered(p *Proxy, sc *streamContext) bool {
	p.liveMu.Lock()
	defer p.liveMu.Unlock()

	_, registered := p.liveConns[sc.secretName][sc]

	return registered
}

// L5, the plain re-key variant: the existing race, through the real doors. The
// swap runs after the door has attributed the stream and before admission, so
// the stream holds a key the set no longer has. It is refused at registration
// under its own reason, never enters the registry, and leaves the door the way
// any refusal at registration does: closed after the server's flight on
// FakeTLS, through the one deny exit on an obfuscated listener.
func TestARekeyAfterAttributionIsRefusedAtRegistration(t *testing.T) { //nolint: paralleltest // swaps a package variable
	for _, ec := range govEntryCases() {
		t.Run(ec.name, func(t *testing.T) {
			secret := ec.secret(t)
			h := ec.harness(t, map[string]Secret{"alice": secret}, nil)

			record := &denyProbeRecord{}
			h.proxy.logger = denyProbeLogger{record: record}

			h.proxy.stats.mu.RLock()
			user := h.proxy.stats.users["alice"]
			h.proxy.stats.mu.RUnlock()

			// Minted here: the hook runs on the stream's goroutine, where a
			// failed require could not stop the test.
			cfg := h.proxy.secrets.Load().toConfig()
			cfg.Secrets["alice"] = ec.secret(t)

			var (
				fired    atomic.Bool
				hookedAs string
				swapErr  error
			)

			installAfterAttributeHook(t, func(sc *streamContext) {
				if !fired.CompareAndSwap(false, true) {
					return
				}

				hookedAs = sc.secretName
				swapErr = h.proxy.ReplaceSecrets(cfg)
			})

			client, done := dialProxyFrom(t, h, ec.policy, tcpFrom("203.0.113.9", 50001))
			ec.openEntry(t, client, secret.Key)

			require.True(t, govAwait(done, govDenyBudget),
				"a stream whose key was re-keyed away after attribution must be refused, not relayed")

			require.True(t, fired.Load(), "the swap ran between attribution and admission")
			require.NoError(t, swapErr)
			require.Equal(t, "alice", hookedAs, "the stream was attributed before the swap")
			require.NotEqual(t, secret.Key, h.proxy.secrets.Load().secrets[0].Key, "and the swap re-keyed its name")

			require.NoError(t, client.SetReadDeadline(time.Now().Add(govDenyBudget)))

			reply, err := io.ReadAll(client)
			assert.NotErrorIs(t, err, os.ErrDeadlineExceeded, "the proxy must have closed the connection")

			if ec.mode == SecretModeFakeTLS {
				require.NotEmpty(t, reply, "the server's flight went out before registration")
				assert.EqualValues(t, 0x16, reply[0], "and it opens with a handshake record")
				assert.Zero(t, h.proxy.obfsStats.denied.Load())
			} else {
				assert.Empty(t, reply, "an obfuscated refusal writes nothing back")
				assert.EqualValues(t, 1, h.proxy.obfsStats.denied.Load(), "it takes the obfuscated door's deny exit")
			}

			assert.Equal(t, []string{"key_revoked"}, record.denyReasons(),
				"refused under its own reason, on the line every refusal writes")
			assert.Zero(t, liveStreamsOf(h.proxy, "alice"), "the stream never entered the registry")
			assert.Zero(t, user.connections.Load(), "a refused stream was never counted")
			assert.Zero(t, user.ipLimitRefused.Load())
			assert.Zero(t, user.clientConnsRefused.Load())
			assert.Nil(t, ledgerCountsOf(h.proxy, "alice"), "the ledger is as it was")
			assert.Zero(t, h.network.telegramDials())
			assert.Zero(t, h.events.frontings(), "refused after the door's exchange, not fronted")
		})
	}
}

// L5b, the plain re-key variant (M1′ of the second review): a complete swap,
// from its Store to the end of its walk, runs at the one instant where loading
// the set before taking liveMu and loading it after differ -- just before the
// lock. Loaded before, the stream would hold the set the swap replaced and
// register after the walk it waited on. Loaded under the lock, it is refused.
func TestARekeyJustBeforeTheRegistrationLockIsRefused(t *testing.T) { //nolint: paralleltest // swaps a package variable
	probe := newClientTableProbe(t, false)
	p := probe.proxy
	set := p.secrets.Load()
	alice := slices.Index(set.names, "alice")

	// A place already held under the old key: the swap's walk closes it, which
	// shows the walk ran before the stream took the lock, and the ledger it
	// leaves is what the refusal must leave as it found it. A hand-built stream
	// has no ServeConn to unregister it, so it stays counted.
	held := probe.stream(t, tcpFrom("198.51.100.7", 50001), 0)
	require.Equal(t, DenyNone, p.attribute(held, set, alice))
	require.Equal(t, DenyNone, p.tryRegisterConn(held))

	cfg := set.toConfig()
	cfg.Secrets["alice"] = GenerateSecret("alice.example.com")

	sc := probe.stream(t, tcpFrom("203.0.113.9", 50002), 0)
	require.Equal(t, DenyNone, p.attribute(sc, set, alice))

	before := probe.ledgerCounts()
	require.Equal(t, map[addressKey]int{"198.51.100.7": 1}, before)

	swapped := false

	installBeforeRegisterLockHook(t, func(hooked *streamContext) {
		if hooked != sc || swapped {
			return
		}

		swapped = true

		require.NoError(t, p.ReplaceSecrets(cfg))
	})

	assert.Equal(t, DenyKeyRevoked, p.tryRegisterConn(sc))

	require.True(t, swapped, "the swap ran just before the registration lock")
	assert.ErrorIs(t, held.Err(), context.Canceled, "the swap's walk had run by then")
	assert.False(t, streamRegistered(p, sc), "the refused stream is not in liveConns")
	assert.Equal(t, 1, probe.registered(), "only the stream registered before the swap is")
	assert.False(t, sc.addrCounted)
	assert.Nil(t, sc.addrEntry.Load())
	assert.Equal(t, before, probe.ledgerCounts(), "the ledger is as it was")
}

// L7, its second half: the key re-check precedes the ban re-check. A stream
// that matched alice's old key from a place banned after it was attributed is
// refused as key_revoked, not as banned: its key is the first thing that no
// longer holds.
func TestARevokedKeyFromABannedPlaceIsRefusedAsKeyRevoked(t *testing.T) {
	t.Parallel()

	probe, _ := banProbe(t, false)
	p := probe.proxy
	set := p.secrets.Load()

	sc := probe.stream(t, tcpFrom("203.0.113.9", 50001), 0)
	require.Equal(t, DenyNone, p.attribute(sc, set, slices.Index(set.names, "alice")),
		"neither banned nor revoked yet")

	mustBan(t, p, "alice", `{"ips":["203.0.113.9"]}`)

	cfg := set.toConfig()
	cfg.Secrets["alice"] = GenerateSecret("alice.example.com")
	require.NoError(t, p.ReplaceSecrets(cfg))
	require.True(t, isBanned(p, "alice", "203.0.113.9"), "a re-key keeps the name's bans")

	require.False(t, p.admit(sc))

	assert.Equal(t, []string{"key_revoked"}, probe.log.denyReasons(), "the key re-check comes first")
	assert.False(t, streamRegistered(p, sc))
	assert.Nil(t, probe.ledgerCounts(), "the ledger is as it was")
}

// A swap that keeps the stream's key -- here an advertising tag change -- runs
// between attribution and admission, and the stream is admitted as before: the
// re-check refuses only a key the set no longer accepts, not a stream whose set
// was replaced.
func TestAnUnrelatedSwapBeforeRegistrationStillAdmits(t *testing.T) { //nolint: paralleltest // swaps a package variable
	tag := [AdTagLength]byte{1, 2, 3}

	for _, ec := range govEntryCases() {
		t.Run(ec.name, func(t *testing.T) {
			secret := ec.secret(t)
			h := ec.harness(t, map[string]Secret{"alice": secret}, nil)

			cfg := h.proxy.secrets.Load().toConfig()
			cfg.SecretAdTags = map[string][AdTagLength]byte{"alice": tag}

			var (
				fired   atomic.Bool
				swapErr error
			)

			installAfterAttributeHook(t, func(*streamContext) {
				if fired.CompareAndSwap(false, true) {
					swapErr = h.proxy.ReplaceSecrets(cfg)
				}
			})

			client, done := dialProxyFrom(t, h, ec.policy, tcpFrom("203.0.113.9", 50001))
			upstream := connectThrough(t, ec, h, client, "alice", secret.Key)

			stream := h.liveStream(t, "alice")
			require.NotNil(t, stream)

			endStream(client, upstream, done)

			require.True(t, fired.Load(), "the swap ran between attribution and admission")
			require.NoError(t, swapErr)

			set := h.proxy.secrets.Load()
			require.NotNil(t, set.adTags[0], "the swap replaced the set")
			assert.Equal(t, tag, *set.adTags[0])
			assert.Equal(t, secret.Key, set.secrets[0].Key, "and kept alice's key")
			assert.Equal(t, secret.Key[:], stream.matchedSecretKey, "the key the stream registered under")
		})
	}
}

// A key_revoked refusal is logged under its reason and counted nowhere: not as
// an address-limit refusal, not as a connection-cap one, and no event. The
// reason has its label and sits after the existing ones, so nothing already
// numbered moves.
func TestKeyRevokedIsLoggedAndNotCounted(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "key_revoked", DenyKeyRevoked.String())
	assert.Less(t, DenyBanned, DenyKeyRevoked)

	probe := newClientTableProbe(t, false)
	p := probe.proxy
	user := p.stats.users["alice"]
	set := p.secrets.Load()

	sc := probe.stream(t, tcpFrom("198.51.100.7", 50001), 0)
	require.Equal(t, DenyNone, p.attribute(sc, set, slices.Index(set.names, "alice")))

	cfg := set.toConfig()
	cfg.Secrets["alice"] = GenerateSecret("alice.example.com")
	require.NoError(t, p.ReplaceSecrets(cfg))

	events := probe.events.count(func(Event) bool { return true })

	require.False(t, p.admit(sc))

	assert.Equal(t, []string{"key_revoked"}, probe.log.denyReasons(),
		"logged under its reason, on the line every refusal writes")
	assert.Zero(t, user.ipLimitRefused.Load(), "ip_limit_refused does not move")
	assert.Zero(t, user.clientConnsRefused.Load(), "client_conns_refused does not move")
	assert.Equal(t, events, probe.events.count(func(Event) bool { return true }), "no event of any type")
	assert.Zero(t, user.connections.Load(), "a refused connection was never counted")
	assert.Zero(t, probe.registered())
	assert.Nil(t, probe.ledgerCounts())
}

// attribute records the set it matched against, and registration lets go of it:
// a stream lives for hours and must not pin a whole old set, candidates and pad
// states, for that long. The key it matched is kept.
func TestRegistrationReleasesTheAttributedSet(t *testing.T) {
	t.Parallel()

	probe := newClientTableProbe(t, false)
	p := probe.proxy
	set := p.secrets.Load()
	alice := slices.Index(set.names, "alice")

	sc := probe.stream(t, tcpFrom("198.51.100.7", 50001), 0)
	require.Equal(t, DenyNone, p.attribute(sc, set, alice))
	require.Same(t, set, sc.attrSet, "attribute records the set it matched against")

	key := sc.matchedSecretKey
	require.Equal(t, set.secrets[alice].Key[:], key)

	require.True(t, p.admit(sc))

	assert.Nil(t, sc.attrSet, "a registered stream does not pin the set it was attributed from")
	require.Len(t, sc.matchedSecretKey, len(key), "its key is kept")
	assert.Same(t, &key[0], &sc.matchedSecretKey[0], "the very key attribute bound")
	assert.Equal(t, set.secrets[alice].Key[:], sc.matchedSecretKey)

	p.release(sc)
}

// accepts in its primary form: a set accepts, for a name it holds, that name's
// primary key and nothing else, at any time.
func TestAcceptsPrimaryForm(t *testing.T) {
	t.Parallel()

	alice := GenerateSecret("alice.example.com")
	bob := GenerateSecret("bob.example.com")
	rekeyed := GenerateSecret("alice.example.com")
	set := buildSecretSet(map[string]Secret{"alice": alice, "bob": bob}, nil, nil, nil)
	now := time.Now()

	var none *secretSet

	assert.False(t, none.accepts("alice", alice.Key[:], now), "a nil set holds nothing")
	assert.False(t, set.accepts("carol", alice.Key[:], now), "a name the set does not hold")
	assert.False(t, set.accepts("alice", bob.Key[:], now), "another name's key")
	assert.False(t, set.accepts("alice", rekeyed.Key[:], now), "another key")
	assert.False(t, set.accepts("alice", alice.Key[:8], now), "part of the key")
	assert.False(t, set.accepts("alice", nil, now), "no key at all")

	assert.True(t, set.accepts("alice", alice.Key[:], now), "the name's primary")
	assert.True(t, set.accepts("bob", bob.Key[:], now))
	assert.True(t, set.accepts("alice", alice.Key[:], time.Time{}), "the primary is accepted whatever the time")
}
