package mtglib

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// client-conns, the per-address connection cap: how many live connections one
// address may hold to a secret. It is counted from the address ledger, which
// refcounts every stream's address whether or not the per-address table has an
// entry for it, so it counts streams that were open before the cap was set and
// it holds when the table is full. It is read before the ledger admits the
// stream (the admit increments the count it would read), and before the table
// is asked for an entry, so a refused connection takes nothing from either.
// Addresses that do not stand for one place are never capped. The addresses
// here are stamped on the accepted socket: documentation ranges for places
// (keyed), the harness's own loopback and private ranges for peers that are not.

// ledgerCountsOf is the named user's live connections per address as the ledger
// holds them, or nil when there is no ledger at all.
func ledgerCountsOf(p *Proxy, name string) map[addressKey]int {
	p.liveMu.Lock()
	defer p.liveMu.Unlock()

	ledger := p.addresses[name]
	if ledger == nil {
		return nil
	}

	counts := make(map[addressKey]int, len(ledger.local))
	for key, n := range ledger.local {
		counts[key] = n
	}

	return counts
}

// liveStreamsOf is how many streams the named user has in the registry.
func liveStreamsOf(p *Proxy, name string) int {
	p.liveMu.Lock()
	defer p.liveMu.Unlock()

	return len(p.liveConns[name])
}

// liveStreamAt is the named user's live stream counted under key. The streams
// of one user are a set, so a test with several of them finds its own by the
// address admission recorded, under the lock admission wrote it under.
func liveStreamAt(t *testing.T, p *Proxy, name string, key addressKey) *streamContext {
	t.Helper()

	p.liveMu.Lock()
	defer p.liveMu.Unlock()

	for sc := range p.liveConns[name] {
		if sc.addrKey == key {
			return sc
		}
	}

	t.Fatalf("%s has no live stream from %s", name, key)

	return nil
}

// capStream is a probe stream of alice's from addr, attributed with a
// per-address cap of conns and no address limit.
func capStream(t *testing.T, probe *denyProbe, addr net.Addr, conns int) *streamContext {
	t.Helper()

	sc := probe.stream(t, addr, 0)
	sc.clientConns = conns

	return sc
}

// capProbe is a table probe whose secret set gives alice a cap of conns.
func capProbe(t *testing.T, tracking bool, conns int) *denyProbe {
	t.Helper()

	probe := newClientTableProbe(t, tracking)
	probe.proxy.secrets.Store(buildSecretSet(
		map[string]Secret{"alice": GenerateSecret("alice.example.com")}, nil, nil,
		map[string]SecretLimits{"alice": {ClientConns: conns}}))

	return probe
}

// refuseAfterHandshake opens this door from addr and requires the proxy to
// refuse the connection the way it refuses one from an address too many: after
// the handshake -- the ee door has answered the hello by then -- and by closing
// it, not relaying it. The bound is what tells the two apart: a relayed stream
// never returns by itself.
func refuseAfterHandshake(t *testing.T, ec govEntryCase, h *entryHarness, key [SecretKeyLength]byte, addr net.Addr) {
	t.Helper()

	client, done := dialProxyFrom(t, h, ec.policy, addr)
	ec.openEntry(t, client, key)

	require.True(t, govAwait(done, govDenyBudget), "a connection past the cap must be refused, not relayed")
	require.NoError(t, client.SetReadDeadline(time.Now().Add(govDenyBudget)))

	answer, err := io.ReadAll(client)
	require.NotErrorIs(t, err, os.ErrDeadlineExceeded, "the proxy must have closed the connection")

	if ec.mode == SecretModeFakeTLS {
		require.NotEmpty(t, answer, "the ee door refuses after the handshake")
		assert.EqualValues(t, 0x16, answer[0], "the hello was answered before the refusal")
	}
}

// The cap through the real door, on every door: it counts the streams that were
// open before a reload set it, it binds one address and not another, a stream
// that closes frees its slot at once, and lowering it closes nothing. A refusal
// has its own counter and moves neither the address limit's nor its event.
func TestClientConnsThroughTheDoor(t *testing.T) {
	t.Parallel()

	for _, ec := range govEntryCases() {
		t.Run(ec.name, func(t *testing.T) {
			t.Parallel()

			secret := ec.secret(t)
			h := ec.harness(t, map[string]Secret{"alice": secret}, nil)

			withCap := func(conns int) {
				t.Helper()

				require.NoError(t, h.proxy.ReplaceSecrets(SecretConfig{
					Secrets: map[string]Secret{"alice": secret},
					Limits:  map[string]SecretLimits{"alice": {ClientConns: conns}},
				}))
			}

			// A phone's two sockets, opened while nothing capped them.
			first, firstDone := dialProxyFrom(t, h, ec.policy, tcpFrom("203.0.113.7", 50001))
			firstUp := connectThrough(t, ec, h, first, "alice", secret.Key)

			second, secondDone := dialProxyFrom(t, h, ec.policy, tcpFrom("203.0.113.7", 50002))
			secondUp := connectThrough(t, ec, h, second, "alice", secret.Key)

			defer endStream(second, secondUp, secondDone)

			withCap(2)
			require.Equal(t, 2, liveStreamsOf(h.proxy, "alice"), "setting the cap closes nothing")

			// The third is one past the cap, counting the two opened before it.
			refuseAfterHandshake(t, ec, h, secret.Key, tcpFrom("203.0.113.7", 50003))

			stats := statsFor(t, h.proxy).Users["alice"]
			assert.Equal(t, 2, stats.ClientConns, "the cap reads back")
			assert.EqualValues(t, 1, stats.ClientConnsRefused)
			assert.Zero(t, stats.IPLimitRefused, "the cap is not the address limit")
			assert.EqualValues(t, 2, stats.Connections, "a refused connection was never counted")
			assert.Equal(t, map[addressKey]int{"203.0.113.7": 2}, ledgerCountsOf(h.proxy, "alice"),
				"the refusal left the ledger as it was")

			// Another place is not touched by this one's cap.
			other, otherDone := dialProxyFrom(t, h, ec.policy, tcpFrom("198.51.100.8", 50004))
			otherUp := connectThrough(t, ec, h, other, "alice", secret.Key)

			defer endStream(other, otherUp, otherDone)

			// A stream that ends gives its slot back at once.
			endStream(first, firstUp, firstDone)

			again, againDone := dialProxyFrom(t, h, ec.policy, tcpFrom("203.0.113.7", 50005))
			againUp := connectThrough(t, ec, h, again, "alice", secret.Key)

			defer endStream(again, againUp, againDone)

			// Lowered under the streams already open: nothing is dropped, and
			// the next one is refused.
			withCap(1)
			require.Equal(t, 3, liveStreamsOf(h.proxy, "alice"), "lowering the cap never drops a stream")

			refuseAfterHandshake(t, ec, h, secret.Key, tcpFrom("203.0.113.7", 50006))

			stats = statsFor(t, h.proxy).Users["alice"]
			assert.Equal(t, 1, stats.ClientConns)
			assert.EqualValues(t, 2, stats.ClientConnsRefused)
			assert.Zero(t, stats.IPLimitRefused)
			assert.EqualValues(t, 3, stats.Connections)
			assert.Zero(t, h.events.count(func(evt Event) bool {
				_, ok := evt.(EventIPLimited)

				return ok
			}), "a cap refusal is announced to nobody")
		})
	}
}

// Review Focus 1: a peer that is not one place -- loopback, a private range, a
// v4-mapped private address -- is never capped, however many connections it
// opens, and is governed as the secret's rest entry. A place in the same secret
// still is capped.
func TestClientConnsNeverCapsAnUnkeyedPeer(t *testing.T) {
	t.Parallel()

	ec := govEntryCases()[1]
	secret := ec.secret(t)
	h := ec.harness(t, map[string]Secret{"alice": secret}, map[string]SecretLimits{"alice": {ClientConns: 1}})

	require.False(t, h.proxy.trackClientIPs, "the cap alone is what asks for entries")

	for range 2 {
		client, done := h.dialProxy(t, ec.policy)
		upstream := connectThrough(t, ec, h, client, "alice", secret.Key)

		defer endStream(client, upstream, done)
	}

	for i, ip := range []string{"10.1.2.3", "10.1.2.3", "::ffff:192.168.1.1", "::ffff:192.168.1.1"} {
		client, done := dialProxyFrom(t, h, ec.policy, tcpFrom(ip, 50001+i))
		upstream := connectThrough(t, ec, h, client, "alice", secret.Key)

		defer endStream(client, upstream, done)
	}

	assert.Equal(t, 6, liveStreamsOf(h.proxy, "alice"), "no unkeyed peer was capped")
	assert.Zero(t, h.proxy.stats.users["alice"].clientConnsRefused.Load())

	rest := liveStreamAt(t, h.proxy, "alice", "127.0.0.1").addrEntry.Load()
	require.NotNil(t, rest)
	assert.True(t, rest.rest, "an unkeyed peer is governed as the rest entry")
	assert.Same(t, rest, liveStreamAt(t, h.proxy, "alice", "10.1.2.3").addrEntry.Load())
	assert.Same(t, rest, liveStreamAt(t, h.proxy, "alice", "192.168.1.1").addrEntry.Load())

	place, placeDone := dialProxyFrom(t, h, ec.policy, tcpFrom("203.0.113.7", 50010))
	placeUp := connectThrough(t, ec, h, place, "alice", secret.Key)

	defer endStream(place, placeUp, placeDone)

	refuseAfterHandshake(t, ec, h, secret.Key, tcpFrom("203.0.113.7", 50011))
	assert.EqualValues(t, 1, h.proxy.stats.users["alice"].clientConnsRefused.Load())
}

// Review Focus 2: the cap counts in the ledger's unit. An IPv4 address and its
// v4-mapped spelling are one place and share one count; so are two addresses of
// one IPv6 /64, and the next /64 is another place.
func TestClientConnsCountsInTheLedgersUnit(t *testing.T) {
	t.Parallel()

	probe := capProbe(t, false, 2)
	p := probe.proxy

	mapped := &net.TCPAddr{IP: net.ParseIP("::ffff:203.0.113.5"), Port: 50001}
	plain := &net.TCPAddr{IP: net.ParseIP("203.0.113.5").To4(), Port: 50002}

	require.Len(t, mapped.IP, net.IPv6len, "the mapped spelling really is the 16-byte form")
	require.Len(t, plain.IP, net.IPv4len)

	require.Equal(t, DenyNone, p.tryRegisterConn(capStream(t, probe, mapped, 2)))
	require.Equal(t, DenyNone, p.tryRegisterConn(capStream(t, probe, plain, 2)))
	assert.Equal(t, DenyClientConns, p.tryRegisterConn(capStream(t, probe, plain, 2)),
		"two sockets as one spelling and the other are two connections of one place")
	assert.Equal(t, DenyClientConns, p.tryRegisterConn(capStream(t, probe, mapped, 2)))

	require.Equal(t, DenyNone, p.tryRegisterConn(capStream(t, probe, tcpFrom("2001:db8::1", 50003), 2)))
	require.Equal(t, DenyNone, p.tryRegisterConn(capStream(t, probe, tcpFrom("2001:db8::ffff:2", 50004), 2)))
	assert.Equal(t, DenyClientConns, p.tryRegisterConn(capStream(t, probe, tcpFrom("2001:db8::3", 50005), 2)),
		"one /64 is one place")
	assert.Equal(t, DenyNone, p.tryRegisterConn(capStream(t, probe, tcpFrom("2001:db8:0:1::1", 50006), 2)),
		"and the next /64 is another")

	assert.Equal(t, map[addressKey]int{"203.0.113.5": 2, "2001:db8::/64": 2, "2001:db8:0:1::/64": 1},
		probe.ledgerCounts())
}

// The cap is read from the ledger, not the table: with the secret's part of the
// table full, a new address joins the rest entry and is still held to the cap.
// A refused connection takes no entry and is not an overflow -- the cap sits
// before the table -- so the rest entry, the client count and the overflow count
// are what the admitted connection left them.
func TestClientConnsHoldsWhenTheTableIsFull(t *testing.T) {
	t.Parallel()

	probe := capProbe(t, false, 1)
	p := probe.proxy
	table := p.clients

	fillClients(t, table, "alice", maxClientsPerSecret)

	admitted := capStream(t, probe, tcpFrom("203.0.113.50", 50001), 1)
	require.Equal(t, DenyNone, p.tryRegisterConn(admitted))

	rest := admitted.addrEntry.Load()
	require.NotNil(t, rest)
	require.True(t, rest.rest, "a full table sends a new place to the rest entry")
	require.EqualValues(t, 1, table.overflow("alice"))

	for port := 50002; port < 50005; port++ {
		refused := capStream(t, probe, tcpFrom("203.0.113.50", port), 1)

		assert.Equal(t, DenyClientConns, p.tryRegisterConn(refused), "the cap holds with no entry to count on")
		assert.Nil(t, refused.addrEntry.Load())
	}

	assert.EqualValues(t, 1, table.overflow("alice"), "a refused connection is not an overflow")
	assert.Equal(t, 1, clientRefs(table, rest), "and holds no part of the rest entry")
	assert.Equal(t, maxClientsPerSecret, table.clients("alice"))
	assert.Equal(t, map[addressKey]int{"203.0.113.50": 1}, probe.ledgerCounts())
}

// Decision 2 in the one case where the ledger and the table disagree about an
// address: its streams were opened before a reload set the cap, and the
// reload's backfill found the table full, so they hold the rest entry and the
// address has no entry of its own. A cap counted from the table would read
// nothing here; the ledger counts them.
func TestClientConnsCountsStreamsTheTableHasNoRoomFor(t *testing.T) {
	t.Parallel()

	probe := newClientTableProbe(t, false)
	p := probe.proxy

	fillClients(t, p.clients, "alice", maxClientsPerSecret)

	first := capStream(t, probe, tcpFrom("203.0.113.60", 50001), 0)
	second := capStream(t, probe, tcpFrom("203.0.113.60", 50002), 0)

	require.Equal(t, DenyNone, p.tryRegisterConn(first))
	require.Equal(t, DenyNone, p.tryRegisterConn(second))
	require.Nil(t, first.addrEntry.Load(), "no control and no tracking: no entry yet")

	cfg := p.secrets.Load().toConfig()
	cfg.Limits = map[string]SecretLimits{"alice": {ClientConns: 2}}

	require.NoError(t, p.ReplaceSecrets(cfg))

	rest := first.addrEntry.Load()
	require.NotNil(t, rest)
	require.True(t, rest.rest, "the backfill found the table full")
	require.Same(t, rest, second.addrEntry.Load())

	third := capStream(t, probe, tcpFrom("203.0.113.60", 50003), 2)

	assert.Equal(t, DenyClientConns, p.tryRegisterConn(third),
		"two streams opened before the cap, with no entry of their own, still count")
	assert.Equal(t, map[addressKey]int{"203.0.113.60": 2}, probe.ledgerCounts())
}

// The full table through the real door, on every door: with the secret's part
// of the table full before anyone dials, a new place is admitted to the rest
// entry and is still held to the cap, the refusal is not an overflow, and once
// every stream has ended the ledger is empty -- the refused attempts left
// nothing in it.
func TestClientConnsHoldsAtTheDoorWithAFullTable(t *testing.T) {
	t.Parallel()

	for _, ec := range govEntryCases() {
		t.Run(ec.name, func(t *testing.T) {
			t.Parallel()

			secret := ec.secret(t)
			h := ec.harness(t, map[string]Secret{"alice": secret}, map[string]SecretLimits{"alice": {ClientConns: 1}})
			table := h.proxy.clients

			fillClients(t, table, "alice", maxClientsPerSecret)

			held, heldDone := dialProxyFrom(t, h, ec.policy, tcpFrom("203.0.113.70", 50001))
			heldUp := connectThrough(t, ec, h, held, "alice", secret.Key)

			rest := liveStreamAt(t, h.proxy, "alice", "203.0.113.70").addrEntry.Load()
			require.NotNil(t, rest)
			require.True(t, rest.rest, "a full table sends a new place to the rest entry")
			require.EqualValues(t, 1, table.overflow("alice"))

			refuseAfterHandshake(t, ec, h, secret.Key, tcpFrom("203.0.113.70", 50002))
			refuseAfterHandshake(t, ec, h, secret.Key, tcpFrom("203.0.113.70", 50003))

			assert.EqualValues(t, 2, h.proxy.stats.users["alice"].clientConnsRefused.Load(),
				"the cap holds with no entry to count on")
			assert.EqualValues(t, 1, table.overflow("alice"), "a refused connection is not an overflow")
			assert.Equal(t, 1, clientRefs(table, rest))
			assert.Equal(t, map[addressKey]int{"203.0.113.70": 1}, ledgerCountsOf(h.proxy, "alice"))

			endStream(held, heldUp, heldDone)

			assert.Nil(t, ledgerCountsOf(h.proxy, "alice"), "refused attempts leave the ledger empty")
			assert.Zero(t, liveStreamsOf(h.proxy, "alice"))
		})
	}
}

// Review Focus 3 and the order of admission: the cap is read before the ledger
// admits the stream and before the table gives it an entry. A refused
// connection reaches neither step, so it takes nothing from the ledger and no
// entry from the table, and once the admitted streams close the ledger is empty.
// The cap-th connection itself is admitted: the count is the one before this
// stream, not after.
func TestClientConnsRefusesBeforeTheLedgerAndTheTable(t *testing.T) { //nolint: paralleltest // swaps a package variable
	probe := capProbe(t, true, 2)
	p := probe.proxy
	table := p.clients

	var steps []registerStep

	installRegisterStepHook(t, func(step registerStep, _ *streamContext) DenyReason {
		steps = append(steps, step)

		return DenyNone
	})

	first := capStream(t, probe, tcpFrom("203.0.113.9", 50001), 2)
	second := capStream(t, probe, tcpFrom("203.0.113.9", 50002), 2)

	require.Equal(t, DenyNone, p.tryRegisterConn(first), "below the cap")
	require.Equal(t, DenyNone, p.tryRegisterConn(second), "the cap-th connection is admitted")

	entry := second.addrEntry.Load()
	require.NotNil(t, entry)
	require.False(t, entry.rest)
	require.Equal(t, 2, clientRefs(table, entry))

	steps = nil

	refused := capStream(t, probe, tcpFrom("203.0.113.9", 50003), 2)

	assert.Equal(t, DenyClientConns, p.tryRegisterConn(refused))
	assert.Empty(t, steps, "the cap refuses before the ledger admits and before the table is asked")
	assert.False(t, refused.addrCounted)
	assert.Nil(t, refused.addrEntry.Load())
	assert.Equal(t, map[addressKey]int{"203.0.113.9": 2}, probe.ledgerCounts(), "the ledger is as it was")
	assert.Equal(t, 2, clientRefs(table, entry), "the entry is held by the admitted streams alone")
	assert.Equal(t, 1, table.clients("alice"))
	assert.Zero(t, table.overflow("alice"))
	assert.Equal(t, 2, probe.registered())

	p.unregisterConn(first)
	p.unregisterConn(second)

	assert.Nil(t, probe.ledgerCounts(), "nothing the refusal did outlives the streams that were admitted")
	assert.Equal(t, 0, clientRefs(table, entry))
}

// Admission accounts a cap refusal as admit does: its own counter, its own
// reason in the log line, no event, and the connection never counted.
func TestAdmitAccountsAClientConnsRefusal(t *testing.T) {
	t.Parallel()

	probe := capProbe(t, false, 1)
	user := probe.proxy.stats.users["alice"]

	held := capStream(t, probe, tcpFrom("198.51.100.7", 50001), 1)
	require.True(t, probe.proxy.admit(held))

	require.False(t, probe.proxy.admit(capStream(t, probe, tcpFrom("198.51.100.7", 50002), 1)))

	assert.EqualValues(t, 1, user.clientConnsRefused.Load())
	assert.Zero(t, user.ipLimitRefused.Load(), "the cap is not the address limit")
	assert.Zero(t, probe.events.count(func(Event) bool { return true }), "no event of any type")
	assert.Equal(t, []string{"client_conns"}, probe.log.denyReasons())
	assert.EqualValues(t, 1, user.connections.Load())
}

// attribute binds the cap the secret had when it matched, beside the address
// limit, read from the same snapshot.
func TestAttributeBindsTheClientConnsCap(t *testing.T) {
	t.Parallel()

	set := buildSecretSet(map[string]Secret{
		"alice": GenerateSecret("cover.example.com"),
		"bob":   GenerateSecret("cover.example.com"),
	}, nil, nil, map[string]SecretLimits{"bob": {IPLimit: 2, ClientConns: 5}})

	probe := newDenyProbe(t)

	for name, want := range map[string]int{"alice": 0, "bob": 5} {
		sc := probe.stream(t, tcpFrom("198.51.100.7", 50001), 0)

		require.Equal(t, DenyNone, probe.proxy.attribute(sc, set, indexOfName(t, set, name)))
		assert.Equal(t, want, sc.clientConns, name)
	}
}

// indexOfName is name's index in the set.
func indexOfName(t *testing.T, set *secretSet, name string) int {
	t.Helper()

	for i, n := range set.names {
		if n == name {
			return i
		}
	}

	t.Fatalf("no secret named %q", name)

	return -1
}

// The table follows the cap the way it follows track-client-ips: a secret with
// a cap gives a new keyed stream an entry at admission with tracking off, and a
// secret without one does not.
func TestClientConnsAsksForEntriesAtAdmission(t *testing.T) {
	t.Parallel()

	probe := newClientTableProbe(t, false)
	probe.proxy.secrets.Store(buildSecretSet(map[string]Secret{
		"alice": GenerateSecret("alice.example.com"),
		"bob":   GenerateSecret("bob.example.com"),
	}, nil, nil, map[string]SecretLimits{"alice": {ClientConns: 3}}))

	capped := capStream(t, probe, tcpFrom("203.0.113.9", 50001), 3)
	require.Equal(t, DenyNone, probe.proxy.tryRegisterConn(capped))

	entry := capped.addrEntry.Load()
	require.NotNil(t, entry, "a secret with a per-address control holds entries with tracking off")
	assert.False(t, entry.rest)
	assert.Equal(t, addressKey("203.0.113.9"), entry.key)

	bobs := probe.stream(t, tcpFrom("203.0.113.9", 50002), 0)
	bobs.secretName = "bob"

	require.Equal(t, DenyNone, probe.proxy.tryRegisterConn(bobs))
	assert.Nil(t, bobs.addrEntry.Load(), "a secret with none holds no entry")
	assert.Nil(t, probe.proxy.clients.snapshot("bob"))
}

// Review Focus 4 through the real door, for the first control there is: a
// reload that adds client-conns, with tracking off, gives an already-open keyed
// stream its own entry and an already-open loopback stream the secret's rest
// entry. Before it, nothing asked for either.
func TestAReloadAddingClientConnsGovernsStreamsAlreadyOpen(t *testing.T) {
	t.Parallel()

	ec := govEntryCases()[1]
	secret := ec.secret(t)
	h := ec.harness(t, map[string]Secret{"alice": secret}, nil)

	require.False(t, h.proxy.trackClientIPs)

	keyed, keyedDone := dialProxyFrom(t, h, ec.policy, tcpFrom("203.0.113.9", 50001))
	keyedUp := connectThrough(t, ec, h, keyed, "alice", secret.Key)

	defer endStream(keyed, keyedUp, keyedDone)

	local, localDone := h.dialProxy(t, ec.policy)
	localUp := connectThrough(t, ec, h, local, "alice", secret.Key)

	defer endStream(local, localUp, localDone)

	keyedStream := liveStreamAt(t, h.proxy, "alice", "203.0.113.9")
	localStream := liveStreamAt(t, h.proxy, "alice", "127.0.0.1")

	require.Nil(t, keyedStream.addrEntry.Load(), "nothing needed an entry before the reload")
	require.Nil(t, localStream.addrEntry.Load())
	require.Nil(t, h.proxy.clients.snapshot("alice"))

	require.NoError(t, h.proxy.ReplaceSecrets(SecretConfig{
		Secrets: map[string]Secret{"alice": secret},
		Limits:  map[string]SecretLimits{"alice": {ClientConns: 4}},
	}))

	own := keyedStream.addrEntry.Load()
	require.NotNil(t, own, "an open keyed stream is given its own entry")
	assert.False(t, own.rest)
	assert.Equal(t, addressKey("203.0.113.9"), own.key)

	rest := localStream.addrEntry.Load()
	require.NotNil(t, rest, "an open loopback stream joins the rest entry")
	assert.True(t, rest.rest)

	table := h.proxy.clients

	assert.Equal(t, 1, clientRefs(table, own))
	assert.Equal(t, 1, clientRefs(table, rest))
	assert.Equal(t, 1, table.clients("alice"))
	assert.Equal(t, 2, liveStreamsOf(h.proxy, "alice"), "and the reload closed nothing")
}

// The set knows once, when it is built, whether any of its secrets has a
// per-address control; a proxy that keeps no addresses asks it before looking a
// secret up. client-conns is such a control and ip-limit is not.
func TestTheSetKnowsWhetherAnySecretHasAClientControl(t *testing.T) {
	t.Parallel()

	assert.True(t, SecretLimits{ClientConns: 1}.hasClientControl())
	assert.False(t, SecretLimits{}.hasClientControl())
	assert.False(t, SecretLimits{IPLimit: 3, SpeedBytesPerSecond: 1 << 20}.hasClientControl(),
		"limits on the secret as a whole are not per-address controls")

	secrets := map[string]Secret{
		"alice": GenerateSecret("alice.example.com"),
		"bob":   GenerateSecret("bob.example.com"),
		"carol": GenerateSecret("carol.example.com"),
	}

	assert.False(t, buildSecretSet(secrets, nil, nil, nil).anyClientControl())
	assert.False(t, buildSecretSet(secrets, nil, nil,
		map[string]SecretLimits{"alice": {IPLimit: 2}}).anyClientControl())
	assert.True(t, buildSecretSet(secrets, nil, nil,
		map[string]SecretLimits{"alice": {IPLimit: 2}, "bob": {ClientConns: 3}}).anyClientControl(),
		"one secret of several is enough")

	// An OR over every secret, not the answer of the last one looked at: the
	// controlled secret sorts first, and the ones after it have limits of
	// their own that carry no control.
	assert.True(t, buildSecretSet(secrets, nil, nil,
		map[string]SecretLimits{"alice": {ClientConns: 3}, "bob": {IPLimit: 2}}).anyClientControl(),
		"a control on the first secret is not undone by a later one without")
	assert.True(t, buildSecretSet(secrets, nil, nil, map[string]SecretLimits{
		"alice": {ClientConns: 3},
		"bob":   {IPLimit: 2},
		"carol": {SpeedBytesPerSecond: 1 << 20},
	}).anyClientControl(), "nor by the last of three")

	var none *secretSet

	assert.False(t, none.anyClientControl())
}

// The set's answer is the OR of every secret's: with tracking on or off, with
// no limits and with each SecretLimits field set alone on one secret of two,
// clientEntriesWantedBy says yes exactly when clientEntriesWanted says yes for
// some secret. Admission and the backfill skip the per-secret question on the
// set's no, so a reason added to the per-secret predicate and not to the set's
// would silently stop entries; one added only to the set's would cost the
// common case its free admission.
func TestTheSetAndItsSecretsAgreeOnEntries(t *testing.T) {
	t.Parallel()

	typ := reflect.TypeFor[SecretLimits]()
	secrets := map[string]Secret{
		"alice": GenerateSecret("alice.example.com"),
		"bob":   GenerateSecret("bob.example.com"),
	}

	for _, tracking := range []bool{false, true} {
		p := &Proxy{trackClientIPs: tracking}

		for i := -1; i < typ.NumField(); i++ {
			var lim SecretLimits

			label := "no limits"

			if i >= 0 {
				nonZeroLimitField(t, &lim, i)

				label = typ.Field(i).Name
			}

			set := buildSecretSet(secrets, nil, nil, map[string]SecretLimits{"bob": lim})

			wanted := false

			for _, name := range set.names {
				secretLim, ok := set.limitsOf(name)
				require.True(t, ok)

				wanted = wanted || p.clientEntriesWanted(secretLim)
			}

			assert.Equal(t, wanted, p.clientEntriesWantedBy(set), "tracking %v, %s", tracking, label)
		}
	}

	assert.False(t, (&Proxy{}).clientEntriesWantedBy(nil), "a nil set wants nothing")
}

// nonZeroLimitField sets field i of lim to a value that is not its zero, by
// kind, and fails the test on a kind it does not know: a field added to
// SecretLimits must be handled here, not skipped.
func nonZeroLimitField(t *testing.T, lim *SecretLimits, i int) {
	t.Helper()

	field := reflect.ValueOf(lim).Elem().Field(i)

	switch {
	case field.Type() == reflect.TypeFor[time.Time]():
		field.Set(reflect.ValueOf(time.Now().Add(time.Hour)))
	case field.Kind() == reflect.Bool:
		field.SetBool(true)
	case field.CanInt():
		field.SetInt(1)
	default:
		t.Fatalf("SecretLimits.%s is a %s, which this test does not know how to set",
			reflect.TypeFor[SecretLimits]().Field(i).Name, field.Type())
	}
}

// limitsNotReadBack lists the SecretLimits fields that GET /secrets/{name} and
// the /stats user object legitimately do not read back, each with the reason.
// Empty: every limit is read back today. A field added to SecretLimits is read
// back on both, or is listed here with a reason -- it cannot skip silently.
var limitsNotReadBack = map[string]string{}

// readBackOf is alice's limits as the API reads them back: her GET
// /secrets/{name} object and her user object on /stats, decoded loosely so
// that any field moving shows.
func readBackOf(t *testing.T, p *Proxy) (map[string]any, map[string]any) {
	t.Helper()

	secret := map[string]any{}
	require.NoError(t, json.Unmarshal(doAPI(t, p, "", http.MethodGet, "/secrets/alice", "").Body.Bytes(), &secret))

	users, ok := statsRaw(t, doAPI(t, p, "", http.MethodGet, "/stats", "").Body.Bytes())["users"].(map[string]any)
	require.True(t, ok)

	user, ok := users["alice"].(map[string]any)
	require.True(t, ok)

	return secret, user
}

// Every field of SecretLimits is a limit: set any one of them alone and the
// limits are not zero, they survive the copy every API mutation starts from,
// and they are read back. IsZero decides whether a secret's limits are kept at
// all -- by the config, by PUT and POST /secrets, by PutSecret and by toConfig
// -- so a field it forgets is silently dropped by each of them; and a limit the
// read-backs (fillLimitInfo, the handleStats overlay) forget is enforced but
// invisible. Walked by reflection, so a field added later is covered without
// anyone remembering to add it here.
func TestEveryLimitFieldIsALimit(t *testing.T) {
	t.Parallel()

	typ := reflect.TypeFor[SecretLimits]()
	require.Positive(t, typ.NumField())

	for name := range limitsNotReadBack {
		_, ok := typ.FieldByName(name)
		require.True(t, ok, "limitsNotReadBack names %s, which SecretLimits does not have", name)
	}

	for i := range typ.NumField() {
		name := typ.Field(i).Name

		t.Run(name, func(t *testing.T) {
			t.Parallel()

			var lim SecretLimits

			nonZeroLimitField(t, &lim, i)

			assert.False(t, lim.IsZero(), "a limit with only %s set is still a limit", name)

			alice := GenerateSecret("alice.example.com")
			set := buildSecretSet(map[string]Secret{"alice": alice}, nil, nil, map[string]SecretLimits{"alice": lim})

			kept, ok := set.toConfig().Limits["alice"]
			require.True(t, ok, "toConfig keeps a secret whose only limit is %s", name)
			assert.Equal(t, lim, kept)

			if reason, exempt := limitsNotReadBack[name]; exempt {
				t.Logf("%s is not read back: %s", name, reason)

				return
			}

			p := newAPITestProxy(map[string]Secret{"alice": alice})
			secretBefore, userBefore := readBackOf(t, p)

			p.secrets.Store(set)

			secretAfter, userAfter := readBackOf(t, p)

			assert.NotEqual(t, secretBefore, secretAfter, "GET /secrets/{name} reads %s back", name)
			assert.NotEqual(t, userBefore, userAfter, "the /stats user object reads %s back", name)
		})
	}
}

// limitFieldSamples is a valid value for each string field of the secrets API's
// limit fields, by JSON name. Booleans are sent as true and numbers as 1; a
// string field with no sample here fails the test below rather than skipping.
var limitFieldSamples = map[string]string{
	"quota":       `"1000"`,
	"quota_reset": `"monthly"`,
	"expires":     `"2030-01-01"`,
	"speed":       `"1mbit"`,
	"speed_up":    `"1mbit"`,
	"speed_down":  `"1mbit"`,
}

// Every SecretLimits field can be set through the secrets API: each API field,
// sent alone, parses into a limit, and between them they reach every field of
// SecretLimits. A field added to SecretLimits without its API field and its
// line in parse fails here.
func TestEveryLimitFieldTravelsTheAPI(t *testing.T) {
	t.Parallel()

	reached := map[string]bool{}
	fields := reflect.TypeFor[limitFields]()

	for i := range fields.NumField() {
		field := fields.Field(i)
		name, _, _ := strings.Cut(field.Tag.Get("json"), ",")

		value, ok := limitFieldSamples[name]

		switch {
		case ok:
		case field.Type.Kind() == reflect.Bool:
			value = "true"
		case field.Type.Kind() == reflect.Int:
			value = "1"
		default:
			t.Fatalf("limit field %s is a %s with no sample in limitFieldSamples", name, field.Type)
		}

		var sent limitFields

		require.NoError(t, json.Unmarshal([]byte(`{"`+name+`":`+value+`}`), &sent), name)

		lim, err := sent.parse()
		require.NoError(t, err, name)
		require.False(t, lim.IsZero(), "%s alone parses into a limit", name)

		parsed := reflect.ValueOf(lim)
		for j := range parsed.NumField() {
			if !parsed.Field(j).IsZero() {
				reached[parsed.Type().Field(j).Name] = true
			}
		}
	}

	for i := range reflect.TypeFor[SecretLimits]().NumField() {
		name := reflect.TypeFor[SecretLimits]().Field(i).Name
		assert.True(t, reached[name], "no API field sets SecretLimits.%s", name)
	}
}

// The cap travels the API as client_conns: PUT sets it and answers 200, it reads
// back on GET /secrets/{name} and inside the user object on /stats, a POST that
// sends it keeps it and one that does not clears it, a mutation of another
// secret leaves it alone, and a negative value is refused by name with the
// running cap untouched.
func TestClientConnsThroughTheAPI(t *testing.T) {
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

	assert.NotContains(t, userOf(t), "client_conns", "absent while unset")
	assert.NotContains(t, userOf(t), "client_conns_refused")

	rec := doAPI(t, p, "", http.MethodPut, "/secrets",
		`{"secrets":{"alice":{"secret":"`+alice.Hex()+`","client_conns":3}}}`)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.JSONEq(t, `{"status":"ok"}`, rec.Body.String())

	assert.Equal(t, 3, p.secrets.Load().limits[0].ClientConns, "a cap alone is kept")
	assert.Equal(t, float64(3), secretOf(t)["client_conns"])
	assert.Equal(t, float64(3), userOf(t)["client_conns"])
	assert.NotContains(t, userOf(t), "client_conns_refused", "nothing refused yet")

	p.stats.OnClientConnsRefused("alice")
	assert.Equal(t, float64(1), userOf(t)["client_conns_refused"])

	// Another secret's mutation starts from a copy of the set, which keeps it.
	require.Equal(t, http.StatusOK, doAPI(t, p, "", http.MethodPost, "/secrets",
		`{"name":"bob","secret":"`+bob.Hex()+`"}`).Code)
	assert.Equal(t, float64(3), secretOf(t)["client_conns"])

	require.Equal(t, http.StatusOK, doAPI(t, p, "", http.MethodPost, "/secrets",
		`{"name":"alice","secret":"`+alice.Hex()+`","client_conns":4}`).Code)
	assert.Equal(t, float64(4), secretOf(t)["client_conns"], "sent, it is kept")

	rec = doAPI(t, p, "", http.MethodPost, "/secrets", `{"name":"alice","secret":"`+alice.Hex()+`","client_conns":-1}`)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "client_conns")
	assert.Equal(t, float64(4), secretOf(t)["client_conns"], "a refused request leaves the running cap alone")

	require.Equal(t, http.StatusOK, doAPI(t, p, "", http.MethodPost, "/secrets",
		`{"name":"alice","secret":"`+alice.Hex()+`","ip_limit":2}`).Code)
	assert.NotContains(t, secretOf(t), "client_conns", "not sent, it is cleared")
	assert.NotContains(t, userOf(t), "client_conns")
	assert.Equal(t, float64(2), secretOf(t)["ip_limit"])
}
