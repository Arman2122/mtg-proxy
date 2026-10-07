package mtglib

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The per-address table as the proxy uses it: an entry is taken at admission,
// after the address ledger, only where something needs one; it is let go when
// the stream ends; a reload reaches streams that were open before it; a removed
// secret takes its entries with it. The addresses here are stamped on the
// accepted socket, documentation ranges for places (keyed) and the harness's
// own loopback for a peer that is not one.

// entryByKey is the named secret's entry for key, or nil.
func entryByKey(table *clientTable, name string, key addressKey) *clientEntry {
	for _, entry := range table.snapshot(name) {
		if !entry.rest && entry.key == key {
			return entry
		}
	}

	return nil
}

// requireOnlyEntry asserts that the table holds exactly want for name, by
// identity: two entries with equal contents are still two addresses.
func requireOnlyEntry(t *testing.T, table *clientTable, name string, want *clientEntry) {
	t.Helper()

	snapshot := table.snapshot(name)
	require.Len(t, snapshot, 1)
	require.Same(t, want, snapshot[0])
}

// awaitUpstreamRecorded waits until every live stream of name has recorded its
// Telegram socket. The upstream has the handshake a moment before the stream
// records the socket, and a stream revoked inside that moment reaches the relay
// with no upstream at all -- a race of doTelegramCall's own, which a test that
// revokes streams right after connecting them must not step into.
func awaitUpstreamRecorded(t *testing.T, p *Proxy, name string) {
	t.Helper()

	require.Eventually(t, func() bool {
		p.liveMu.Lock()

		streams := make([]*streamContext, 0, len(p.liveConns[name]))
		for sc := range p.liveConns[name] {
			streams = append(streams, sc)
		}

		p.liveMu.Unlock()

		for _, sc := range streams {
			if sc.telegram() == nil {
				return false
			}
		}

		return len(streams) > 0
	}, 5*time.Second, time.Millisecond, "%s's streams never recorded their Telegram socket", name)
}

// newClientTableProbe is a denyProbe with a table and a secret set of one ee
// secret, "alice", which is everything admission, a reload and the table touch.
func newClientTableProbe(t *testing.T, tracking bool) *denyProbe {
	t.Helper()

	probe := newDenyProbe(t)
	probe.proxy.trackClientIPs = tracking
	probe.proxy.clients = newClientTable(addrClock{})
	probe.proxy.doppelGanger = idleGanger()
	probe.proxy.secrets.Store(buildSecretSet(
		map[string]Secret{"alice": GenerateSecret("alice.example.com")}, nil, nil, nil))

	return probe
}

// A keyed address gets an entry when it connects, every socket from it holds
// the same one, and the entry outlives them: on every door.
func TestAClientEntryFollowsItsConnections(t *testing.T) {
	t.Parallel()

	for _, ec := range govEntryCases() {
		t.Run(ec.name, func(t *testing.T) {
			t.Parallel()

			secret := ec.secret(t)
			h := ec.harness(t, map[string]Secret{"alice": secret}, nil)
			h.proxy.trackClientIPs = true

			table := h.proxy.clients
			require.NotNil(t, table, "the harness builds the table, as NewProxy does")

			client, done := dialProxyFrom(t, h, ec.policy, tcpFrom("203.0.113.7", 50001))
			upstream := connectThrough(t, ec, h, client, "alice", secret.Key)

			entry := h.liveStream(t, "alice").addrEntry.Load()
			require.NotNil(t, entry, "a tracked, keyed address is given an entry of its own")

			assert.False(t, entry.rest)
			assert.Equal(t, addressKey("203.0.113.7"), entry.key)
			assert.Equal(t, 1, clientRefs(table, entry))
			requireOnlyEntry(t, table, "alice", entry)

			sibling, siblingDone := dialProxyFrom(t, h, ec.policy, tcpFrom("203.0.113.7", 50002))
			siblingUp := connectThrough(t, ec, h, sibling, "alice", secret.Key)

			assert.Equal(t, 2, clientRefs(table, entry), "a second socket from the same place holds the same entry")

			endStream(sibling, siblingUp, siblingDone)
			assert.Equal(t, 1, clientRefs(table, entry))

			endStream(client, upstream, done)
			assert.Equal(t, 0, clientRefs(table, entry), "every stream let go of it")
			requireOnlyEntry(t, table, "alice", entry)
		})
	}
}

// Decision 3: a secret with neither track-client-ips nor a per-address control
// holds no entry at all -- not for a keyed address, not a rest entry for an
// unkeyed one. The data path then reads a nil pointer and the table costs
// nothing. The ledger still counts the stream: the connection cap reads the
// ledger, not the table.
func TestNoClientEntryWhenNothingNeedsOne(t *testing.T) {
	t.Parallel()

	ec := govEntryCases()[1]
	secret := ec.secret(t)
	h := ec.harness(t, map[string]Secret{"alice": secret}, nil)

	require.False(t, h.proxy.trackClientIPs)
	require.NotNil(t, h.proxy.clients)

	keyed, keyedDone := dialProxyFrom(t, h, ec.policy, tcpFrom("203.0.113.7", 50001))
	keyedUp := connectThrough(t, ec, h, keyed, "alice", secret.Key)

	defer endStream(keyed, keyedUp, keyedDone)

	stream := h.liveStream(t, "alice")
	assert.Nil(t, stream.addrEntry.Load(), "nothing asked for an entry")
	assert.True(t, stream.addrCounted, "but the ledger counts the stream all the same")

	local, localDone := h.dialProxy(t, ec.policy)
	localUp := connectThrough(t, ec, h, local, "alice", secret.Key)

	defer endStream(local, localUp, localDone)

	assert.Nil(t, h.proxy.clients.snapshot("alice"), "not even a rest entry")
	assert.Zero(t, h.proxy.clients.clients("alice"))
}

// Review Focus 1 and 2 through the door: a loopback peer is not a place and
// joins the rest entry, which is not a client and not an overflow; an IPv4
// address and its v4-mapped spelling are one place, and so is an IPv6 /64.
func TestUnkeyedAndSharedAddressesThroughTheDoor(t *testing.T) {
	t.Parallel()

	ec := govEntryCases()[1]
	secret := ec.secret(t)
	h := ec.harness(t, map[string]Secret{"alice": secret}, nil)
	h.proxy.trackClientIPs = true

	table := h.proxy.clients

	local, localDone := h.dialProxy(t, ec.policy)
	localUp := connectThrough(t, ec, h, local, "alice", secret.Key)

	rest := h.liveStream(t, "alice").addrEntry.Load()
	require.NotNil(t, rest, "an unkeyed peer is governed, as the rest entry")
	assert.True(t, rest.rest)
	assert.Zero(t, table.clients("alice"), "the rest entry is not a client")
	assert.Zero(t, table.overflow("alice"), "and a loopback peer is not an overflow")

	endStream(local, localUp, localDone)
	assert.Equal(t, 0, clientRefs(table, rest))

	for _, addr := range []*net.TCPAddr{
		{IP: net.ParseIP("::ffff:203.0.113.5"), Port: 50001},
		{IP: net.ParseIP("203.0.113.5").To4(), Port: 50002},
		{IP: net.ParseIP("2001:db8::1"), Port: 50003},
		{IP: net.ParseIP("2001:db8::ffff:2"), Port: 50004},
		{IP: net.ParseIP("2001:db8:0:1::1"), Port: 50005},
	} {
		client, done := dialProxyFrom(t, h, ec.policy, addr)
		upstream := connectThrough(t, ec, h, client, "alice", secret.Key)

		defer endStream(client, upstream, done)
	}

	four := entryByKey(table, "alice", "203.0.113.5")
	require.NotNil(t, four)
	assert.Equal(t, 2, clientRefs(table, four), "a v4-mapped address and its IPv4 address are one place")

	six := entryByKey(table, "alice", "2001:db8::/64")
	require.NotNil(t, six)
	assert.Equal(t, 2, clientRefs(table, six), "one /64 is one place")

	assert.NotNil(t, entryByKey(table, "alice", "2001:db8:0:1::/64"), "the next /64 is another")
	assert.Equal(t, 3, table.clients("alice"))
}

// Review Focus 4, for streams that were open before the table had a reason to
// hold them: a reload that turns on something needing entries gives an open
// keyed stream its own entry and an open unkeyed one -- loopback, or no address
// at all -- the rest entry, and a second reload changes nothing.
//
// Turning track-client-ips on stands in for the per-address control a reload
// adds: none exists before client-conns, and both feed the one predicate that
// decides whether a secret needs entries. The setting is flipped with no
// stream goroutine running, which is why this is a probe and not a door test.
func TestAReloadBackfillsStreamsAlreadyOpen(t *testing.T) {
	t.Parallel()

	probe := newClientTableProbe(t, false)

	keyed := probe.stream(t, tcpFrom("203.0.113.9", 50001), 0)
	local := probe.stream(t, tcpFrom("127.0.0.1", 50002), 0)
	nowhere := probe.stream(t, &net.UnixAddr{Name: "@nowhere", Net: "unix"}, 0)

	for _, sc := range []*streamContext{keyed, local, nowhere} {
		require.Equal(t, DenyNone, probe.proxy.tryRegisterConn(sc))
		require.Nil(t, sc.addrEntry.Load())
	}

	require.Nil(t, probe.proxy.clients.snapshot("alice"))

	probe.proxy.trackClientIPs = true

	reload := func() {
		t.Helper()

		require.NoError(t, probe.proxy.ReplaceSecrets(probe.proxy.secrets.Load().toConfig()))
	}

	reload()

	own := keyed.addrEntry.Load()
	require.NotNil(t, own, "an open keyed stream is given its own entry")
	assert.False(t, own.rest)
	assert.Equal(t, addressKey("203.0.113.9"), own.key)

	rest := local.addrEntry.Load()
	require.NotNil(t, rest, "an open unkeyed stream joins the rest entry, never left ungoverned")
	assert.True(t, rest.rest)
	assert.Same(t, rest, nowhere.addrEntry.Load(), "and so does one with no address at all")

	table := probe.proxy.clients

	assert.Equal(t, 1, clientRefs(table, own))
	assert.Equal(t, 2, clientRefs(table, rest))
	assert.Equal(t, 1, table.clients("alice"))
	assert.Zero(t, table.overflow("alice"))

	reload()

	assert.Same(t, own, keyed.addrEntry.Load(), "a second reload gives nobody a second entry")
	assert.Same(t, rest, local.addrEntry.Load())
	assert.Equal(t, 1, clientRefs(table, own))
	assert.Equal(t, 2, clientRefs(table, rest))

	for _, sc := range []*streamContext{keyed, local, nowhere} {
		probe.proxy.unregisterConn(sc)
		assert.Nil(t, sc.addrEntry.Load(), "a released stream carries no entry")
	}

	assert.Equal(t, 0, clientRefs(table, own))
	assert.Equal(t, 0, clientRefs(table, rest))
}

// Spec §2: the entry is taken after the ledger has admitted the stream, so a
// connection the ip-limit refuses never reaches the table. It takes no entry
// and counts as neither a client nor an overflow; otherwise a flood of refused
// new addresses would fill the table with orphans for ten minutes. A
// connection with no address at all, refused because a limit cannot be
// counted without one, takes no rest entry either.
func TestAnAddressRefusedByIPLimitTakesNoEntry(t *testing.T) {
	t.Parallel()

	probe := newClientTableProbe(t, true)
	table := probe.proxy.clients

	require.Equal(t, DenyNone, probe.proxy.tryRegisterConn(probe.stream(t, tcpFrom("203.0.113.1", 50001), 1)))
	require.Equal(t, DenyIPLimit, probe.proxy.tryRegisterConn(probe.stream(t, tcpFrom("203.0.113.2", 50002), 1)))

	assert.Nil(t, entryByKey(table, "alice", "203.0.113.2"), "a refused address takes no entry")
	assert.Equal(t, 1, table.clients("alice"))
	assert.Zero(t, table.overflow("alice"))

	nowhere := probe.stream(t, &net.UnixAddr{Name: "@nowhere", Net: "unix"}, 1)

	require.Equal(t, DenyIPLimit, probe.proxy.tryRegisterConn(nowhere))
	assert.Len(t, table.snapshot("alice"), 1, "nor does a connection with no address take the rest entry")
}

// A refusal gives back exactly the hold it took on the rest entry and no more:
// an unkeyed stream already live keeps the rest entry held. A second release
// would let the sweep forget a rest entry still in use, and the next unkeyed
// stream would make a second one for the same secret.
func TestARefusedUnkeyedStreamLeavesTheOtherHolders(t *testing.T) { //nolint: paralleltest // swaps a package variable
	probe := newClientTableProbe(t, true)
	table := probe.proxy.clients

	live := probe.stream(t, tcpFrom("127.0.0.1", 50001), 0)
	require.Equal(t, DenyNone, probe.proxy.tryRegisterConn(live))

	rest := live.addrEntry.Load()
	require.NotNil(t, rest)
	require.True(t, rest.rest)

	heldInHook := 0

	installRegisterStepHook(t, func(step registerStep, _ *streamContext) DenyReason {
		if step != stepEntryAcquired {
			return DenyNone
		}

		heldInHook = clientRefs(table, rest)

		return DenyBanned
	})

	require.Equal(t, DenyBanned, probe.proxy.tryRegisterConn(probe.stream(t, tcpFrom("127.0.0.1", 50002), 0)))

	assert.Equal(t, 2, heldInHook, "the refused stream held the same rest entry")
	assert.Equal(t, 1, clientRefs(table, rest), "and gave back its own hold, and no more")
	assert.Same(t, rest, live.addrEntry.Load())
}

// The maintenance loop's sweep really walks in chunks of clientSweepChunk, so a
// table of any size holds its lock for one chunk at a time.
func TestSweepClientsWorksInChunks(t *testing.T) {
	t.Parallel()

	clock := newFakeAddrClock()

	p := newLimitTestProxy(map[string]Secret{"alice": GenerateSecret("alice.example.com")}, nil)
	p.clients = newClientTable(clock.clock())

	const idle = 2500

	for _, entry := range fillClients(t, p.clients, "alice", idle) {
		p.clients.release(entry)
	}

	clock.advance(clientIdleRetention)

	var holds []int

	p.clients.afterHold = func(walked int) { holds = append(holds, walked) }

	assert.Equal(t, idle, p.sweepClients())
	assert.Equal(t, []int{clientSweepChunk, clientSweepChunk, idle - 2*clientSweepChunk}, holds)
}

// The per-secret entry cap is 4,096 whatever ip-limit says. The ledger holds a
// secret's LIVE addresses to its ip-limit; the table's idle entries -- kept ten
// minutes after their last stream -- must not push a roaming client's new
// address to the rest entry, which has no ceiling, for the life of its
// connection.
func TestThePerSecretCapDoesNotFollowIPLimit(t *testing.T) {
	t.Parallel()

	probe := newClientTableProbe(t, true)
	probe.proxy.secrets.Store(buildSecretSet(
		map[string]Secret{"alice": GenerateSecret("alice.example.com")}, nil, nil,
		map[string]SecretLimits{"alice": {IPLimit: 2}}))

	table := probe.proxy.clients

	// The phone on Wi-Fi and the laptop: both gone now, both still held idle.
	for i, from := range []string{"203.0.113.1", "203.0.113.2"} {
		sc := probe.stream(t, tcpFrom(from, 50001+i), 2)

		require.Equal(t, DenyNone, probe.proxy.tryRegisterConn(sc))
		probe.proxy.unregisterConn(sc)
	}

	require.Equal(t, 2, table.clients("alice"))

	// The phone again, now on LTE. No address is live, so the ledger admits it.
	roaming := probe.stream(t, tcpFrom("198.51.100.3", 50003), 2)

	require.Equal(t, DenyNone, probe.proxy.tryRegisterConn(roaming))

	entry := roaming.addrEntry.Load()
	require.NotNil(t, entry)

	assert.False(t, entry.rest, "a new address gets its own entry, not the rest entry, whatever ip-limit says")
	assert.Equal(t, 3, table.clients("alice"))
	assert.Zero(t, table.overflow("alice"), "no cap turned it away")
}

// Review Focus 5: removing a secret drops its entries and its rest entry at
// once, and the streams it closes let go of entries the table no longer holds
// without disturbing anything; a re-key closes the old key's streams but keeps
// the name's entries, which are the same addresses.
func TestRemovingASecretDropsItsEntriesAndARekeyKeepsThem(t *testing.T) {
	t.Parallel()

	ec := govEntryCases()[1]
	alice, bob := ec.secret(t), ec.secret(t)

	h := ec.harness(t, map[string]Secret{"alice": alice, "bob": bob}, nil)
	h.proxy.trackClientIPs = true

	table := h.proxy.clients

	aliceClient, aliceDone := dialProxyFrom(t, h, ec.policy, tcpFrom("203.0.113.1", 50001))
	connectThrough(t, ec, h, aliceClient, "alice", alice.Key)

	bobClient, bobDone := dialProxyFrom(t, h, ec.policy, tcpFrom("203.0.113.2", 50002))
	connectThrough(t, ec, h, bobClient, "bob", bob.Key)

	bobLocal, bobLocalDone := h.dialProxy(t, ec.policy)
	connectThrough(t, ec, h, bobLocal, "bob", bob.Key)

	aliceEntry := entryByKey(table, "alice", "203.0.113.1")
	require.NotNil(t, aliceEntry)
	require.Len(t, table.snapshot("bob"), 2, "bob's address and his rest entry")

	awaitUpstreamRecorded(t, h.proxy, "alice")
	awaitUpstreamRecorded(t, h.proxy, "bob")

	require.NoError(t, h.proxy.DeleteSecret("bob"))

	assert.Nil(t, table.snapshot("bob"), "a removed secret's entries go with it")
	assert.Zero(t, table.clients("bob"))

	require.True(t, govAwait(bobDone, govDenyBudget), "the removal closes bob's streams")
	require.True(t, govAwait(bobLocalDone, govDenyBudget))

	assert.Nil(t, table.snapshot("bob"), "and their release brings nothing back")
	requireOnlyEntry(t, table, "alice", aliceEntry)
	assert.Equal(t, 1, clientRefs(table, aliceEntry), "another secret is untouched")

	require.NoError(t, h.proxy.PutSecret("alice", ec.secret(t), nil, nil))
	require.True(t, govAwait(aliceDone, govDenyBudget), "a re-key closes the old key's streams")

	requireOnlyEntry(t, table, "alice", aliceEntry)
	assert.Equal(t, 0, clientRefs(table, aliceEntry), "but the name keeps its entries")
}

// The lock order is reloadMu, liveMu, tableMu: the sweep the maintenance loop
// runs, and the reads the stats and the fair-share ticker make, take the
// table's lock alone. Go has no lock-order checker and the race detector finds
// data races, not inversions, so this holds liveMu and requires them to finish
// anyway.
func TestTheTableNeverWaitsForLiveMu(t *testing.T) {
	t.Parallel()

	probe := newClientTableProbe(t, true)
	p := probe.proxy

	require.Equal(t, DenyNone, p.tryRegisterConn(probe.stream(t, tcpFrom("203.0.113.9", 50001), 0)))

	p.liveMu.Lock()

	done := make(chan struct{})

	go func() {
		defer close(done)

		p.sweepClients()
		p.clients.snapshot("alice")
		p.clients.clients("alice")
		p.clients.overflow("alice")
	}()

	finished := govAwait(done, 2*time.Second)

	p.liveMu.Unlock()
	<-done

	require.True(t, finished, "the sweep and the table's reads must not wait for liveMu")
}

// The gap Task 3 left: a refusal after the entry was taken gives it back, for an
// unkeyed stream (the rest entry) as for a keyed one, and leaves the ledger and
// the registry as they were. At the step itself the entry is held and the
// stream does not carry it yet.
func TestARefusalAfterTheEntryGivesItBack(t *testing.T) { //nolint: paralleltest // swaps a package variable
	for name, from := range map[string]net.Addr{
		"keyed":   tcpFrom("203.0.113.9", 50001),
		"unkeyed": tcpFrom("127.0.0.1", 50001),
	} {
		t.Run(name, func(t *testing.T) {
			probe := newClientTableProbe(t, true)
			table := probe.proxy.clients

			var (
				steps      []registerStep
				heldInHook int
				carried    bool
			)

			installRegisterStepHook(t, func(step registerStep, sc *streamContext) DenyReason {
				steps = append(steps, step)

				if step != stepEntryAcquired {
					return DenyNone
				}

				for _, entry := range table.snapshot("alice") {
					heldInHook += clientRefs(table, entry)
				}

				carried = sc.addrEntry.Load() != nil

				return DenyBanned
			})

			sc := probe.stream(t, from, 0)

			assert.Equal(t, DenyBanned, probe.proxy.tryRegisterConn(sc))
			assert.Equal(t, []registerStep{stepLedgerAdmitted, stepEntryAcquired}, steps)
			assert.Equal(t, 1, heldInHook, "the entry is held by the step after it was taken")
			assert.False(t, carried, "and the stream does not carry it until every step has passed")

			assert.Nil(t, sc.addrEntry.Load())
			assert.Nil(t, probe.ledgerCounts(), "the ledger is as it was")
			assert.Zero(t, probe.registered())

			snapshot := table.snapshot("alice")
			require.Len(t, snapshot, 1)
			assert.Equal(t, name == "unkeyed", snapshot[0].rest)
			assert.Equal(t, 0, clientRefs(table, snapshot[0]), "the refusal gave the entry back")
		})
	}
}

// A proxy with no table -- every Proxy{} literal in the tests -- admits,
// reloads, removes and sweeps as it always did, and no stream carries an entry.
// Nor does a table without a secret set to read the limits from.
func TestAProxyWithoutATableHasNoEntries(t *testing.T) {
	t.Parallel()

	probe := newClientTableProbe(t, true)
	probe.proxy.clients = nil
	probe.proxy.secrets.Store(buildSecretSet(map[string]Secret{
		"alice": GenerateSecret("alice.example.com"),
		"bob":   GenerateSecret("bob.example.com"),
	}, nil, nil, nil))

	sc := probe.stream(t, tcpFrom("203.0.113.9", 50001), 0)

	require.Equal(t, DenyNone, probe.proxy.tryRegisterConn(sc))
	assert.Nil(t, sc.addrEntry.Load())

	require.NoError(t, probe.proxy.ReplaceSecrets(probe.proxy.secrets.Load().toConfig()))
	require.NoError(t, probe.proxy.DeleteSecret("bob"))
	assert.Zero(t, probe.proxy.sweepClients())

	probe.proxy.unregisterConn(sc)
	assert.Zero(t, probe.registered())

	bare := newDenyProbe(t)
	bare.proxy.trackClientIPs = true
	bare.proxy.clients = newClientTable(addrClock{})

	other := bare.stream(t, tcpFrom("203.0.113.9", 50002), 0)

	require.Equal(t, DenyNone, bare.proxy.tryRegisterConn(other))
	assert.Nil(t, other.addrEntry.Load(), "no secret set, no limits to read, no entry")
}

// The maintenance loop sweeps the table on its own interval, on the table's
// clock, forgetting what has been idle long enough and nothing else.
func TestMaintenanceSweepsTheClientTable(t *testing.T) {
	t.Parallel()

	clock := newFakeAddrClock()

	p := newLimitTestProxy(map[string]Secret{"alice": GenerateSecret("alice.example.com")}, nil)
	p.clients = newClientTable(clock.clock())

	p.clients.release(p.clients.acquire("alice", "203.0.113.9", true, entryInit{}))
	live := p.clients.acquire("alice", "203.0.113.10", true, entryInit{})

	clock.advance(clientIdleRetention)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	p.startMaintenanceEvery(ctx, time.Hour, time.Hour, 20*time.Millisecond)

	require.Eventually(t, func() bool { return p.clients.clients("alice") == 1 },
		3*time.Second, 10*time.Millisecond, "the idle entry is swept on the clock")

	requireOnlyEntry(t, p.clients, "alice", live)
}

// NewProxy builds the table whatever the configuration: an empty table costs a
// map, and whether a stream takes an entry is decided per secret at admission.
func TestNewProxyBuildsTheClientTable(t *testing.T) {
	t.Parallel()

	opts, _ := servingOpts(t)

	proxy, err := NewProxy(opts)
	require.NoError(t, err)
	t.Cleanup(proxy.Shutdown)

	assert.NotNil(t, proxy.clients)
}
