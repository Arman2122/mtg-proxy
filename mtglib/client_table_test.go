package mtglib

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The per-address table on its own: no proxy, no sockets, a fake clock. What it
// promises is about lifetime and bounds -- an entry outlives its connections,
// the caps turn new addresses away and never existing ones, the sweep forgets
// only what has been idle long enough and never holds the lock for long -- and
// every one of those is a number or a pointer these tests can compare.

// newTestClientTable is a table on a fake clock that starts on a whole second,
// so that the second-granular idle clock has no rounding to argue about.
func newTestClientTable(t *testing.T) (*clientTable, *fakeAddrClock) {
	t.Helper()

	clock := newFakeAddrClock()

	return newClientTable(clock.clock()), clock
}

// clientRefs is how many streams hold e, read under the table's lock.
func clientRefs(table *clientTable, e *clientEntry) int {
	table.mu.Lock()
	defer table.mu.Unlock()

	return e.refs
}

// syntheticClientKey is the i-th of a run of distinct keys. The table never
// parses a key, so these only have to be distinct.
func syntheticClientKey(i int) addressKey {
	return addressKey(fmt.Sprintf("198.18.%d.%d", i/256, i%256))
}

// fillClients gives name n keyed entries, each held by one stream.
func fillClients(t *testing.T, table *clientTable, name string, n int) []*clientEntry {
	t.Helper()

	entries := make([]*clientEntry, n)

	for i := range n {
		entries[i] = table.acquire(name, syntheticClientKey(i), true, entryInit{})
		require.False(t, entries[i].rest, "entry %d of %d must have room", i, n)
	}

	return entries
}

// An entry is made once per address and secret, every stream that uses it holds
// it, and letting go of every stream does not forget it: that is the whole point
// of a lifetime of its own.
func TestClientTableHoldsOneEntryPerAddress(t *testing.T) {
	t.Parallel()

	table, _ := newTestClientTable(t)

	first := table.acquire("alice", "203.0.113.5", true, entryInit{})
	require.NotNil(t, first)

	assert.False(t, first.rest)
	assert.Equal(t, addressKey("203.0.113.5"), first.key)
	assert.Equal(t, "alice", first.name)
	assert.Equal(t, 1, clientRefs(table, first))

	assert.Same(t, first, table.acquire("alice", "203.0.113.5", true, entryInit{}),
		"a second connection from the same place is the same entry")
	assert.Equal(t, 2, clientRefs(table, first))

	other := table.acquire("alice", "203.0.113.6", true, entryInit{})
	assert.NotSame(t, first, other)

	bobs := table.acquire("bob", "203.0.113.5", true, entryInit{})
	assert.NotSame(t, first, bobs, "an entry belongs to an address AND a secret")

	assert.Equal(t, 2, table.clients("alice"))
	assert.Equal(t, 1, table.clients("bob"))

	table.release(first)
	assert.Equal(t, 1, clientRefs(table, first))

	table.release(first)
	assert.Equal(t, 0, clientRefs(table, first))

	table.release(first)
	assert.Equal(t, 0, clientRefs(table, first), "a release too many must not go below nothing")

	table.release(nil)

	assert.Equal(t, 2, table.clients("alice"), "an entry outlives its last connection")
	assert.Same(t, first, table.acquire("alice", "203.0.113.5", true, entryInit{}),
		"and the address finds it again when it comes back")
}

// A new entry's limiters are made from init before anyone can see the entry,
// and only then: an address that comes back finds the bucket it left -- with the
// bytes it moved and the tokens it spent -- even if the limits changed meanwhile,
// because re-rating a live entry is applyLimits' job and not the table's. The
// rest entry carries no ceiling, whatever init says.
func TestClientTableInitialisesLimitersOnlyWhenItCreates(t *testing.T) {
	t.Parallel()

	table, clock := newTestClientTable(t)

	init := entryInit{
		CeilingRate: 1 << 20,
		FairTotals:  fairTotals{Speed: 8 << 20, Up: 2 << 20, Down: 4 << 20},
	}

	entry := table.acquire("alice", "203.0.113.5", true, init)

	ceiling := installedLimiter(t, &entry.ceiling)
	assert.InDelta(t, float64(1<<20), float64(ceiling.Limit()), 0)
	assert.Equal(t, ceilingBurst(1<<20), ceiling.Burst())

	for name, tc := range map[string]struct {
		limiter *addrLimiter
		total   int64
	}{
		"speed": {&entry.fairSpeed, 8 << 20},
		"up":    {&entry.fairUp, 2 << 20},
		"down":  {&entry.fairDown, 4 << 20},
	} {
		fair := installedLimiter(t, tc.limiter)
		assert.InDelta(t, float64(tc.total), float64(fair.Limit()), 0, name)
		assert.Equal(t, fairBurst(tc.total), fair.Burst(), name)
	}

	// Spend the ceiling's bucket and some bytes, leave, and come back under
	// different limits.
	drainAddrLimiter(t, &entry.ceiling)
	entry.bytesIn.Add(1000)
	entry.bytesOut.Add(2000)

	table.release(entry)

	again := table.acquire("alice", "203.0.113.5", true, entryInit{CeilingRate: 4 << 20})
	require.Same(t, entry, again)

	assert.Same(t, ceiling, installedLimiter(t, &again.ceiling),
		"a returning address keeps its limiter object: a new one would start full")
	assert.Less(t, ceiling.TokensAt(clock.read()), 1.0,
		"and the tokens it spent stay spent")
	assert.EqualValues(t, 1000, again.bytesIn.Load())
	assert.EqualValues(t, 2000, again.bytesOut.Load())

	rest := table.acquire("alice", "", false, init)
	require.NotNil(t, rest)
	require.True(t, rest.rest)

	assert.Nil(t, rest.ceiling.limiter.Load(),
		"the rest entry stands for many addresses, so no one address's ceiling applies to it")
	assert.EqualValues(t, 8<<20, rest.fairSpeed.bytesPerSecond(), "but it holds a fair share like any other")
	assert.EqualValues(t, 2<<20, rest.fairUp.bytesPerSecond())
	assert.EqualValues(t, 4<<20, rest.fairDown.bytesPerSecond())

	plain := table.acquire("alice", "203.0.113.6", true, entryInit{})
	for _, l := range []*addrLimiter{&plain.ceiling, &plain.fairSpeed, &plain.fairUp, &plain.fairDown} {
		assert.Nil(t, l.limiter.Load(), "no limit asked for is no limiter: the data path pays one load")
	}
}

// Unkeyed peers -- loopback, private and the like, which do not stand for one
// place -- are not left ungoverned: every one of them shares the secret's one
// rest entry. They are not an overflow: no cap turned them away.
func TestClientTableUnkeyedPeersJoinTheRestEntry(t *testing.T) {
	t.Parallel()

	table, _ := newTestClientTable(t)

	rest := table.acquire("alice", "", false, entryInit{})
	require.NotNil(t, rest)

	assert.True(t, rest.rest)
	assert.Empty(t, rest.key)
	assert.Equal(t, "alice", rest.name)

	assert.Same(t, rest, table.acquire("alice", "127.0.0.1", false, entryInit{}),
		"whatever key an unkeyed peer has, it is the rest entry")
	assert.Equal(t, 2, clientRefs(table, rest))

	assert.NotSame(t, rest, table.acquire("bob", "", false, entryInit{}), "one rest entry per secret")

	assert.Zero(t, table.clients("alice"), "the rest entry is not a client")
	assert.Zero(t, table.overflow("alice"), "and an unkeyed peer is not an overflow")
	assert.Contains(t, table.snapshot("alice"), rest)
}

// A full secret turns a NEW address to the rest entry and counts the connection
// as an overflow; it never evicts an existing entry and never resets one -- an
// eviction would hand a drained bucket back full to whoever filled the table.
// An address already held is admitted to its own entry at the cap, as often as
// it comes back, and that is not an overflow.
func TestClientTablePerSecretCapDropsNewNeverEvicts(t *testing.T) {
	t.Parallel()

	table, clock := newTestClientTable(t)

	first := table.acquire("alice", syntheticClientKey(0), true, entryInit{CeilingRate: 1 << 20})
	drainAddrLimiter(t, &first.ceiling)
	first.bytesIn.Add(4242)

	limiter := installedLimiter(t, &first.ceiling)

	filled := append([]*clientEntry{first}, fillClients(t, table, "alice", maxClientsPerSecret)[1:]...)
	require.Equal(t, maxClientsPerSecret, table.clients("alice"))
	assert.Zero(t, table.overflow("alice"), "connections that found room are not an overflow")

	newcomer := addressKey("203.0.113.200")

	rest := table.acquire("alice", newcomer, true, entryInit{})
	assert.True(t, rest.rest, "a new address past the cap joins the rest entry")
	assert.EqualValues(t, 1, table.overflow("alice"))

	assert.Same(t, rest, table.acquire("alice", newcomer, true, entryInit{}))
	assert.EqualValues(t, 2, table.overflow("alice"), "overflow counts connections, not addresses")

	assert.Same(t, first, table.acquire("alice", syntheticClientKey(0), true, entryInit{}),
		"an address already held keeps getting its own entry at the cap")
	assert.EqualValues(t, 2, table.overflow("alice"), "and that is not an overflow")

	assert.Equal(t, maxClientsPerSecret, table.clients("alice"))
	assert.Same(t, limiter, installedLimiter(t, &first.ceiling), "nothing was reset")
	assert.Less(t, limiter.TokensAt(clock.read()), 1.0)
	assert.EqualValues(t, 4242, first.bytesIn.Load())

	// By identity: assert.Contains would deep-compare 4,096 entries 4,096 times.
	held := make(map[*clientEntry]bool, maxClientsPerSecret+1)
	for _, e := range table.snapshot("alice") {
		held[e] = true
	}

	for i, e := range filled {
		require.True(t, held[e], "entry %d is still held", i)
	}

	// The cap is a bound on what is held, not a ban: once an entry is swept the
	// next new address gets its own.
	last := filled[len(filled)-1]
	table.release(last)
	clock.advance(clientIdleRetention)

	require.Equal(t, 1, table.sweep(clock.read(), clientSweepChunk))

	assert.False(t, table.acquire("alice", newcomer, true, entryInit{}).rest)
	assert.EqualValues(t, 2, table.overflow("alice"))
}

// The table as a whole is bounded too: when every secret together holds the
// global cap, a new address of any secret joins that secret's rest entry, and
// what is held stays held.
func TestClientTableGlobalCapDropsNewNeverEvicts(t *testing.T) {
	t.Parallel()

	table, clock := newTestClientTable(t)

	secrets := maxClients / maxClientsPerSecret
	require.Equal(t, maxClients, secrets*maxClientsPerSecret, "the global cap is a whole number of full secrets")

	var first *clientEntry

	for s := range secrets {
		entries := fillClients(t, table, fmt.Sprintf("user%d", s), maxClientsPerSecret)
		if s == 0 {
			first = entries[0]
		}
	}

	first.bytesOut.Add(77)

	late := table.acquire("latecomer", "203.0.113.9", true, entryInit{})
	assert.True(t, late.rest, "a secret with room of its own still has none when the table is full")
	assert.EqualValues(t, 1, table.overflow("latecomer"))
	assert.Zero(t, table.clients("latecomer"))

	assert.Same(t, first, table.acquire("user0", syntheticClientKey(0), true, entryInit{}))
	assert.EqualValues(t, 77, first.bytesOut.Load(), "nothing was evicted to make room")

	// One entry swept anywhere is one slot free everywhere. Every other entry
	// is still held by the stream that made it, so only this one goes.
	victim := table.acquire("user3", syntheticClientKey(7), true, entryInit{})
	table.release(victim)
	table.release(victim)
	clock.advance(clientIdleRetention)

	require.Equal(t, 1, table.sweep(clock.read(), clientSweepChunk))
	assert.False(t, table.acquire("latecomer", "203.0.113.9", true, entryInit{}).rest)
}

// Review Focus 2: an IPv4 address and its v4-mapped IPv6 spelling are one
// place, and so are two addresses of one IPv6 /64, so they share one entry. The
// classification that decides keyed or not is hintKey's, read off the unmapped
// address before any /64 masking: a v4-mapped private address is private.
func TestClientKeysShareOneEntryPerPlace(t *testing.T) {
	t.Parallel()

	key := func(text string) (addressKey, bool) {
		ip := net.ParseIP(text)
		require.NotNil(t, ip, text)

		k, ok := addressKeyOf(ip)
		require.True(t, ok, text)

		return k, clientKeyed(ip)
	}

	plain4, keyed := key("203.0.113.5")
	require.True(t, keyed)

	plainBytes, ok := addressKeyOf(net.ParseIP("203.0.113.5").To4())
	require.True(t, ok)
	require.True(t, clientKeyed(net.ParseIP("203.0.113.5").To4()))

	mapped, keyed := key("::ffff:203.0.113.5")
	require.True(t, keyed)

	sameNet1, keyed := key("2001:db8::1")
	require.True(t, keyed)

	sameNet2, _ := key("2001:db8::ffff:2")
	otherNet, _ := key("2001:db8:0:1::1")

	table, _ := newTestClientTable(t)

	four := table.acquire("alice", plain4, true, entryInit{})
	assert.Same(t, four, table.acquire("alice", plainBytes, true, entryInit{}),
		"a 4-byte and a 16-byte IPv4 are one place")
	assert.Same(t, four, table.acquire("alice", mapped, true, entryInit{}),
		"a v4-mapped address is its IPv4 address")
	assert.Equal(t, 3, clientRefs(table, four))

	six := table.acquire("alice", sameNet1, true, entryInit{})
	assert.Same(t, six, table.acquire("alice", sameNet2, true, entryInit{}), "one /64 is one place")
	assert.NotSame(t, six, table.acquire("alice", otherNet, true, entryInit{}), "the next /64 is another")

	assert.Equal(t, 3, table.clients("alice"))

	for _, text := range []string{
		"127.0.0.1", "::1", "10.0.0.1", "::ffff:10.0.0.1", "172.16.0.1", "192.168.1.1",
		"169.254.1.1", "fe80::1", "fd00::1", "0.0.0.0", "::", "224.0.0.1", "ff02::1",
	} {
		assert.False(t, clientKeyed(net.ParseIP(text)), "%s does not stand for one place", text)
	}

	for _, text := range []string{"203.0.113.9", "198.51.100.7", "2001:db8::1", "::ffff:198.51.100.7"} {
		assert.True(t, clientKeyed(net.ParseIP(text)), "%s stands for one place", text)
	}

	assert.False(t, clientKeyed(nil), "no address is no place")
}

// The sweep forgets an entry only when no stream holds it and its address has
// been gone ten minutes: a live entry stays however old, a recently idle one
// stays, and the idle clock starts again whenever the address comes back.
func TestClientTableSweepKeepsLiveAndRecentlyIdleEntries(t *testing.T) {
	t.Parallel()

	table, clock := newTestClientTable(t)

	live := table.acquire("alice", "203.0.113.1", true, entryInit{})

	idle := table.acquire("alice", "203.0.113.2", true, entryInit{})
	table.release(idle)

	returning := table.acquire("alice", "203.0.113.3", true, entryInit{})
	table.release(returning)

	rest := table.acquire("alice", "", false, entryInit{})
	table.release(rest)

	clock.advance(9 * time.Minute)

	table.acquire("alice", "203.0.113.3", true, entryInit{})
	table.release(returning)

	clock.advance(time.Minute - time.Second)

	assert.Zero(t, table.sweep(clock.read(), clientSweepChunk), "nobody has been gone ten minutes yet")
	assert.Len(t, table.snapshot("alice"), 4)

	clock.advance(time.Second)

	assert.Equal(t, 2, table.sweep(clock.read(), clientSweepChunk), "the idle entry and the idle rest entry")

	snapshot := table.snapshot("alice")
	assert.ElementsMatch(t, []*clientEntry{live, returning}, snapshot,
		"a live entry stays however old, and a returning address restarted its idle clock")
	assert.Equal(t, 2, table.clients("alice"))

	table.mu.Lock()
	assert.Equal(t, 2, table.keyed, "a swept entry frees its slot in the global count")
	assert.Len(t, table.all, 2)
	table.mu.Unlock()

	again := table.acquire("alice", "203.0.113.2", true, entryInit{})
	assert.NotSame(t, idle, again, "a swept address starts afresh")
	assert.Zero(t, again.bytesIn.Load())

	assert.NotSame(t, rest, table.acquire("alice", "", false, entryInit{}), "and so does a swept rest entry")
}

// The sweep never walks more than its chunk under one hold of the lock, and lets
// go of it between chunks, so a full table costs an admission a short wait at
// most. An address that arrives between two chunks is not swept by mistake.
func TestClientTableSweepWorksInChunks(t *testing.T) {
	t.Parallel()

	table, clock := newTestClientTable(t)

	const idle = 2500

	for _, e := range fillClients(t, table, "alice", idle) {
		table.release(e)
	}

	clock.advance(clientIdleRetention + time.Minute)

	var (
		holds    []int
		released []bool
		arrival  *clientEntry
	)

	table.afterHold = func(walked int) {
		holds = append(holds, walked)

		free := table.mu.TryLock()
		if free {
			table.mu.Unlock()
		}

		released = append(released, free)

		if arrival == nil {
			arrival = table.acquire("alice", "203.0.113.77", true, entryInit{})
		}
	}

	assert.Equal(t, idle, table.sweep(clock.read(), clientSweepChunk))

	require.GreaterOrEqual(t, len(holds), 3, "2,500 entries take at least three holds of 1,024")

	for i, walked := range holds {
		assert.LessOrEqual(t, walked, clientSweepChunk, "hold %d", i)
		assert.True(t, released[i], "the lock is let go after hold %d", i)
	}

	require.NotNil(t, arrival)
	assert.Equal(t, []*clientEntry{arrival}, table.snapshot("alice"), "only the newcomer is left")
	assert.Equal(t, 1, table.clients("alice"))
}

// A secret that is removed takes its entries, its rest entry and its overflow
// count with it, and frees their slots. A stream of it that is still closing
// lets go of an entry the table no longer holds, which must disturb nothing --
// not even the secret's name coming back.
func TestClientTableDropSecretForgetsEverything(t *testing.T) {
	t.Parallel()

	table, _ := newTestClientTable(t)

	held := fillClients(t, table, "alice", maxClientsPerSecret)[0]
	require.True(t, table.acquire("alice", "203.0.113.2", true, entryInit{}).rest)
	rest := table.acquire("alice", "", false, entryInit{})
	bobs := table.acquire("bob", "203.0.113.1", true, entryInit{})

	require.EqualValues(t, 1, table.overflow("alice"))

	table.dropSecret("alice")

	assert.Zero(t, table.clients("alice"))
	assert.Zero(t, table.overflow("alice"))
	assert.Empty(t, table.snapshot("alice"))

	assert.Equal(t, []*clientEntry{bobs}, table.snapshot("bob"), "another secret is untouched")

	table.mu.Lock()
	assert.Equal(t, 1, table.keyed)
	assert.Len(t, table.all, 1)
	table.mu.Unlock()

	table.release(held)
	table.release(rest)

	again := table.acquire("alice", held.key, true, entryInit{})
	assert.NotSame(t, held, again, "the name coming back starts afresh")
	assert.Equal(t, 1, table.clients("alice"))
	assert.Equal(t, 1, clientRefs(table, again))

	table.dropSecret("nobody")
}

// snapshot copies the pointers, rest entry included, so a caller can walk them
// without the lock and without changing the table.
func TestClientTableSnapshotIsACopy(t *testing.T) {
	t.Parallel()

	table, _ := newTestClientTable(t)

	keyed := table.acquire("alice", "203.0.113.1", true, entryInit{})
	rest := table.acquire("alice", "", false, entryInit{})

	snapshot := table.snapshot("alice")
	assert.ElementsMatch(t, []*clientEntry{keyed, rest}, snapshot)

	snapshot[0] = nil

	assert.ElementsMatch(t, []*clientEntry{keyed, rest}, table.snapshot("alice"))
	assert.Nil(t, table.snapshot("nobody"))
}

// No table is "off", and every method says so instead of panicking: a Proxy{}
// literal in a test has none.
func TestNilClientTableIsOff(t *testing.T) {
	t.Parallel()

	var table *clientTable

	assert.Nil(t, table.acquire("alice", "203.0.113.1", true, entryInit{}))
	assert.Nil(t, table.acquire("alice", "", false, entryInit{}))
	assert.Zero(t, table.sweep(time.Now(), clientSweepChunk))
	assert.Nil(t, table.snapshot("alice"))
	assert.Zero(t, table.clients("alice"))
	assert.Zero(t, table.overflow("alice"))

	table.release(&clientEntry{})
	table.dropSecret("alice")
}
