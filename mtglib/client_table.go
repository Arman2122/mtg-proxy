package mtglib

import (
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// The per-address table: what one source address of a shared secret has moved
// and is allowed, kept for longer than any one of its connections.
//
// The address ledger already counts every address's live connections, but it
// forgets an address the moment its last connection closes, so nothing that has
// to survive a reconnect -- a token bucket, a byte count -- can live there: a
// phone that reconnects every minute would get a full bucket every minute. The
// table holds those, with a lifetime of its own: an entry is made by the first
// connection from an address and forgotten ten minutes after the last one
// closes. Connection counts stay in the ledger, which sees every stream whether
// or not the table had room for it.
//
// The table is bounded, per secret and in all, and a full table drops the NEW
// address rather than an old one: evicting would hand a drained bucket back
// full to whoever filled the table. An address that finds no room, and every
// address that does not stand for one place (hintKey's classification:
// loopback, private and the like, which behind a carrier that forwards no
// client address is every client at once), joins its secret's one "rest"
// entry, which is governed like any other address. Nothing is left ungoverned
// by a full table.
//
// The table has its own lock, tableMu, which comes after liveMu: an admission
// holds liveMu and then takes tableMu to find its entry. The sweep and the
// fair-share ticker take tableMu alone and never liveMu, so neither can hold
// up an admission for longer than one short hold of the table. The data path
// takes no lock at all: it reaches an entry through the stream's pointer and
// touches only atomics.
//
// Every method is safe on a nil receiver, which is "off": a Proxy{} literal in
// a test has no table.

const (
	// maxClientsPerSecret is how many addresses one secret holds an entry for,
	// or its ip-limit if that is smaller.
	maxClientsPerSecret = 4096

	// maxClients is how many address entries the table holds across every
	// secret. Rest entries are not counted: there is at most one per secret,
	// and a stream must always have one to go to.
	maxClients = 32768

	// clientIdleRetention is how long an entry outlives its address's last
	// connection. Long enough that a phone moving between networks, or a
	// client that reconnects after a stall, finds the bucket it left.
	clientIdleRetention = 10 * time.Minute

	// clientSweepChunk is the most entries the sweep looks at under one hold
	// of the table's lock: a full table is walked in about thirty short holds
	// rather than one long one.
	clientSweepChunk = 1024
)

// fairTotals is a secret's speed limits as fair share divides them: the
// combined, upload and download totals, each 0 when that limit is not set or
// fair share is off.
type fairTotals struct {
	Speed, Up, Down int64
}

// entryInit is what a new entry's limiters are made from: the secret's
// per-address ceiling (client-speed) and, when fair share is on, the totals it
// divides. The zero value makes no limiter at all, which is unlimited. It is
// read from the secret set that is current when the entry is made, so that a
// reload cannot leave a new entry on a stale limit; once the entry exists only
// applyLimits and the fair-share ticker change its limiters.
type entryInit struct {
	CeilingRate int64
	FairTotals  fairTotals
}

// clientEntry is one address of one secret: an IPv4 address or an IPv6 /64,
// or the secret's rest entry, which stands for every address the table keeps
// no entry of its own for. It is published once its limiters are made and is
// never copied; the streams that use it hold a pointer.
type clientEntry struct {
	// key is the address, "" for the rest entry, and name the secret.
	key  addressKey
	name string

	// rest marks the secret's rest entry.
	rest bool

	// refs is how many streams hold the entry, and index is where it sits in
	// clientTable.all. Both are guarded by the table's lock.
	refs  int
	index int

	// bytesIn and bytesOut are what the address's streams moved, from the
	// client's side: in is what it sent.
	bytesIn, bytesOut atomic.Int64

	// firstSeen is when the entry was made and never changes. lastSeen is the
	// second the address was last seen -- a connection opening or closing, or
	// a byte moving -- stored only when the second changes. The sweep measures
	// idleness from it.
	firstSeen time.Time
	lastSeen  atomic.Int64

	// ceiling is client-speed, combined across both directions; the rest
	// entry never has one. The fair limiters are client-fair's share of the
	// secret's combined, upload and download limits, one each. A limiter with
	// nothing installed is unlimited.
	ceiling                     addrLimiter
	fairSpeed, fairUp, fairDown addrLimiter
}

// seen stamps lastSeen with now, to the second, writing only when the second
// changed, as markActive does.
func (e *clientEntry) seen(now time.Time) {
	if second := now.Unix(); e.lastSeen.Load() != second {
		e.lastSeen.Store(second)
	}
}

// secretClients is one secret's part of the table. It lives until the secret
// is removed, not until its entries are swept, so the overflow count only ever
// grows while the secret exists.
type secretClients struct {
	entries map[addressKey]*clientEntry
	rest    *clientEntry

	// overflow counts the connections of new addresses that found the table
	// full and joined the rest entry.
	overflow int64
}

// clientTable is the per-address table. Every field is guarded by mu, which is
// tableMu in the lock order.
type clientTable struct {
	mu sync.Mutex

	// clock is what entries' limiters run on and what the table stamps
	// entries with. The zero value is the real clock; a test injects its own.
	clock addrClock

	secrets map[string]*secretClients

	// all is every entry, rest entries included, in no order, so the sweep
	// can walk the table a chunk at a time: a map cannot be walked across two
	// holds of a lock. An entry knows its own index, so removal is a swap with
	// the last.
	all []*clientEntry

	// keyed counts the address entries in all, for the global cap.
	keyed int

	// afterHold, when set, runs after each hold of the lock the sweep takes,
	// with the lock released, and is told how many entries that hold looked
	// at. Only tests set it.
	afterHold func(walked int)
}

// newClientTable makes an empty table on the given clock.
func newClientTable(clock addrClock) *clientTable {
	return &clientTable{clock: clock, secrets: make(map[string]*secretClients)}
}

// clientKeyed says whether ip stands for one place, by the hint cache's rule:
// loopback, private, link-local, unspecified and multicast addresses do not,
// nor does a connection with no address. Such a peer is never given an entry of
// its own and is never capped by client-conns: behind a carrier that forwards
// no client address, every client presents the same one.
func clientKeyed(ip net.IP) bool {
	_, ok := hintKey(ip)

	return ok
}

// clientCap is the per-secret cap for a secret with the given ip-limit: the
// table's own bound, or the ip-limit when that is smaller. A secret cannot be
// in more places at once than its ip-limit, so holding more for it would only
// help someone cycle through addresses to fill the table.
func clientCap(ipLimit int) int {
	if ipLimit > 0 {
		return min(ipLimit, maxClientsPerSecret)
	}

	return maxClientsPerSecret
}

// acquire finds or makes the entry a new stream of the named secret is
// governed by, and holds it for the stream: the address's own entry when key is
// keyed and the table has room for it, and the secret's rest entry otherwise.
// A keyed address that finds no room is counted as an overflow, once per
// connection; an unkeyed one is not, since no cap turned it away.
//
// An entry that already exists is returned as it is: its bucket, bytes and
// limiters are what its address left, whatever init says now. A new one has its
// limiters made from init before it is published -- a rest entry without the
// ceiling -- so nobody ever sees it without them. ipLimit is the secret's
// ip-limit, from the same snapshot as init, for the per-secret cap.
func (t *clientTable) acquire(name string, key addressKey, keyed bool, ipLimit int, init entryInit) *clientEntry {
	if t == nil {
		return nil
	}

	now := t.clock.read()

	t.mu.Lock()
	defer t.mu.Unlock()

	sc := t.secrets[name]
	if sc == nil {
		sc = &secretClients{entries: make(map[addressKey]*clientEntry)}
		t.secrets[name] = sc
	}

	if keyed {
		entry := sc.entries[key]

		switch {
		case entry != nil:
		case len(sc.entries) < clientCap(ipLimit) && t.keyed < maxClients:
			entry = t.makeLocked(name, key, false, init, now)
			sc.entries[key] = entry
			t.keyed++
		default:
			sc.overflow++
		}

		if entry != nil {
			t.holdLocked(entry, now)

			return entry
		}
	}

	if sc.rest == nil {
		sc.rest = t.makeLocked(name, "", true, init, now)
	}

	t.holdLocked(sc.rest, now)

	return sc.rest
}

// makeLocked builds an entry with its limiters already made and appends it to
// all. The caller publishes it. Caller holds mu.
func (t *clientTable) makeLocked(name string, key addressKey, rest bool, init entryInit, now time.Time) *clientEntry {
	entry := &clientEntry{key: key, name: name, rest: rest, firstSeen: now}

	// The clock first: a limiter must run on the table's clock from the first
	// call made on it.
	for _, l := range []*addrLimiter{&entry.ceiling, &entry.fairSpeed, &entry.fairUp, &entry.fairDown} {
		l.clock = t.clock
	}

	if !rest && init.CeilingRate > 0 {
		entry.ceiling.install(init.CeilingRate, ceilingBurst(init.CeilingRate))
	}

	for _, fair := range []struct {
		limiter *addrLimiter
		total   int64
	}{
		{&entry.fairSpeed, init.FairTotals.Speed},
		{&entry.fairUp, init.FairTotals.Up},
		{&entry.fairDown, init.FairTotals.Down},
	} {
		if fair.total > 0 {
			fair.limiter.install(fair.total, fairBurst(fair.total))
		}
	}

	entry.index = len(t.all)
	t.all = append(t.all, entry)

	return entry
}

// holdLocked counts one more stream on entry. Caller holds mu.
func (t *clientTable) holdLocked(entry *clientEntry, now time.Time) {
	entry.refs++
	entry.seen(now)
}

// release lets go of an entry a stream held. The entry stays in the table, and
// its idle clock starts now if this was its last stream. An entry the table has
// already forgotten -- its secret was removed while the stream was closing --
// is only counted down: it is in no index and no count any more.
func (t *clientTable) release(entry *clientEntry) {
	if t == nil || entry == nil {
		return
	}

	now := t.clock.read()

	t.mu.Lock()
	defer t.mu.Unlock()

	if entry.refs > 0 {
		entry.refs--
	}

	entry.seen(now)
}

// sweep forgets every entry that no stream holds and whose address has not been
// seen for clientIdleRetention, and says how many it forgot. It walks the table
// from the end of all towards the start, at most maxPerHold entries per hold of
// the lock, letting go in between so that admissions are never held up for
// long. An entry made between two holds lands past the point the walk has
// reached and is left for the next sweep; an entry removed between two holds
// takes the last one's place, which the walk has either seen already or has
// still to reach. Each entry is judged under the hold that removes it, so one
// that a stream picked up meanwhile is kept.
//
// It takes the table's lock and nothing else: it never takes liveMu.
func (t *clientTable) sweep(now time.Time, maxPerHold int) int {
	if t == nil {
		return 0
	}

	maxPerHold = max(maxPerHold, 1)
	cutoff := now.Add(-clientIdleRetention).Unix()
	dropped := 0

	t.mu.Lock()

	cursor := len(t.all) - 1

	for {
		walked := 0

		for ; cursor >= 0 && walked < maxPerHold; cursor-- {
			walked++

			entry := t.all[cursor]
			if entry.refs == 0 && entry.lastSeen.Load() <= cutoff {
				t.forgetLocked(entry)

				dropped++
			}
		}

		t.mu.Unlock()

		if walked > 0 && t.afterHold != nil {
			t.afterHold(walked)
		}

		if cursor < 0 {
			return dropped
		}

		t.mu.Lock()

		cursor = min(cursor, len(t.all)-1)
	}
}

// forgetLocked takes entry out of every index and count. A stream that still
// holds it keeps a working entry that nothing else can reach. Caller holds mu.
func (t *clientTable) forgetLocked(entry *clientEntry) {
	if entry.index < 0 || entry.index >= len(t.all) || t.all[entry.index] != entry {
		return
	}

	last := len(t.all) - 1

	moved := t.all[last]
	t.all[entry.index] = moved
	moved.index = entry.index

	t.all[last] = nil
	t.all = t.all[:last]
	entry.index = -1

	sc := t.secrets[entry.name]

	switch {
	case sc == nil:
	case entry.rest:
		if sc.rest == entry {
			sc.rest = nil
		}
	case sc.entries[entry.key] == entry:
		delete(sc.entries, entry.key)

		t.keyed--
	}
}

// snapshot copies the named secret's entries, its rest entry included, so a
// caller can read them without the lock. The entries are the live objects; only
// the slice is a copy. Nil for a secret the table holds nothing for.
func (t *clientTable) snapshot(name string) []*clientEntry {
	if t == nil {
		return nil
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	sc := t.secrets[name]
	if sc == nil {
		return nil
	}

	out := make([]*clientEntry, 0, len(sc.entries)+1)
	for _, entry := range sc.entries {
		out = append(out, entry)
	}

	if sc.rest != nil {
		out = append(out, sc.rest)
	}

	return out
}

// dropSecret forgets everything the table holds for a secret that was removed:
// its entries, its rest entry and its overflow count. A re-keyed secret keeps
// its name, and with it all of this. The secret's streams are closed by the
// reload and let go of their entries as they finish, which then touches
// nothing the table can still reach.
func (t *clientTable) dropSecret(name string) {
	if t == nil {
		return
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	sc := t.secrets[name]
	if sc == nil {
		return
	}

	for _, entry := range sc.entries {
		t.forgetLocked(entry)
	}

	if sc.rest != nil {
		t.forgetLocked(sc.rest)
	}

	delete(t.secrets, name)
}

// clients is how many addresses the named secret holds an entry for, the rest
// entry not counted.
func (t *clientTable) clients(name string) int {
	if t == nil {
		return 0
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	if sc := t.secrets[name]; sc != nil {
		return len(sc.entries)
	}

	return 0
}

// overflow is how many connections of the named secret were sent to its rest
// entry because a cap left no room for their address. It only grows while the
// secret exists.
func (t *clientTable) overflow(name string) int64 {
	if t == nil {
		return 0
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	if sc := t.secrets[name]; sc != nil {
		return sc.overflow
	}

	return 0
}
