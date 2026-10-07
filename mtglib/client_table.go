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
// takes none of these: it reaches an entry through the stream's pointer and
// touches only atomics, and, around a wait that feeds fair share, a blocked
// tracker's own lock, which is a leaf.
//
// Every method is safe on a nil receiver, which is "off": a Proxy{} literal in
// a test has no table.

const (
	// maxClientsPerSecret is how many addresses one secret holds an entry for,
	// whatever its ip-limit says. The address ledger already holds a secret's
	// live addresses to its ip-limit -- it refuses a new address first -- so a
	// cap at the ip-limit would only ever bite on idle entries: a phone that
	// left Wi-Fi a minute ago would push its own new LTE address to the rest
	// entry, which has no ceiling, for the life of the connection. This bounds
	// the memory idle entries hold, and nothing else.
	maxClientsPerSecret = 4096

	// maxClients is how many address entries the table holds across every
	// secret. Rest entries are not counted: there is at most one per secret,
	// and a stream must always have one to go to.
	maxClients = 32768

	// clientIdleRetention is how long an entry outlives its address's last
	// connection. Long enough that a phone moving between networks, or a
	// client that reconnects after a stall, finds the bucket it left.
	clientIdleRetention = 10 * time.Minute

	// clientSweepInterval is how often the maintenance loop looks for idle
	// entries. An entry is therefore forgotten between ten and eleven minutes
	// after its address's last connection closed.
	clientSweepInterval = time.Minute

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
// applyLimits and fair share change its limiters -- fair share by its tick, and
// when the address comes back to the entry (acquire's returnLocked).
type entryInit struct {
	CeilingRate int64
	FairTotals  fairTotals
}

// entryInitOf is what a new entry of a secret with these limits starts from:
// its client-speed as the ceiling. Fair share is not here yet, so a new entry's
// fair limiters are unlimited; client-fair fills them in when it lands.
func entryInitOf(lim SecretLimits) entryInit {
	return entryInit{CeilingRate: lim.ClientSpeedBytesPerSecond}
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
	// a byte moving -- stored only when the second moves on. The sweep measures
	// idleness from it.
	firstSeen time.Time
	lastSeen  atomic.Int64

	// clock is the table's, set when the entry is made and never changed: the
	// clock the entry's limiters run on, and the one the data path stamps
	// lastSeen and the blocked trackers by, so that all of them agree with the
	// sweep and the fair-share ticker about what time it is.
	clock addrClock

	// ceiling is client-speed, combined across both directions; the rest
	// entry never has one. The fair limiters are client-fair's share of the
	// secret's combined, upload and download limits, one each. A limiter with
	// nothing installed is unlimited.
	ceiling                     addrLimiter
	fairSpeed, fairUp, fairDown addrLimiter

	// throttledNanos is the time the address's streams spent waiting at its
	// own limiters, the ceiling's included. Only grows.
	throttledNanos atomic.Int64

	// The blocked trackers measure fair share's duty, one per fair limiter:
	// the time at least one of the address's streams was waiting at that fair
	// limiter or at the user's bucket it divides. Never the ceiling's waits. See
	// blocked_tracker.go.
	blockedSpeed, blockedUp, blockedDown blockedTracker

	// fair is what fair share remembers of the address from one tick to the
	// next. Guarded by the table's lock. See fair_share.go.
	fair fairEntryState
}

// lastSeenStepBack is how far back a stamp has to go before seen takes it for
// the clock's own step rather than a race between streams. Streams that read
// the clock moments apart disagree by a second; a wall clock put right after a
// machine resumed with a bad time can be minutes or hours out.
const lastSeenStepBack = time.Minute

// seen stamps lastSeen with now, to the second, writing only when the second
// has moved on past the stamp, as markActive does. The streams of one address
// stamp it from many goroutines, and one that read the clock a moment before
// another must not take the stamp back when it stores after it, so an earlier
// second is ignored -- unless it is lastSeenStepBack or more earlier, which is
// the wall clock stepped back: a stamp left in the future would keep the sweep
// from forgetting the address until that future came, plus ten minutes.
//
// A stamp that is current costs one load. That it costs no store is not
// something a value can show -- a store of the same second leaves the same
// number -- and only the benchmarks that put many streams on one entry, the
// CountingConnParallel entry rows and the addr=shared/tracked door rows, would
// see a store on every call.
func (e *clientEntry) seen(now time.Time) {
	second := now.Unix()

	for {
		last := e.lastSeen.Load()
		if second == last || (second < last && last-second < int64(lastSeenStepBack/time.Second)) {
			return
		}

		if e.lastSeen.CompareAndSwap(last, second) {
			return
		}
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

	// fair is the secret's fair share: the totals its fair limiters are made
	// for, and what the ticks have measured. See fair_share.go.
	fair fairSecretState
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

	// beforeFairPublish, when set, runs in a fair-share tick after it has
	// decided and before it takes the lock again to publish, with the lock
	// released. Only tests set it, and it is read without the lock: a test
	// sets it before anything that ticks is running.
	beforeFairPublish func()
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

// acquire finds or makes the entry a new stream of the named secret is
// governed by, and holds it for the stream: the address's own entry when key is
// keyed and the table has room for it, and the secret's rest entry otherwise.
// A keyed address that finds no room is counted as an overflow, once per
// connection; an unkeyed one is not, since no cap turned it away.
//
// An entry that already exists is returned as it is: its bucket, bytes and
// limiters are what its address left, whatever init says now -- except that an
// address coming back to an entry no stream held runs at its secret's fair
// level as it is now, not the one it left at. A new one has its limiters made
// from init before it is published -- a rest entry without the ceiling, fair
// limiters at the secret's level -- so nobody ever sees it without them.
func (t *clientTable) acquire(name string, key addressKey, keyed bool, init entryInit) *clientEntry {
	if t == nil {
		return nil
	}

	now := t.clock.read()

	t.mu.Lock()
	defer t.mu.Unlock()

	sc := t.secrets[name]
	if sc == nil {
		sc = &secretClients{entries: make(map[addressKey]*clientEntry), fair: fairSecretState{totals: init.FairTotals}}
		t.secrets[name] = sc
	}

	if keyed {
		entry := sc.entries[key]

		switch {
		case entry != nil:
			t.returnLocked(sc, entry, init)
		case len(sc.entries) < maxClientsPerSecret && t.keyed < maxClients:
			entry = t.makeLocked(sc, name, key, false, init, now)
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
		sc.rest = t.makeLocked(sc, name, "", true, init, now)
	} else {
		t.returnLocked(sc, sc.rest, init)
	}

	t.holdLocked(sc.rest, now)

	return sc.rest
}

// makeLocked builds an entry of sc with its limiters already made and appends
// it to all. Its fair limiters start at the secret's level, or at the total
// when the table knows none -- the secret's first tick is still to come, or
// nobody took part in the last, which leaves the level at the total. The caller
// publishes it. Caller holds mu.
func (t *clientTable) makeLocked(
	sc *secretClients, name string, key addressKey, rest bool, init entryInit, now time.Time,
) *clientEntry {
	entry := &clientEntry{key: key, name: name, rest: rest, firstSeen: now, clock: t.clock}

	// The clock first: a limiter must run on the table's clock from the first
	// call made on it.
	for _, l := range []*addrLimiter{&entry.ceiling, &entry.fairSpeed, &entry.fairUp, &entry.fairDown} {
		l.clock = t.clock
	}

	if !rest && init.CeilingRate > 0 {
		entry.ceiling.install(init.CeilingRate, ceilingBurst(init.CeilingRate))
	}

	for b := range fairBucketCount {
		if total := init.FairTotals.of(b); total > 0 {
			entry.fairLimiter(b).install(sc.fair.rate(b, total), fairBurst(total))
		}
	}

	entry.index = len(t.all)
	t.all = append(t.all, entry)

	return entry
}

// returnLocked moves an existing entry of sc that no stream holds -- an
// address coming back within the retention window -- to the secret's fair
// level as it is now. The tick sets only the entries a stream holds, so an
// address that left at another level would otherwise come back at that one.
// Only a limiter that is there is moved, and init's totals say which buckets
// are divided. An entry a stream still holds is at the level already. Caller
// holds mu.
func (t *clientTable) returnLocked(sc *secretClients, entry *clientEntry, init entryInit) {
	if entry.refs > 0 {
		return
	}

	for b := range fairBucketCount {
		if total := init.FairTotals.of(b); total > 0 {
			t.setRate(entry, b, sc.fair.rate(b, total))
		}
	}
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
// An entry no stream holds whose stamp is more than lastSeenStepBack ahead of
// now is forgotten too. The wall clock was stepped back under it: the stamp
// says nothing about how long the address has been gone, and an idle entry is
// never stamped again to bring it back, so it would otherwise be kept for the
// step plus ten minutes. A held entry is kept whatever its stamp, and a stamp a
// little ahead is only skew between two reads of the clock.
//
// It takes the table's lock and nothing else: it never takes liveMu.
func (t *clientTable) sweep(now time.Time, maxPerHold int) int {
	if t == nil {
		return 0
	}

	maxPerHold = max(maxPerHold, 1)
	cutoff := now.Add(-clientIdleRetention).Unix()
	future := now.Add(lastSeenStepBack).Unix()
	dropped := 0

	t.mu.Lock()

	cursor := len(t.all) - 1

	for {
		walked := 0

		for ; cursor >= 0 && walked < maxPerHold; cursor-- {
			walked++

			entry := t.all[cursor]
			if seen := entry.lastSeen.Load(); entry.refs == 0 && (seen <= cutoff || seen > future) {
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

// applyCeilings moves the ceiling of every address entry the table holds to
// what rateOf says for the entry's secret, 0 for none: how a reload reaches the
// entries made before it. Entries no stream holds are moved too: an address
// that comes back finds its entry as it left it, and must not find the ceiling
// of a reload ago. Rest entries are left alone, because they never have a
// ceiling, and so is every entry of a secret rateOf does not know: the reload
// drops those and closes their streams straight after, and lifting their
// ceilings first would let those streams relay unheld for the moment between.
//
// The caller holds liveMu, the lock admission makes an entry under from the
// secret set it reads there. A reload swaps its set in before it gets here, so
// an admission that read the set before the swap made its entry before this
// walk, which moves it, and one after it read the new set: no entry is ever
// left on a ceiling a reload has replaced.
func (t *clientTable) applyCeilings(rateOf func(name string) (bytesPerSecond int64, kept bool)) {
	if t == nil {
		return
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	for name, sc := range t.secrets {
		bytesPerSecond, kept := rateOf(name)
		if !kept {
			continue
		}

		for _, entry := range sc.entries {
			entry.ceiling.apply(bytesPerSecond, ceilingBurst(bytesPerSecond))
		}
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

// clientCounts is one secret's two numbers on /stats: the addresses it holds an
// entry for, the rest entry not counted, and its overflow count.
type clientCounts struct {
	clients  int
	overflow int64
}

// counts is every secret's clientCounts, read under one hold of the lock
// rather than two per secret, so a /stats scrape of many users takes the table's
// lock once. Nil on a nil table.
func (t *clientTable) counts() map[string]clientCounts {
	if t == nil {
		return nil
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	out := make(map[string]clientCounts, len(t.secrets))
	for name, sc := range t.secrets {
		out[name] = clientCounts{clients: len(sc.entries), overflow: sc.overflow}
	}

	return out
}

// clientsView is one secret's part of the table as GET /secrets/{name}/clients
// reads it, copied under one hold of the lock so the numbers agree with each
// other. The entries are the live objects, read through their atomics after
// the lock is let go; only what the lock guards is copied here.
type clientsView struct {
	// entries are the secret's address entries, the rest entry not among them,
	// in no order. Nil unless the caller asked for them.
	entries []*clientEntry

	// rest is the secret's rest entry, nil when it has none or the caller did
	// not ask for the entries, and restRefs how many streams hold it, which
	// only the lock may read.
	rest     *clientEntry
	restRefs int

	// total is how many address entries the secret holds, and overflow its
	// overflow count.
	total    int
	overflow int64
}

// view copies the named secret's part of the table: the counts always, and the
// entries only when withEntries says so, so a caller that may not list
// addresses never holds them. The zero view for a secret the table holds
// nothing for, and on a nil table.
//
// It takes the table's lock alone. GET /secrets/{name}/clients calls it under
// liveMu, which comes before tableMu in the lock order, so that the ledger's
// connection counts it reads beside are from the same moment.
func (t *clientTable) view(name string, withEntries bool) clientsView {
	if t == nil {
		return clientsView{}
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	sc := t.secrets[name]
	if sc == nil {
		return clientsView{}
	}

	view := clientsView{total: len(sc.entries), overflow: sc.overflow}
	if !withEntries {
		return view
	}

	view.entries = make([]*clientEntry, 0, len(sc.entries))
	for _, entry := range sc.entries {
		view.entries = append(view.entries, entry)
	}

	if sc.rest != nil {
		view.rest, view.restRefs = sc.rest, sc.rest.refs
	}

	return view
}
