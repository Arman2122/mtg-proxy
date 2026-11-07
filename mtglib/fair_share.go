package mtglib

import (
	"math"
	"time"
)

// Fair share: client-fair divides each of a secret's speed limits among the
// addresses using it, by the water level (water_level.go), once a tick.
//
// Every tick, for each limit the secret has -- speed, speed-up, speed-down,
// each divided on its own -- the addresses taking part are its keyed entries
// with a live stream that moved a byte in that limit's direction, or was
// blocked waiting to, in the last ten seconds, and its rest entry whenever a
// stream holds it: one share however many clients it stands for. An address
// held in one long wait has moved nothing but is asking for its share; at a
// small level a 16 KiB write sleeps longer than ten seconds, and dropping such
// an address would hand its share to the others. Each has a duty, the fraction of the
// tick during which at least one of its streams was blocked in that direction,
// at its fair limiter or at the user's bucket the limiter divides -- never at
// its ceiling. A duty of a quarter or more is throttled: the address wants
// more than it gets, so it has no demand to report and asks for everything.
// Any other address asks for what it moved. The level L shares the total among
// those demands, and every entry of the secret with a live stream is set to it,
// the quiet ones too, so that one waking up does not run at a stale rate.
//
// The secret's bucket counts in the duty because it divides its tokens per
// connection, not per address: an address with four connections takes four
// times what an address with one does there, and neither is ever held at its
// own fair limiter, which sits above what each gets. Without those waits the
// split would report itself as two satisfied demands that add up to the total,
// and stay 4:1. The ceiling's waits do not count: an address its own ceiling
// holds back is not short of its share, and saying it was would take from the
// others what it cannot use.
//
// A throttle holds for three more ticks, so a share does not flap on one quiet
// tick, unless the address moved less than half the level -- a download that
// paused -- which releases it at once and hands its share to the others now.
//
// The decision is decideFairShare, a pure function over what the tick knows of
// each entry. tick gathers that under the table's lock, decides outside it,
// and publishes under it again; it never takes liveMu. One goroutine ticks.

const (
	// fairThrottleDivisor: an address blocked for at least 1/fairThrottleDivisor
	// of the tick is throttled. A quarter is far above the noise of the clock
	// reads around the waits -- hundreds of nanoseconds each -- and far below
	// the duty of an address that wants more than its share, which is blocked
	// nearly all the time.
	fairThrottleDivisor = 4

	// fairHoldTicks is how many ticks a throttle outlives the duty that set
	// it, while the address keeps moving at least half the level.
	fairHoldTicks = 3

	// fairActiveWindow is how recently an address must have moved a byte, or
	// been blocked waiting to, to take part. A connected address quiet for
	// longer asks for nothing, and is still set to the level.
	fairActiveWindow = 10 * time.Second

	// fairTickInterval is how often the proxy's ticker ticks every fair
	// secret. A second is short enough that a share follows an address that
	// starts or stops within about two, and long enough that a tick's work --
	// a walk of the secret's entries -- is nothing beside it.
	fairTickInterval = time.Second
)

// fairBucket is one of a secret's speed limits as fair share divides it, with
// the fair limiter, the blocked tracker and the bytes that go with it.
type fairBucket int

const (
	// fairSpeedBucket is speed, both directions together: fairSpeed,
	// blockedSpeed, and every byte the address moved.
	fairSpeedBucket fairBucket = iota

	// fairUpBucket is speed-up, what the address sends: fairUp, blockedUp, and
	// its reads, bytesIn.
	fairUpBucket

	// fairDownBucket is speed-down, what the address receives: fairDown,
	// blockedDown, and its writes, bytesOut.
	fairDownBucket

	// fairBucketCount is how many there are.
	fairBucketCount
)

// of is the total of bucket b, 0 when it is not divided.
func (f fairTotals) of(b fairBucket) int64 {
	switch b {
	case fairUpBucket:
		return f.Up
	case fairDownBucket:
		return f.Down
	default: // fairSpeedBucket
		return f.Speed
	}
}

// fairLimiter is the entry's fair limiter for bucket b.
func (e *clientEntry) fairLimiter(b fairBucket) *addrLimiter {
	switch b {
	case fairUpBucket:
		return &e.fairUp
	case fairDownBucket:
		return &e.fairDown
	default: // fairSpeedBucket
		return &e.fairSpeed
	}
}

// fairBlocked is the tracker of the entry's duty in bucket b.
func (e *clientEntry) fairBlocked(b fairBucket) *blockedTracker {
	switch b {
	case fairUpBucket:
		return &e.blockedUp
	case fairDownBucket:
		return &e.blockedDown
	default: // fairSpeedBucket
		return &e.blockedSpeed
	}
}

// fairBytes is what an entry moved in bucket b's direction, out of what it
// read (in) and wrote (out).
func fairBytes(b fairBucket, in, out int64) int64 {
	switch b {
	case fairUpBucket:
		return in
	case fairDownBucket:
		return out
	default: // fairSpeedBucket
		return in + out
	}
}

// fairSecret is a secret as one tick divides it: its name and the totals of
// the limits its client-fair divides, each 0 when not divided.
type fairSecret struct {
	name   string
	totals fairTotals
}

// fairEntry is what one tick knows of one entry in one bucket: the input of
// the decision. tick gathers it from the table and the entry; the tests write
// it out.
type fairEntry struct {
	// live is whether a stream holds the entry, rest whether it is the
	// secret's rest entry, and active whether it moved a byte in the bucket's
	// direction, or was blocked waiting to, in the last fairActiveWindow.
	live, rest, active bool

	// rate is what it moved in the bucket's direction over the tick, in bytes
	// a second.
	rate int64

	// blocked is the time at least one of its streams was blocked in the
	// bucket's direction over the tick, the duty's numerator.
	blocked time.Duration

	// hold is how many more ticks a throttle from an earlier tick holds, as
	// the last decision left it.
	hold int
}

// fairVerdict is the decision about one entry.
type fairVerdict struct {
	// participant is whether it took part in the level, and throttled whether
	// it took part asking for everything.
	participant, throttled bool

	// duty is its blocked time over the tick, clamped to [0, 1].
	duty float64

	// hold is how many more ticks its throttle holds, for the next decision.
	hold int
}

// decideFairShare is one tick of one bucket of one secret, pure: total is the
// secret's total for the bucket, previous the level the entries ran at over
// the tick -- the total when there was none -- and elapsed the tick's length,
// which must be positive. It returns the new level and a verdict per entry, in
// the order given. Every entry with a live stream is to be set to the level,
// participant or not; the others are left as they are.
//
// A participant is live, and active in the last ten seconds or the rest entry.
// Its duty is blocked over elapsed, clamped to [0, 1]. A duty of at
// least a quarter throttles it and holds the throttle for fairHoldTicks more
// ticks. A participant whose throttle is held from an earlier tick stays
// throttled while it moves at least half of previous, and is released below
// that. A throttled participant demands demandInfinite and any other one its
// rate; the level is waterLevel of the total over those demands, at least 1.
// A non-participant has no throttle and no hold.
func decideFairShare(total, previous int64, elapsed time.Duration, entries []fairEntry) (int64, []fairVerdict) {
	verdicts := make([]fairVerdict, len(entries))
	demands := make([]int64, 0, len(entries))

	for i, entry := range entries {
		blocked := min(max(entry.blocked, 0), elapsed)
		verdict := fairVerdict{
			participant: entry.live && (entry.rest || entry.active),
			duty:        float64(blocked) / float64(elapsed),
		}

		if verdict.participant {
			switch {
			case fairThrottleDivisor*blocked >= elapsed:
				verdict.throttled, verdict.hold = true, fairHoldTicks
			case entry.hold > 0 && entry.rate >= previous-previous/2:
				// At least half the level, rounded up: a rate that is an
				// integer is below previous/2 exactly when it is below this.
				verdict.throttled, verdict.hold = true, entry.hold-1
			}

			demand := entry.rate
			if verdict.throttled {
				demand = demandInfinite
			}

			demands = append(demands, demand)
		}

		verdicts[i] = verdict
	}

	return waterLevel(total, demands), verdicts
}

// fairBucketState is what fair share remembers of an entry in one bucket.
type fairBucketState struct {
	// hold is how many more ticks the entry's throttle holds.
	hold int

	// active is the last tick whose window the entry moved a byte in, in the
	// bucket's direction, or spent time blocked waiting to. It is measured from
	// the bytes and the blocked tracker, not from lastSeen, which a connection
	// opening or closing stamps too.
	active time.Time

	// participant and throttled are the last decision about the entry, kept
	// so that it can be read.
	participant, throttled bool
}

// fairEntryState is what fair share remembers of an entry from one tick to
// the next. Guarded by the table's lock: a tick copies it under one hold of
// the lock and writes it back under another, and applyFair clears a bucket of
// it when the bucket's limiter is installed or removed.
type fairEntryState struct {
	// bytesIn and bytesOut are the entry's counters as the last tick read them.
	// A new entry's are 0, which is what its counters started at.
	bytesIn, bytesOut int64

	buckets [fairBucketCount]fairBucketState
}

// fairSecretState is a secret's fair share. Guarded by the table's lock.
type fairSecretState struct {
	// totals are what the secret's fair limiters are made for: the totals of
	// the entry that made the secret's part of the table, and then whatever
	// applyFair last set.
	totals fairTotals

	// level is the last level of each bucket, 0 when there is none yet for its
	// total. A new or returning address starts there.
	level [fairBucketCount]int64

	// lastTick is when the last tick measured, zero before the first and
	// after applyFair changes the secret's fair limiters: the tick that
	// follows only takes a baseline.
	lastTick time.Time

	// epoch moves whenever applyFair changes the secret's fair limiters. A
	// tick that finds it moved between its two holds of the lock measured
	// limiters and states that are gone, and publishes nothing.
	epoch uint64
}

// rate is what an entry of the secret is set to when it gets a bucket's fair
// limiter, or a stream again after it had none: the level, or the total when
// there is no level for it. A level above total belongs to another total.
func (s *fairSecretState) rate(b fairBucket, total int64) int64 {
	if level := s.level[b]; level > 0 && level <= total {
		return level
	}

	return total
}

// fairGathered is one entry as a tick gathered it.
type fairGathered struct {
	entry *clientEntry
	live  bool
	state fairEntryState

	// in and out are what it read and wrote since the last tick, and blocked
	// what each bucket's tracker held.
	in, out int64
	blocked [fairBucketCount]time.Duration
}

// tick is one fair-share tick of secret, at now: for each bucket the secret
// divides, it measures every entry of the secret over the time since the last
// tick, decides the level, and sets every entry with a live stream to it.
//
// It takes the table's lock twice, and otherwise only the leaf locks after it
// in the lock order -- each blocked tracker's, and each fair limiter's -- never
// liveMu. The first hold copies the secret's entries, whether a stream holds
// each, and what fair share remembers of them. Outside the lock it reads their
// counters and snapshots their blocked trackers -- every entry's, so that a
// window never spans more than one tick -- and decides. The second hold
// publishes the level and the states and sets the entries a stream holds by
// then, so an address that arrived while the tick was deciding gets the new
// level too. If a reload moved the secret's fair limiters in between, the tick
// publishes nothing.
//
// The first tick of a secret, the first after a reload moved its fair
// limiters, and a tick whose instant is not after the last one's -- a clock
// put back -- only take a baseline: there is no tick length to measure a rate
// over, or none that the limiters now in place were measured across.
//
// One goroutine ticks a secret. A snapshot takes a tracker's window with it,
// so a second tick running beside the first would measure next to nothing and
// publish levels nobody is held at.
func (t *clientTable) tick(now time.Time, secret fairSecret) {
	if t == nil {
		return
	}

	buckets := make([]fairBucket, 0, fairBucketCount)

	for b := range fairBucketCount {
		if secret.totals.of(b) > 0 {
			buckets = append(buckets, b)
		}
	}

	if len(buckets) == 0 {
		return
	}

	t.mu.Lock()

	sc := t.secrets[secret.name]
	if sc == nil {
		t.mu.Unlock()

		return
	}

	gathered := make([]fairGathered, 0, len(sc.entries)+1)

	for _, entry := range sc.entries {
		gathered = append(gathered, fairGathered{entry: entry, live: entry.refs > 0, state: entry.fair})
	}

	if sc.rest != nil {
		gathered = append(gathered, fairGathered{entry: sc.rest, live: sc.rest.refs > 0, state: sc.rest.fair})
	}

	epoch, last, levels := sc.fair.epoch, sc.fair.lastTick, sc.fair.level

	t.mu.Unlock()

	for i := range gathered {
		g := &gathered[i]

		in, out := g.entry.bytesIn.Load(), g.entry.bytesOut.Load()
		g.in, g.out = max(in-g.state.bytesIn, 0), max(out-g.state.bytesOut, 0)
		g.state.bytesIn, g.state.bytesOut = in, out

		for _, b := range buckets {
			g.blocked[b] = g.entry.fairBlocked(b).snapshot(now)
		}
	}

	elapsed := now.Sub(last)
	decided := !last.IsZero() && elapsed > 0

	if decided {
		for _, b := range buckets {
			levels[b] = decideBucket(b, secret.totals.of(b), levels[b], now, elapsed, gathered)
		}
	}

	if t.beforeFairPublish != nil {
		t.beforeFairPublish()
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	if sc.fair.epoch != epoch {
		return
	}

	for _, g := range gathered {
		g.entry.fair = g.state
	}

	sc.fair.lastTick = now

	if !decided {
		return
	}

	for _, b := range buckets {
		sc.fair.level[b] = levels[b]
	}

	set := func(entry *clientEntry) {
		if entry.refs > 0 {
			for _, b := range buckets {
				t.setRate(entry, b, levels[b])
			}
		}
	}

	for _, entry := range sc.entries {
		set(entry)
	}

	if sc.rest != nil {
		set(sc.rest)
	}
}

// decideBucket is the decision of one bucket over the gathered entries, whose
// states it updates with the verdicts; it returns the level. previous is the
// level the entries ran at, 0 for none.
func decideBucket(
	b fairBucket, total, previous int64, now time.Time, elapsed time.Duration, gathered []fairGathered,
) int64 {
	if previous <= 0 || previous > total {
		previous = total
	}

	entries := make([]fairEntry, len(gathered))

	for i := range gathered {
		g := &gathered[i]
		state := &g.state.buckets[b]

		// Blocked time counts as activity: a write held in one long wait moves
		// nothing until it ends, and is asking for its share all along.
		moved := fairBytes(b, g.in, g.out)
		if moved > 0 || g.blocked[b] > 0 {
			state.active = now
		}

		entries[i] = fairEntry{
			live:    g.live,
			rest:    g.entry.rest,
			active:  !state.active.IsZero() && now.Sub(state.active) < fairActiveWindow,
			rate:    fairRateOver(moved, elapsed),
			blocked: g.blocked[b],
			hold:    state.hold,
		}
	}

	level, verdicts := decideFairShare(total, previous, elapsed, entries)

	for i, verdict := range verdicts {
		state := &gathered[i].state.buckets[b]
		state.hold, state.participant, state.throttled = verdict.hold, verdict.participant, verdict.throttled
	}

	return level
}

// fairRateOver is moved bytes over elapsed, in bytes a second. Float, so a
// long tick's count cannot overflow on the way, and saturated: a rate past
// what an int64 holds is as good as infinite.
func fairRateOver(moved int64, elapsed time.Duration) int64 {
	if moved <= 0 || elapsed <= 0 {
		return 0
	}

	rate := float64(moved) / elapsed.Seconds()
	if rate >= math.MaxInt64 {
		return demandInfinite
	}

	return int64(rate)
}

// setRate re-rates the entry's fair limiter for bucket to bytesPerSecond. It
// is the one way a fair share moves, and the hook piece D's adaptive rate
// plugs into. It never makes a limiter -- only a new entry's init and
// applyFair do -- and never hands one a zero, which would read as unlimited.
func (t *clientTable) setRate(entry *clientEntry, bucket fairBucket, bytesPerSecond int64) {
	if t == nil || entry == nil {
		return
	}

	entry.fairLimiter(bucket).setRate(bytesPerSecond)
}

// applyFair moves the fair limiters of every entry the table holds to the
// totals rateOf says for the entry's secret: how a reload that turns fair
// share on or off, or adds, changes or removes one of the limits it divides,
// reaches the entries made before it. Every entry: the rest entry, and entries
// no stream holds, which an address that comes back must find as the secret is
// now. A bucket with a total gets a limiter with that total's burst, run at the
// secret's level, or at the total when the total changed and there is no level
// for it yet; a bucket without one has its limiter removed, which is
// unlimited. A limiter installed or installed again starts with an empty
// tracker and no throttle: time from an earlier fair period must not start a
// hysteresis nobody earned. Once anything changed, the secret's next tick only
// takes a baseline: the last tick may be long past -- fair share was off, and
// nothing ticked -- and a tick across that gap would measure an average of it,
// not the second the new limiters ran. A secret rateOf does not know is left to
// the drop that follows, as applyCeilings leaves it.
//
// The caller holds liveMu, the lock admission makes an entry under, so no
// entry is made from one set and missed by the walk for the next.
func (t *clientTable) applyFair(rateOf func(name string) (totals fairTotals, kept bool)) {
	if t == nil {
		return
	}

	now := t.clock.read()

	t.mu.Lock()
	defer t.mu.Unlock()

	for name, sc := range t.secrets {
		totals, kept := rateOf(name)
		if !kept {
			continue
		}

		t.applyFairLocked(sc, totals, now)
	}
}

// applyFairLocked is applyFair for one secret. Caller holds mu.
func (t *clientTable) applyFairLocked(sc *secretClients, totals fairTotals, now time.Time) {
	changed := sc.fair.totals != totals

	for b := range fairBucketCount {
		if totals.of(b) != sc.fair.totals.of(b) {
			sc.fair.level[b] = 0
		}
	}

	sc.fair.totals = totals

	apply := func(entry *clientEntry) {
		for b := range fairBucketCount {
			limiter := entry.fairLimiter(b)
			before := limiter.limiter.Load()

			if total := totals.of(b); total > 0 {
				limiter.apply(sc.fair.rate(b, total), fairBurst(total))
			} else {
				limiter.apply(0, 0)
			}

			after := limiter.limiter.Load()
			if after == before {
				continue
			}

			changed = true
			entry.fair.buckets[b] = fairBucketState{}

			if after != nil {
				entry.fairBlocked(b).snapshot(now)
			}
		}
	}

	for _, entry := range sc.entries {
		apply(entry)
	}

	if sc.rest != nil {
		apply(sc.rest)
	}

	if changed {
		sc.fair.epoch++
		sc.fair.lastTick = time.Time{}
	}
}
