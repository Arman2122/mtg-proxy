package mtglib

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Fair share, tested synthetically. The decision is a pure function over what
// one tick knows of each entry, so most of what it promises is a table of
// numbers. The tick around it gathers those numbers from real entries -- real
// counters, real blocked trackers, real limiters on a fake clock -- and the
// traffic that feeds them is a model rather than sockets: the secret's bucket
// shares its tokens per connection, each address's limiters cap its
// connections, and a connection that wants more than it gets is blocked at
// whichever of the two binds. How real streams time out is 12b's end-to-end
// test, in wide bands.

// fairTestTotal is the limit most of these tests divide. A round decimal, so
// that its halves, thirds, fifths and eighths come out the same in the model's
// arithmetic and the tick's.
const fairTestTotal = 1_000_000

// fairTestTick is one tick.
const fairTestTick = time.Second

// fairBucketName names a bucket by the config key it divides.
func fairBucketName(b fairBucket) string {
	switch b {
	case fairUpBucket:
		return "speed-up"
	case fairDownBucket:
		return "speed-down"
	default:
		return "speed"
	}
}

// fairTotalsOf is a secret whose only fair total is total, in bucket b.
func fairTotalsOf(b fairBucket, total int64) fairTotals {
	switch b {
	case fairUpBucket:
		return fairTotals{Up: total}
	case fairDownBucket:
		return fairTotals{Down: total}
	default:
		return fairTotals{Speed: total}
	}
}

// fairCount counts n bytes moved in bucket b's direction on e: what the
// address sent for speed-up, what it received for speed-down, and a download
// for the combined bucket, which counts both directions alike.
func fairCount(e *clientEntry, b fairBucket, n int64) {
	if b == fairUpBucket {
		e.bytesIn.Add(n)

		return
	}

	e.bytesOut.Add(n)
}

// fairBlockTick has one of e's streams blocked in bucket b's direction for the
// whole tick that starts at start.
func fairBlockTick(e *clientEntry, b fairBucket, start time.Time) {
	blocked := e.fairBlocked(b)
	blocked.enter(start)
	blocked.leave(start.Add(fairTestTick))
}

// fairStateOf is what the last tick decided for e in bucket b, read under the
// table's lock.
func fairStateOf(table *clientTable, e *clientEntry, b fairBucket) fairBucketState {
	table.mu.Lock()
	defer table.mu.Unlock()

	return e.fair.buckets[b]
}

// fairLevelOf is the level the table remembers for name in bucket b, 0 for
// none, read under the table's lock.
func fairLevelOf(table *clientTable, name string, b fairBucket) int64 {
	table.mu.Lock()
	defer table.mu.Unlock()

	if sc := table.secrets[name]; sc != nil {
		return sc.fair.level[b]
	}

	return 0
}

// fairRate is e's fair limiter for b as it runs now, 0 for none.
func fairRate(e *clientEntry, b fairBucket) int64 {
	return e.fairLimiter(b).bytesPerSecond()
}

// assertFairInvariant checks what fair share's duty rests on, for one secret
// of table: each fair limiter is installed exactly when the secret's total for
// its bucket is set, on EVERY entry the table holds for the secret -- the rest
// entry, entries no stream holds, entries made before the total was set --
// with the burst made from that total and a rate within it, and the table's
// own record of the totals agrees. A wait at the secret's bucket is counted in
// the duty only when the matching fair limiter is installed
// (countingConn.waitShared), so an entry missing one fails silently: its duty
// reads nothing and the 4:1 lock-in comes back. 12b calls this after
// applyLimits, with the totals of the secret's client-fair, or none.
func assertFairInvariant(t *testing.T, table *clientTable, name string, totals fairTotals) bool {
	t.Helper()

	ok := true

	for _, entry := range table.snapshot(name) {
		for b := range fairBucketCount {
			total := totals.of(b)
			current := entry.fairLimiter(b).limiter.Load()

			if total <= 0 {
				ok = assert.Nil(t, current, "%s's entry %q has a %s share with none configured",
					name, entry.key, fairBucketName(b)) && ok

				continue
			}

			if !assert.NotNil(t, current, "%s's entry %q (rest %v, refs %d) has no %s share",
				name, entry.key, entry.rest, clientRefs(table, entry), fairBucketName(b)) {
				ok = false

				continue
			}

			ok = assert.Equal(t, fairBurst(total), current.Burst(), "%s's entry %q: the %s burst comes from the total",
				name, entry.key, fairBucketName(b)) && ok

			rate := int64(current.Limit())
			ok = assert.True(t, rate >= 1 && rate <= total, "%s's entry %q: a %s rate of %d is outside [1, %d]",
				name, entry.key, fairBucketName(b), rate, total) && ok
		}
	}

	table.mu.Lock()
	sc := table.secrets[name]

	var recorded fairTotals
	if sc != nil {
		recorded = sc.fair.totals
	}
	table.mu.Unlock()

	if sc != nil {
		ok = assert.Equal(t, totals, recorded, "the table's record of %s's totals", name) && ok
	}

	return ok
}

// Spec §3 gives these numbers verbatim.
func TestFairShareConstantsAreTheSpecs(t *testing.T) {
	t.Parallel()

	assert.Equal(t, 4, fairThrottleDivisor, "throttled at a duty of a quarter of the tick")
	assert.Equal(t, 3, fairHoldTicks, "a throttle holds three ticks")
	assert.Equal(t, 10*time.Second, fairActiveWindow, "a participant moved a byte in the last ten seconds")
}

// ---- the pure decision -------------------------------------------------------

// decideOneTick is one decision over a tick of one second.
func decideOneTick(total, previous int64, entries ...fairEntry) (int64, []fairVerdict) {
	return decideFairShare(total, previous, fairTestTick, entries)
}

// fairBusy is a participant blocked for the whole tick, having moved rate.
func fairBusy(rate int64) fairEntry {
	return fairEntry{live: true, active: true, rate: rate, blocked: fairTestTick}
}

// fairQuiet is a participant that moved rate and was never blocked.
func fairQuiet(rate int64) fairEntry {
	return fairEntry{live: true, active: true, rate: rate}
}

// Work-conserving: an address that wants less than its share keeps what it
// wants, and the address that wants more gets the rest. Nobody is held when
// the demands fit.
func TestFairShareGivesTheQuietAddressItsDemand(t *testing.T) {
	t.Parallel()

	level, verdicts := decideOneTick(fairTestTotal, fairTestTotal, fairBusy(900_000), fairQuiet(100_000))

	assert.EqualValues(t, 900_000, level, "the low one keeps its demand, the high one gets the rest")
	require.Len(t, verdicts, 2)
	assert.True(t, verdicts[0].participant)
	assert.True(t, verdicts[0].throttled, "blocked all tick: it wants more than it gets")
	assert.True(t, verdicts[1].participant)
	assert.False(t, verdicts[1].throttled)

	level, _ = decideOneTick(fairTestTotal, fairTestTotal, fairQuiet(300_000), fairQuiet(100_000))
	assert.EqualValues(t, fairTestTotal, level, "demands that fit hold nobody back")
}

// Throttled is a duty of at least a quarter of the tick: the time at least one
// stream was blocked over the tick's length, so the same blocked time is a
// throttle in a short tick and not in a long one.
func TestFairShareThrottlesAtAQuarterOfTheTick(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		elapsed, blocked time.Duration
		throttled        bool
	}{
		{time.Second, 250 * time.Millisecond, true},
		{time.Second, 250*time.Millisecond - time.Nanosecond, false},
		{time.Second, time.Second, true},
		{time.Second, 0, false},
		{2 * time.Second, 500 * time.Millisecond, true},
		{2 * time.Second, 499 * time.Millisecond, false},
	} {
		_, verdicts := decideFairShare(fairTestTotal, fairTestTotal, tc.elapsed,
			[]fairEntry{{live: true, active: true, rate: 1000, blocked: tc.blocked}})
		require.Len(t, verdicts, 1)

		assert.Equal(t, tc.throttled, verdicts[0].throttled, "%v blocked in a tick of %v", tc.blocked, tc.elapsed)
		assert.InDelta(t, float64(tc.blocked)/float64(tc.elapsed), verdicts[0].duty, 1e-12)
	}
}

// The duty is a fraction of the tick, so it is clamped to [0, 1]: a tracker
// window can hold a little more than its own length when a reading reaches the
// tracker's lock late, and nothing is ever blocked for less than nothing.
func TestFairShareDutyIsClampedToTheTick(t *testing.T) {
	t.Parallel()

	_, verdicts := decideOneTick(fairTestTotal, fairTestTotal,
		fairEntry{live: true, active: true, blocked: 1500 * time.Millisecond},
		fairEntry{live: true, active: true, blocked: -time.Second},
	)
	require.Len(t, verdicts, 2)

	assert.InDelta(t, 1.0, verdicts[0].duty, 0, "more blocked time than the tick is the whole tick")
	assert.True(t, verdicts[0].throttled)
	assert.InDelta(t, 0.0, verdicts[1].duty, 0)
	assert.False(t, verdicts[1].throttled)
}

// Hysteresis: once throttled, an address stays throttled -- its demand +inf --
// for three more ticks while it keeps moving at least half the level, and is let
// go on the fourth. Exactly three: a shorter hold flaps, a longer one keeps a
// quiet address's share from the others.
func TestFairShareHoldsAThrottleForThreeTicks(t *testing.T) {
	t.Parallel()

	const total = 1000

	hold, previous := 0, int64(total)

	for tick := range 6 {
		busy := fairEntry{live: true, active: true, rate: 600, hold: hold}
		if tick == 0 {
			busy = fairBusy(900)
		}

		level, verdicts := decideOneTick(total, previous, busy, fairQuiet(100))
		require.Len(t, verdicts, 2)

		// Three, written out rather than read off the constant, so that a
		// constant changed with the behaviour still fails here.
		if tick <= 3 {
			assert.True(t, verdicts[0].throttled, "tick %d: still held", tick)
			assert.EqualValues(t, 900, level, "tick %d: demand +inf, so the other keeps 100 and it gets the rest", tick)
			assert.Equal(t, 3-tick, verdicts[0].hold, "tick %d", tick)
		} else {
			assert.False(t, verdicts[0].throttled, "tick %d: released after three ticks", tick)
			assert.EqualValues(t, total, level, "tick %d: 600 and 100 fit in 1000", tick)
			assert.Zero(t, verdicts[0].hold, "tick %d", tick)
		}

		hold, previous = verdicts[0].hold, level
	}
}

// A throttled address whose rate falls below half the level -- a downloader
// that paused -- is released at once rather than after three ticks, so the
// others get its share now. At exactly half it is still held.
func TestFairSharePauseReleasesAtOnce(t *testing.T) {
	t.Parallel()

	level, verdicts := decideOneTick(1000, 1000, fairBusy(500), fairBusy(500))
	require.EqualValues(t, 500, level)
	require.Equal(t, fairHoldTicks, verdicts[0].hold)

	paused := fairEntry{live: true, active: true, rate: 0, hold: verdicts[0].hold}

	level, verdicts = decideOneTick(1000, 500, paused, fairBusy(500))
	assert.EqualValues(t, 1000, level, "the paused one is released, so the other gets everything at once")
	assert.False(t, verdicts[0].throttled)
	assert.Zero(t, verdicts[0].hold)

	atHalf := fairEntry{live: true, active: true, rate: 250, hold: fairHoldTicks}

	level, verdicts = decideOneTick(1000, 500, atHalf, fairBusy(500))
	assert.EqualValues(t, 500, level, "half the level is not below it: still held")
	assert.True(t, verdicts[0].throttled)

	belowHalf := fairEntry{live: true, active: true, rate: 249, hold: fairHoldTicks}

	level, verdicts = decideOneTick(1000, 500, belowHalf, fairBusy(500))
	assert.EqualValues(t, 751, level, "released: it keeps its 249 and the other gets the rest")
	assert.False(t, verdicts[0].throttled)

	// With a level of 1 the half is a half: nothing moved is below it.
	level, verdicts = decideOneTick(1000, 1, fairEntry{live: true, active: true, hold: fairHoldTicks}, fairBusy(1))
	assert.EqualValues(t, 1000, level)
	assert.False(t, verdicts[0].throttled)
}

// The release is for an address that stopped asking, not for one that is
// still waiting: a stream blocked all tick in a long wait moves nothing, and
// its duty, not its rate, says what it is.
func TestFairShareCurrentDutyOutweighsTheRelease(t *testing.T) {
	t.Parallel()

	waiting := fairEntry{live: true, active: true, rate: 0, blocked: fairTestTick, hold: fairHoldTicks}

	level, verdicts := decideOneTick(1000, 500, waiting, fairBusy(500))
	assert.EqualValues(t, 500, level)
	assert.True(t, verdicts[0].throttled, "blocked all tick is held, whatever it moved")
	assert.Equal(t, fairHoldTicks, verdicts[0].hold)
}

// Participants are the keyed entries with a live stream that was active --
// moved a byte, or was blocked waiting to -- in the last ten seconds, plus the
// rest entry whenever it has a live stream. active is the gatherer's verdict
// over those ten seconds (TestFairShareTenQuietSecondsEndAParticipation pins
// it); here it is an input. Each case is blocked this tick beside one busy
// participant, so whether it takes part is whether the level is halved.
func TestFairShareParticipants(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name        string
		entry       fairEntry
		participant bool
	}{
		{"an active keyed entry", fairEntry{live: true, active: true}, true},
		{"a keyed entry inactive for ten seconds", fairEntry{live: true}, false},
		{"a keyed entry with no stream", fairEntry{active: true}, false},
		{"the rest entry with a stream", fairEntry{live: true, rest: true}, true},
		{"the rest entry with none", fairEntry{rest: true, active: true}, false},
	} {
		tc.entry.blocked = fairTestTick

		level, verdicts := decideOneTick(1000, 1000, tc.entry, fairBusy(1000))
		require.Len(t, verdicts, 2, tc.name)

		assert.Equal(t, tc.participant, verdicts[0].participant, tc.name)
		assert.True(t, verdicts[1].participant, tc.name)

		if tc.participant {
			assert.EqualValues(t, 500, level, tc.name)
			assert.True(t, verdicts[0].throttled, tc.name)
		} else {
			assert.EqualValues(t, 1000, level, tc.name)
			assert.False(t, verdicts[0].throttled, "%s: a non-participant is never held", tc.name)
			assert.Zero(t, verdicts[0].hold, tc.name)
		}
	}
}

// The level is floored and at least one byte a second -- a zero would read as
// unlimited -- and nothing larger lifts it: lifting it above total/n would put
// the rates' sum above the total and hand the split back to the secret's
// bucket.
func TestFairShareRatesAreNeverZeroAndNothingLiftsThem(t *testing.T) {
	t.Parallel()

	busy := func(n int) []fairEntry {
		entries := make([]fairEntry, n)
		for i := range entries {
			entries[i] = fairBusy(1)
		}

		return entries
	}

	level, _ := decideFairShare(MinSpeedBytesPerSecond, MinSpeedBytesPerSecond, fairTestTick, busy(maxClientsPerSecret+1))
	assert.EqualValues(t, 1, level, "8,000 B/s among 4,097 participants")

	level, _ = decideFairShare(MinSpeedBytesPerSecond, MinSpeedBytesPerSecond, fairTestTick, busy(9000))
	assert.EqualValues(t, 1, level, "a computed 0 is raised to 1, never left at 0")

	level, _ = decideFairShare(100_000, 100_000, fairTestTick, busy(50))
	assert.EqualValues(t, 2000, level, "2,000 B/s each: nothing lifts it to 8,000")

	level, _ = decideFairShare(100_000, 100_000, fairTestTick, nil)
	assert.EqualValues(t, 100_000, level, "nobody taking part: the whole total")
}

// ---- the tick, on real entries ----------------------------------------------

// fairSimAddr is one address in the model: its entry, and how many of its
// connections want more than they get. Zero is an address still connected
// that has paused. Its limits are read off the entry.
type fairSimAddr struct {
	entry *clientEntry
	conns int
}

// fairSim drives one secret's traffic in one bucket's direction a second at a
// time on a fake clock, and ticks after each second.
type fairSim struct {
	table  *clientTable
	clock  *fakeAddrClock
	secret fairSecret
	bucket fairBucket
	addrs  []*fairSimAddr

	// moved is what each address moved in the last second.
	moved []int64
}

// fairSimBlocked is how much of a second a connection that wants more than
// it gets spends waiting: all of it but its writes.
const fairSimBlocked = 900 * time.Millisecond

// newFairSim is a model of the secret "alice" with fairTestTotal in bucket b,
// the secret's own bucket at that total too.
func newFairSim(t *testing.T, b fairBucket) *fairSim {
	t.Helper()

	table, clock := newTestClientTable(t)

	return &fairSim{
		table:  table,
		clock:  clock,
		secret: fairSecret{name: "alice", totals: fairTotalsOf(b, fairTestTotal)},
		bucket: b,
	}
}

// init is what admission would make a new entry from: the secret's fair
// totals, and ceiling as its client-speed.
func (s *fairSim) init(ceiling int64) entryInit {
	return entryInit{CeilingRate: ceiling, FairTotals: s.secret.totals}
}

// join connects conns streams from key, each held on the address's entry.
func (s *fairSim) join(t *testing.T, key addressKey, keyed bool, conns int, init entryInit) *fairSimAddr {
	t.Helper()

	addr := &fairSimAddr{conns: conns}

	for range conns {
		entry := s.table.acquire(s.secret.name, key, keyed, init)
		require.NotNil(t, entry)
		require.True(t, addr.entry == nil || addr.entry == entry)

		addr.entry = entry
	}

	s.addrs = append(s.addrs, addr)

	return addr
}

// prime is the first tick, which only takes a baseline.
func (s *fairSim) prime() {
	s.table.tick(s.clock.read(), s.secret)
}

// step runs one second and then the tick. The secret's bucket shares its
// tokens per connection, max-min, each connection capped by its address's
// binding limit -- the fair share, or the ceiling where that is lower -- split
// evenly among the address's connections. A connection whose cap binds waits
// at its address; one that gets less than its cap waits at the secret's
// bucket. The waits countingConn brackets for the duty are the ones at the
// fair limiter and at the secret's bucket of an address that has a fair
// limiter there (waitAddress, waitShared), never the ones at the ceiling.
func (s *fairSim) step() {
	start := s.clock.read()
	total := s.secret.totals.of(s.bucket)

	var (
		caps         []int64
		owners       []int
		ceilingBinds []bool
	)

	for i, a := range s.addrs {
		limit := total

		if fair := fairRate(a.entry, s.bucket); fair > 0 {
			limit = fair
		}

		ceiling := a.entry.ceiling.bytesPerSecond()
		held := ceiling > 0 && ceiling < limit

		if held {
			limit = ceiling
		}

		for range a.conns {
			caps = append(caps, limit/int64(a.conns))
			owners = append(owners, i)
			ceilingBinds = append(ceilingBinds, held)
		}
	}

	level := waterLevel(total, caps)

	s.moved = make([]int64, len(s.addrs))
	tracked := make([]bool, len(s.addrs))

	for j, limit := range caps {
		owner := s.addrs[owners[j]]
		s.moved[owners[j]] += min(limit, level)

		// Held at its address by the ceiling: a wait nothing brackets. Held
		// there by the fair share, or held at the secret's bucket: bracketed,
		// as long as the address has a fair limiter for the bucket.
		atAddress := limit <= level
		atCeiling := atAddress && ceilingBinds[j]

		if !atCeiling && owner.entry.fairLimiter(s.bucket).installed() {
			tracked[owners[j]] = true
		}
	}

	for i, a := range s.addrs {
		fairCount(a.entry, s.bucket, s.moved[i])

		if tracked[i] {
			blocked := a.entry.fairBlocked(s.bucket)
			blocked.enter(start)
			blocked.leave(start.Add(fairSimBlocked))
		}
	}

	s.clock.advance(fairTestTick)
	s.table.tick(s.clock.read(), s.secret)
}

// Review Focus 7, the second review's blocker: a 4-connection address and a
// 1-connection address both downloading, each fair limiter starting at the
// total, so the secret's bucket splits 4:1 by connection. Neither is ever held
// at its own fair limiter -- each sits above what it gets -- so only the waits
// at the secret's bucket say that both want more. With them in the duty both
// are throttled and the level is half; without them the 4:1 split reports
// itself as two satisfied demands that sum to the total, and stays. Per bucket:
// the duty of each is its own tracker.
func TestFairShareFourConnectionsAgainstOneConverge(t *testing.T) {
	t.Parallel()

	const half = fairTestTotal / 2

	for b := range fairBucketCount {
		t.Run(fairBucketName(b), func(t *testing.T) {
			t.Parallel()

			sim := newFairSim(t, b)
			four := sim.join(t, "203.0.113.4", true, 4, sim.init(0))
			one := sim.join(t, "198.51.100.1", true, 1, sim.init(0))

			sim.prime()
			require.EqualValues(t, fairTestTotal, fairRate(four.entry, b), "every fair limiter starts at the total")
			require.EqualValues(t, fairTestTotal, fairRate(one.entry, b))

			sim.step()
			require.Equal(t, []int64{4 * fairTestTotal / 5, fairTestTotal / 5}, sim.moved,
				"the secret's bucket splits per connection: 4:1")

			converged := -1

			for i := 1; i <= 3 && converged < 0; i++ {
				sim.step()

				if sim.moved[0] == half && sim.moved[1] == half {
					converged = i
				}
			}

			require.GreaterOrEqual(t, converged, 1, "4:1 must become 1:1 within three ticks, moved %v", sim.moved)

			for range 5 {
				sim.step()

				assert.Equal(t, []int64{half, half}, sim.moved, "and it stays 1:1")
				assert.EqualValues(t, half, fairRate(four.entry, b))
				assert.EqualValues(t, half, fairRate(one.entry, b))
			}
		})
	}
}

// Decision 6, the first review's case: an address held back by its own
// ceiling is not short of its share -- its waits there are not in its duty --
// so its demand is what it moves, and the rest goes to the address that can
// use it. Counting the ceiling's waits would halve the other's share for
// nothing.
func TestFairShareAnAddressHeldByItsCeilingReportsItsTrueDemand(t *testing.T) {
	t.Parallel()

	const ceiling = fairTestTotal / 5

	sim := newFairSim(t, fairDownBucket)
	held := sim.join(t, "203.0.113.1", true, 1, sim.init(ceiling))
	other := sim.join(t, "203.0.113.2", true, 1, sim.init(0))

	require.EqualValues(t, ceiling, held.entry.ceiling.bytesPerSecond())

	sim.prime()

	for range 4 {
		sim.step()
	}

	assert.EqualValues(t, fairTestTotal-ceiling, fairLevelOf(sim.table, "alice", fairDownBucket),
		"the held address demands its 200,000 and the other gets the rest")
	assert.EqualValues(t, fairTestTotal-ceiling, fairRate(other.entry, fairDownBucket))
	assert.Equal(t, []int64{ceiling, fairTestTotal - ceiling}, sim.moved)
	assert.False(t, fairStateOf(sim.table, held.entry, fairDownBucket).throttled, "a ceiling is not a fair throttle")
	assert.True(t, fairStateOf(sim.table, other.entry, fairDownBucket).throttled)
}

// A downloader that pauses -- still connected, nothing moving -- releases the
// other address at once, on the very next tick, not after its three ticks of
// hysteresis.
func TestFairShareAPausedDownloaderReleasesTheOtherAtOnce(t *testing.T) {
	t.Parallel()

	sim := newFairSim(t, fairDownBucket)
	pausing := sim.join(t, "203.0.113.1", true, 1, sim.init(0))
	other := sim.join(t, "203.0.113.2", true, 1, sim.init(0))

	sim.prime()
	sim.step()
	sim.step()

	require.Equal(t, []int64{fairTestTotal / 2, fairTestTotal / 2}, sim.moved)

	pausing.conns = 0

	sim.step()

	assert.EqualValues(t, fairTestTotal, fairRate(other.entry, fairDownBucket),
		"the paused address is released at once and the other gets everything")
	assert.False(t, fairStateOf(sim.table, pausing.entry, fairDownBucket).throttled)

	sim.step()
	assert.Equal(t, []int64{0, fairTestTotal}, sim.moved)
}

// A new address starts at the level the secret is at -- not at the total,
// which would hand it a burst of the whole limit -- and the others make room
// for it within two ticks.
func TestFairShareANewArrivalStartsAtTheLevel(t *testing.T) {
	t.Parallel()

	sim := newFairSim(t, fairDownBucket)
	first := sim.join(t, "203.0.113.1", true, 1, sim.init(0))
	second := sim.join(t, "203.0.113.2", true, 1, sim.init(0))

	sim.prime()
	sim.step()
	sim.step()

	require.EqualValues(t, fairTestTotal/2, fairRate(first.entry, fairDownBucket))

	arrival := sim.join(t, "203.0.113.3", true, 1, sim.init(0))
	assert.EqualValues(t, fairTestTotal/2, fairRate(arrival.entry, fairDownBucket),
		"a new address starts at the current level")

	third := int64(fairTestTotal / 3)

	for i := 1; i <= 2; i++ {
		sim.step()
	}

	for _, a := range []*fairSimAddr{first, second, arrival} {
		assert.EqualValues(t, third, fairRate(a.entry, fairDownBucket), "within two ticks everyone has a third")
	}
}

// An address that comes back within the retention window runs at the level
// the secret is at now, not at the rate it left at; while it was gone its
// limiter was left alone. And once everyone has gone the next tick sets the
// level back to the whole total, so the one who arrives alone gets it.
func TestFairShareAReturningAddressGetsTheCurrentLevel(t *testing.T) {
	t.Parallel()

	sim := newFairSim(t, fairDownBucket)
	first := sim.join(t, "203.0.113.1", true, 1, sim.init(0))
	leaving := sim.join(t, "203.0.113.2", true, 1, sim.init(0))

	sim.prime()
	sim.step()
	sim.step()

	require.EqualValues(t, fairTestTotal/2, fairRate(leaving.entry, fairDownBucket))

	sim.table.release(leaving.entry)
	leaving.conns = 0

	sim.join(t, "203.0.113.3", true, 1, sim.init(0))
	sim.join(t, "203.0.113.4", true, 1, sim.init(0))

	for range 3 {
		sim.step()
	}

	third := int64(fairTestTotal / 3)

	require.EqualValues(t, third, fairRate(first.entry, fairDownBucket))
	assert.EqualValues(t, fairTestTotal/2, fairRate(leaving.entry, fairDownBucket),
		"an entry with no live stream is left as it was")

	again := sim.table.acquire("alice", leaving.entry.key, true, sim.init(0))
	require.Same(t, leaving.entry, again)

	assert.EqualValues(t, third, fairRate(again, fairDownBucket), "it comes back at the current level")

	// Everyone leaves; the tick after that has nobody taking part, which is the
	// whole total, and the next address, alone, starts there.
	for _, entry := range sim.table.snapshot("alice") {
		for clientRefs(sim.table, entry) > 0 {
			sim.table.release(entry)
		}
	}

	for _, a := range sim.addrs {
		a.conns = 0
	}

	sim.step()

	alone := sim.table.acquire("alice", "203.0.113.9", true, sim.init(0))
	assert.EqualValues(t, fairTestTotal, fairRate(alone, fairDownBucket), "alone, it starts at the total")
}

// The tick measures every entry of the secret, a stream or not: what an
// address moved and waited in the second it left in is closed off by the next
// tick, so when it comes back its first tick measures only what it does then.
// Measured only while live, the left-over bytes and blocked time would land in
// that first tick and throttle an address that is barely moving.
func TestFairShareAReturningAddressStartsFromAClosedWindow(t *testing.T) {
	t.Parallel()

	table, clock := newTestClientTable(t)
	secret := fairSecret{name: "alice", totals: fairTotals{Down: fairTestTotal}}
	init := entryInit{FairTotals: secret.totals}

	busy := table.acquire("alice", "203.0.113.1", true, init)
	leaving := table.acquire("alice", "203.0.113.2", true, init)

	table.tick(clock.read(), secret)

	second := func(leavingMoves int64, leavingBlocked bool) {
		start := clock.read()
		busy.bytesOut.Add(fairRate(busy, fairDownBucket))
		fairBlockTick(busy, fairDownBucket, start)

		leaving.bytesOut.Add(leavingMoves)

		if leavingBlocked {
			leaving.blockedDown.enter(start)
			leaving.blockedDown.leave(start.Add(900 * time.Millisecond))
		}

		clock.advance(fairTestTick)
	}

	// Its last second: it moves and waits, and its stream closes before the
	// tick.
	second(fairTestTotal/2, true)
	table.release(leaving)
	table.tick(clock.read(), secret)

	for range 3 {
		second(0, false)
		table.tick(clock.read(), secret)
	}

	// Back, moving a little and never waiting.
	table.acquire("alice", leaving.key, true, init)
	second(10_000, false)
	table.tick(clock.read(), secret)

	assert.False(t, fairStateOf(table, leaving, fairDownBucket).throttled, "nothing from before it left is measured")
	assert.EqualValues(t, fairTestTotal-10_000, fairLevelOf(table, "alice", fairDownBucket),
		"its demand is the 10,000 it moved now")
}

// The tick sets the entries a stream holds when it publishes, not when it
// gathered: an address that arrived while the tick was deciding was made at
// the level of a tick ago, and gets the new one with everybody else.
func TestFairShareATickSetsAnAddressThatArrivedWhileItDecided(t *testing.T) {
	t.Parallel()

	table, clock := newTestClientTable(t)
	secret := fairSecret{name: "alice", totals: fairTotals{Down: fairTestTotal}}
	init := entryInit{FairTotals: secret.totals}

	first := table.acquire("alice", "203.0.113.1", true, init)
	second := table.acquire("alice", "203.0.113.2", true, init)

	table.tick(clock.read(), secret)

	start := clock.read()

	for _, e := range []*clientEntry{first, second} {
		e.bytesOut.Add(fairTestTotal / 2)
		fairBlockTick(e, fairDownBucket, start)
	}

	var arrival *clientEntry

	table.beforeFairPublish = func() {
		table.beforeFairPublish = nil

		arrival = table.acquire("alice", "203.0.113.3", true, init)
	}

	clock.advance(fairTestTick)
	table.tick(clock.read(), secret)

	require.NotNil(t, arrival)
	assert.EqualValues(t, fairTestTotal/2, fairRate(first, fairDownBucket))
	assert.EqualValues(t, fairTestTotal/2, fairRate(arrival, fairDownBucket),
		"made at the old level while the tick decided, set to the new one when it published")
}

// Every entry with a live stream is set to the level, a quiet one too, so an
// address that wakes up after ten quiet seconds does not run at a stale,
// possibly tiny, rate for a tick. It is not a participant: what it does not ask
// for goes to the others.
func TestFairShareSetsAnIdleConnectedEntryToTheLevel(t *testing.T) {
	t.Parallel()

	sim := newFairSim(t, fairDownBucket)
	sim.join(t, "203.0.113.1", true, 1, sim.init(0))
	sim.join(t, "203.0.113.2", true, 1, sim.init(0))
	idle := sim.join(t, "203.0.113.3", true, 1, sim.init(0))
	idle.conns = 0

	sim.prime()
	require.EqualValues(t, fairTestTotal, fairRate(idle.entry, fairDownBucket))

	sim.step()

	assert.EqualValues(t, fairTestTotal/2, fairRate(idle.entry, fairDownBucket), "connected and quiet: set to the level")
	assert.False(t, fairStateOf(sim.table, idle.entry, fairDownBucket).participant, "but not a participant")
	assert.EqualValues(t, fairTestTotal/2, fairLevelOf(sim.table, "alice", fairDownBucket),
		"the two busy ones share the total")
}

// An address takes part while it was active in the last ten seconds: it moved
// a byte, or one of its streams was blocked waiting to. That is measured tick
// by tick from the bytes and the blocked tracker, not from lastSeen, which a
// connection opening or closing stamps too.
//
// An address stuck in one long wait -- a write held for longer than ten
// seconds at a small level -- moves nothing, and is asking for its share all
// along: it stays a participant, throttled. An address that moved one burst
// and then neither moved nor waited takes part for ten seconds after it and
// then not, even though a stream of it connected a moment before; still
// connected, it is still set to the level.
func TestFairShareTenQuietSecondsEndAParticipation(t *testing.T) {
	t.Parallel()

	table, clock := newTestClientTable(t)
	secret := fairSecret{name: "alice", totals: fairTotals{Down: fairTestTotal}}
	init := entryInit{FairTotals: secret.totals}

	busy := table.acquire("alice", "203.0.113.1", true, init)
	stuck := table.acquire("alice", "203.0.113.2", true, init)
	quiet := table.acquire("alice", "203.0.113.3", true, init)

	table.tick(clock.read(), secret)

	// The first second: stuck and quiet move a little, and stuck enters a wait
	// that does not end.
	stuck.bytesOut.Add(1000)
	stuck.blockedDown.enter(clock.read())
	quiet.bytesOut.Add(1000)

	for tick := 1; tick <= 13; tick++ {
		start := clock.read()
		busy.bytesOut.Add(fairRate(busy, fairDownBucket))
		fairBlockTick(busy, fairDownBucket, start)

		if tick == 9 {
			// A second stream from the quiet address connects: its lastSeen is
			// now, and it has moved nothing and waited for nothing since the
			// first second.
			table.acquire("alice", quiet.key, true, init)
		}

		clock.advance(fairTestTick)
		table.tick(clock.read(), secret)

		stuckState := fairStateOf(table, stuck, fairDownBucket)
		assert.True(t, stuckState.participant, "tick %d: blocked all along, so asking", tick)
		assert.True(t, stuckState.throttled, "tick %d", tick)

		if tick >= 2 {
			assert.EqualValues(t, fairTestTotal/2, fairLevelOf(table, "alice", fairDownBucket),
				"tick %d: the busy one and the stuck one share the total", tick)
		}

		quietState := fairStateOf(table, quiet, fairDownBucket)

		if tick <= 10 {
			assert.True(t, quietState.participant, "tick %d: its byte %d s ago", tick, tick-1)
		} else {
			assert.False(t, quietState.participant, "tick %d: neither a byte nor a wait for ten seconds", tick)
			assert.EqualValues(t, fairTestTotal/2, fairRate(quiet, fairDownBucket),
				"tick %d: still connected, so still set to the level", tick)
		}
	}
}

// The rest entry -- every unkeyed client and every address past a cap -- holds
// one share like any address, however many clients it stands for, and no
// address's ceiling.
func TestFairShareTheRestEntryIsOneParticipantWithoutACeiling(t *testing.T) {
	t.Parallel()

	sim := newFairSim(t, fairDownBucket)
	init := sim.init(4 * fairTestTotal)

	keyed := sim.join(t, "203.0.113.1", true, 1, init)
	rest := sim.join(t, "", false, 4, init)

	require.True(t, rest.entry.rest)
	assert.False(t, rest.entry.ceiling.installed(), "the rest entry carries no ceiling")
	assert.True(t, keyed.entry.ceiling.installed())

	sim.prime()

	for range 3 {
		sim.step()
	}

	assert.True(t, fairStateOf(sim.table, rest.entry, fairDownBucket).participant)
	assert.EqualValues(t, fairTestTotal/2, fairLevelOf(sim.table, "alice", fairDownBucket), "one share each")
	assert.EqualValues(t, fairTestTotal/2, fairRate(rest.entry, fairDownBucket))
	assert.Equal(t, []int64{fairTestTotal / 2, fairTestTotal / 2}, sim.moved)
}

// The duty is a fraction of time, so it does not depend on the rate: at 100
// times the rate every wait is a hundredth as long -- well under a millisecond
// for a 16 KiB write at 90 MB/s -- and the address is just as held back. The
// same traffic at 1 MB/s and at 100 MB/s ends in the same decisions.
func TestFairShareDutyIsRateIndependent(t *testing.T) {
	t.Parallel()

	const chunk = 16 << 10

	run := func(total int64) ([]float64, []bool) {
		table, clock := newTestClientTable(t)
		secret := fairSecret{name: "alice", totals: fairTotals{Down: total}}
		init := entryInit{FairTotals: secret.totals}

		busy := table.acquire("alice", "203.0.113.1", true, init)
		quiet := table.acquire("alice", "203.0.113.2", true, init)

		table.tick(clock.read(), secret)

		var (
			levels    []float64
			throttled []bool
		)

		for range 5 {
			start := clock.read()

			// The quiet address moves a tenth of the total and never waits; the
			// busy one gets the rest of the secret's bucket, up to its share, a
			// chunk at a time, each chunk four fifths waiting.
			rate := min(fairRate(busy, fairDownBucket), total-total/10)
			quiet.bytesOut.Add(total / 10)
			busy.bytesOut.Add(rate)

			cycle := time.Duration(int64(time.Second) * chunk / rate)
			for at := time.Duration(0); at+cycle <= fairTestTick; at += cycle {
				busy.blockedDown.enter(start.Add(at))
				busy.blockedDown.leave(start.Add(at + cycle*4/5))
			}

			clock.advance(fairTestTick)
			table.tick(clock.read(), secret)

			levels = append(levels, float64(fairLevelOf(table, "alice", fairDownBucket))/float64(total))
			throttled = append(throttled, fairStateOf(table, busy, fairDownBucket).throttled)
		}

		return levels, throttled
	}

	slowLevels, slowThrottled := run(1_000_000)
	fastLevels, fastThrottled := run(100_000_000)

	assert.Equal(t, []float64{0.9, 0.9, 0.9, 0.9, 0.9}, slowLevels, "the busy one gets what the quiet one leaves")
	assert.Equal(t, slowLevels, fastLevels, "the same at a hundred times the rate")
	assert.Equal(t, []bool{true, true, true, true, true}, slowThrottled)
	assert.Equal(t, slowThrottled, fastThrottled)
}

// Each bucket is measured from its own bytes: speed-up from what the address
// sent (a read, bytesIn), speed-down from what it received (a write, bytesOut),
// and speed from both. The quiet address here sends a tenth of the total and
// receives a fifth, and the busy one gets what is left of that bucket.
func TestFairShareMeasuresEachBucketByItsOwnBytes(t *testing.T) {
	t.Parallel()

	for b, want := range map[fairBucket]int64{
		fairSpeedBucket: fairTestTotal - fairTestTotal/10 - fairTestTotal/5,
		fairUpBucket:    fairTestTotal - fairTestTotal/10,
		fairDownBucket:  fairTestTotal - fairTestTotal/5,
	} {
		t.Run(fairBucketName(b), func(t *testing.T) {
			t.Parallel()

			table, clock := newTestClientTable(t)
			secret := fairSecret{name: "alice", totals: fairTotalsOf(b, fairTestTotal)}
			init := entryInit{FairTotals: secret.totals}

			busy := table.acquire("alice", "203.0.113.1", true, init)
			quiet := table.acquire("alice", "203.0.113.2", true, init)

			table.tick(clock.read(), secret)

			start := clock.read()
			quiet.bytesIn.Add(fairTestTotal / 10)
			quiet.bytesOut.Add(fairTestTotal / 5)
			fairCount(busy, b, fairTestTotal/2)
			fairBlockTick(busy, b, start)

			clock.advance(fairTestTick)
			table.tick(clock.read(), secret)

			assert.EqualValues(t, want, fairLevelOf(table, "alice", b))
			assert.EqualValues(t, want, fairRate(busy, b))
			assert.False(t, fairStateOf(table, quiet, b).throttled)
		})
	}
}

// The first tick of a secret has nothing to measure from and only takes a
// baseline; so does a tick whose instant is not after the last one's, a clock
// put back. Neither sets a rate.
func TestFairShareTickBaselinesBeforeItDecides(t *testing.T) {
	t.Parallel()

	table, clock := newTestClientTable(t)
	secret := fairSecret{name: "alice", totals: fairTotals{Down: fairTestTotal}}
	init := entryInit{FairTotals: secret.totals}

	first := table.acquire("alice", "203.0.113.1", true, init)
	second := table.acquire("alice", "203.0.113.2", true, init)

	busySecond := func() {
		start := clock.read()

		for _, e := range []*clientEntry{first, second} {
			e.bytesOut.Add(fairTestTotal / 2)
			fairBlockTick(e, fairDownBucket, start)
		}

		clock.advance(fairTestTick)
	}

	busySecond()
	table.tick(clock.read(), secret)

	assert.EqualValues(t, fairTestTotal, fairRate(first, fairDownBucket), "the first tick sets nothing")
	assert.Zero(t, fairLevelOf(table, "alice", fairDownBucket), "and knows no level")
	assert.False(t, fairStateOf(table, first, fairDownBucket).throttled)

	busySecond()
	table.tick(clock.read(), secret)

	require.EqualValues(t, fairTestTotal/2, fairRate(first, fairDownBucket), "the second decides")
	require.EqualValues(t, fairTestTotal/2, fairRate(second, fairDownBucket))

	// The clock is put back a second, and in that second the first address
	// stopped. A tick at an instant that is not after the last decides nothing.
	clock.advance(-2 * fairTestTick)
	second.bytesOut.Add(fairTestTotal / 2)
	fairBlockTick(second, fairDownBucket, clock.read())
	clock.advance(fairTestTick)
	table.tick(clock.read(), secret)

	assert.EqualValues(t, fairTestTotal/2, fairRate(second, fairDownBucket), "a tick back in time decides nothing")
	assert.EqualValues(t, fairTestTotal/2, fairLevelOf(table, "alice", fairDownBucket))
	assert.Equal(t, fairHoldTicks, fairStateOf(table, first, fairDownBucket).hold)
}

// A baseline tick keeps the counts it took. Here the first second is busy and
// the second nearly idle for one address: measured from the baseline, that
// address moved 10,000 in the second second and the other gets the rest;
// measured from nothing, its first second would count too and it would look
// like it wanted half the total.
func TestFairShareABaselineTickKeepsItsCounts(t *testing.T) {
	t.Parallel()

	table, clock := newTestClientTable(t)
	secret := fairSecret{name: "alice", totals: fairTotals{Down: fairTestTotal}}
	init := entryInit{FairTotals: secret.totals}

	slowing := table.acquire("alice", "203.0.113.1", true, init)
	busy := table.acquire("alice", "203.0.113.2", true, init)

	start := clock.read()

	for _, e := range []*clientEntry{slowing, busy} {
		e.bytesOut.Add(fairTestTotal / 2)
		fairBlockTick(e, fairDownBucket, start)
	}

	clock.advance(fairTestTick)
	table.tick(clock.read(), secret)
	require.Zero(t, fairLevelOf(table, "alice", fairDownBucket), "the first tick is the baseline")

	start = clock.read()
	slowing.bytesOut.Add(10_000)
	busy.bytesOut.Add(fairTestTotal / 2)
	fairBlockTick(busy, fairDownBucket, start)

	clock.advance(fairTestTick)
	table.tick(clock.read(), secret)

	assert.EqualValues(t, fairTestTotal-10_000, fairLevelOf(table, "alice", fairDownBucket),
		"the slowing address asks for the 10,000 it moved since the baseline")
	assert.False(t, fairStateOf(table, slowing, fairDownBucket).throttled)
}

// A tick that comes late -- the ticker held up, or the tick after one a reload
// discarded -- measures over its own length: the same bytes over two seconds
// are half the rate, and the same blocked time half the duty.
func TestFairShareMeasuresALongTickOverItsLength(t *testing.T) {
	t.Parallel()

	table, clock := newTestClientTable(t)
	secret := fairSecret{name: "alice", totals: fairTotals{Down: fairTestTotal}}
	init := entryInit{FairTotals: secret.totals}

	quiet := table.acquire("alice", "203.0.113.1", true, init)
	busy := table.acquire("alice", "203.0.113.2", true, init)

	table.tick(clock.read(), secret)

	// Two seconds: the quiet address moves 400,000 and waits 400 ms -- a duty
	// of a fifth, which over one second would have been two fifths, and
	// throttled. The busy one waits throughout.
	start := clock.read()
	quiet.bytesOut.Add(400_000)
	quiet.blockedDown.enter(start)
	quiet.blockedDown.leave(start.Add(400 * time.Millisecond))
	busy.bytesOut.Add(fairTestTotal)
	busy.blockedDown.enter(start)
	busy.blockedDown.leave(start.Add(2 * fairTestTick))

	clock.advance(2 * fairTestTick)
	table.tick(clock.read(), secret)

	assert.False(t, fairStateOf(table, quiet, fairDownBucket).throttled, "a duty of a fifth")
	assert.EqualValues(t, fairTestTotal-200_000, fairLevelOf(table, "alice", fairDownBucket),
		"400,000 over two seconds is 200,000 a second, and the busy one gets the rest")
}

// The half-level release compares an address's rate with the level it ran at,
// not with the total: three addresses at a third each, one of which has a tick
// of little waiting while it still moves its third. A third is at least half
// of a third, so its throttle holds; it is below half the total, which would
// have released it.
func TestFairShareTheHalfLevelRuleUsesTheLevelItRanAt(t *testing.T) {
	t.Parallel()

	table, clock := newTestClientTable(t)
	secret := fairSecret{name: "alice", totals: fairTotals{Down: fairTestTotal}}
	init := entryInit{FairTotals: secret.totals}

	entries := []*clientEntry{
		table.acquire("alice", "203.0.113.1", true, init),
		table.acquire("alice", "203.0.113.2", true, init),
		table.acquire("alice", "203.0.113.3", true, init),
	}

	table.tick(clock.read(), secret)

	third := int64(fairTestTotal / 3)

	second := func(steady bool) {
		start := clock.read()

		for i, e := range entries {
			e.bytesOut.Add(third)

			if i == 0 && steady {
				e.blockedDown.enter(start)
				e.blockedDown.leave(start.Add(100 * time.Millisecond))

				continue
			}

			fairBlockTick(e, fairDownBucket, start)
		}

		clock.advance(fairTestTick)
		table.tick(clock.read(), secret)
	}

	second(false)
	require.EqualValues(t, third, fairLevelOf(table, "alice", fairDownBucket))
	require.Equal(t, fairHoldTicks, fairStateOf(table, entries[0], fairDownBucket).hold)

	second(true)

	state := fairStateOf(table, entries[0], fairDownBucket)
	assert.True(t, state.throttled, "moving the level it ran at, it is still held")
	assert.Equal(t, fairHoldTicks-1, state.hold)
}

// A reload that moves a secret's fair limiters while a tick is computing makes
// that tick's work stale: it was measured against limiters and states the
// reload has replaced, so the tick publishes nothing -- no level, no state, no
// rate -- and the next tick starts from what the reload left. A secret removed
// and made again meanwhile is not the one the tick measured either.
func TestFairShareATickDiscardsWorkAReloadOvertook(t *testing.T) {
	t.Parallel()

	t.Run("reload", func(t *testing.T) {
		t.Parallel()

		table, clock := newTestClientTable(t)
		secret := fairSecret{name: "alice", totals: fairTotals{Down: fairTestTotal}}
		init := entryInit{FairTotals: secret.totals}

		first := table.acquire("alice", "203.0.113.1", true, init)
		second := table.acquire("alice", "203.0.113.2", true, init)

		table.tick(clock.read(), secret)

		start := clock.read()

		for _, e := range []*clientEntry{first, second} {
			e.bytesOut.Add(fairTestTotal / 2)
			fairBlockTick(e, fairDownBucket, start)
		}

		table.beforeFairPublish = func() {
			table.beforeFairPublish = nil

			table.applyFair(func(string) (fairTotals, bool) { return fairTotals{}, true })
			table.applyFair(func(string) (fairTotals, bool) { return secret.totals, true })
		}

		clock.advance(fairTestTick)
		table.tick(clock.read(), secret)

		assert.Zero(t, fairLevelOf(table, "alice", fairDownBucket), "no level is published")
		assert.EqualValues(t, fairTestTotal, fairRate(first, fairDownBucket), "the reload's limiter runs at its own rate")
		assert.Equal(t, fairBucketState{}, fairStateOf(table, first, fairDownBucket), "the reload's state stands")
	})

	t.Run("removal", func(t *testing.T) {
		t.Parallel()

		table, clock := newTestClientTable(t)
		secret := fairSecret{name: "alice", totals: fairTotals{Down: fairTestTotal}}
		init := entryInit{FairTotals: secret.totals}

		old := table.acquire("alice", "203.0.113.1", true, init)

		table.tick(clock.read(), secret)
		old.bytesOut.Add(fairTestTotal)
		fairBlockTick(old, fairDownBucket, clock.read())

		var fresh *clientEntry

		table.beforeFairPublish = func() {
			table.beforeFairPublish = nil

			table.dropSecret("alice")
			fresh = table.acquire("alice", "203.0.113.2", true, init)
		}

		clock.advance(fairTestTick)
		table.tick(clock.read(), secret)

		require.NotNil(t, fresh)
		assert.Zero(t, fairLevelOf(table, "alice", fairDownBucket))
		assert.Equal(t, fairEntryState{}, func() fairEntryState {
			table.mu.Lock()
			defer table.mu.Unlock()

			return fresh.fair
		}(), "nothing the tick measured lands on the secret made since")

		table.mu.Lock()
		lastTick := table.secrets["alice"].fair.lastTick
		table.mu.Unlock()

		assert.True(t, lastTick.IsZero(), "the new secret's first tick is still to come")
	})
}

// Rates move only through the table's setRate, which never makes a limiter:
// an address with no fair share stays unlimited, and only applyFair and a new
// entry's own init install one. Nor is a rate ever zero, which would read as
// unlimited.
func TestFairShareSetRateNeverCreatesALimiter(t *testing.T) {
	t.Parallel()

	table, clock := newTestClientTable(t)

	plain := table.acquire("alice", "203.0.113.1", true, entryInit{})

	for b := range fairBucketCount {
		table.setRate(plain, b, 5000)
		assert.False(t, plain.fairLimiter(b).installed(), fairBucketName(b))
	}

	// A tick over a secret whose entries lack the limiter it divides -- the
	// invariant broken -- re-rates nothing into existence either.
	secret := fairSecret{name: "alice", totals: fairTotals{Speed: fairTestTotal}}
	table.tick(clock.read(), secret)
	clock.advance(fairTestTick)
	table.tick(clock.read(), secret)

	assert.False(t, plain.fairSpeed.installed(), "the tick does not install what applyFair did not")

	shared := table.acquire("alice", "203.0.113.2", true, entryInit{FairTotals: fairTotals{Up: fairTestTotal}})

	table.setRate(shared, fairUpBucket, 0)
	assert.EqualValues(t, 1, fairRate(shared, fairUpBucket), "never zero")

	table.setRate(shared, fairUpBucket, 5000)
	assert.EqualValues(t, 5000, fairRate(shared, fairUpBucket))
}

// No table is "off" for fair share too, and a table asked about a secret it
// holds nothing for does nothing.
func TestNilClientTableHasNoFairShare(t *testing.T) {
	t.Parallel()

	var table *clientTable

	secret := fairSecret{name: "alice", totals: fairTotals{Speed: fairTestTotal}}

	table.tick(time.Now(), secret)
	table.applyFair(func(string) (fairTotals, bool) { return fairTotals{Speed: fairTestTotal}, true })
	table.setRate(&clientEntry{}, fairSpeedBucket, 1)
	table.setRate(nil, fairSpeedBucket, 1)

	live, clock := newTestClientTable(t)
	live.tick(clock.read(), secret)
	live.tick(clock.read(), fairSecret{name: "alice"})
	live.setRate(nil, fairUpBucket, 1)
	live.applyFair(func(string) (fairTotals, bool) { return fairTotals{}, false })
}

// The lock order is reloadMu, liveMu, tableMu: the fair-share tick takes the
// table's lock alone, like the sweep. This holds liveMu and requires two ticks
// -- a baseline and a decision -- to finish anyway. (The table holds no route to
// liveMu, so the ticker that would take it is 12b's; this pins the table half.)
func TestTheFairTickNeverWaitsForLiveMu(t *testing.T) {
	t.Parallel()

	probe := newClientTableProbe(t, true)
	p := probe.proxy

	require.Equal(t, DenyNone, p.tryRegisterConn(probe.stream(t, tcpFrom("203.0.113.9", 50001), 0)))
	require.Len(t, p.clients.snapshot("alice"), 1)

	secret := fairSecret{name: "alice", totals: fairTotals{Speed: 1 << 20}}

	p.liveMu.Lock()

	done := make(chan struct{})

	go func() {
		defer close(done)

		now := time.Now()
		p.clients.tick(now, secret)
		p.clients.tick(now.Add(fairTestTick), secret)
	}()

	finished := govAwait(done, 2*time.Second)

	p.liveMu.Unlock()
	<-done

	require.True(t, finished, "the fair-share tick must not wait for liveMu")
}

// ---- applyFair: the fair limiters follow the secret's totals ----------------

// The invariant fair share's duty rests on, through every change a reload can
// make: each fair limiter is installed exactly when its total is set, on every
// entry of the secret -- one a stream holds, one none does, the rest entry, and
// ones made before fair share was on -- and removed from all of them when it is
// not. Another secret is untouched.
func TestApplyFairKeepsTheInvariantOnEveryEntry(t *testing.T) {
	t.Parallel()

	table, _ := newTestClientTable(t)

	before := entryInit{CeilingRate: 1 << 20}

	table.acquire("alice", "203.0.113.1", true, before)

	idle := table.acquire("alice", "203.0.113.2", true, before)
	table.release(idle)

	rest := table.acquire("alice", "", false, before)
	require.True(t, rest.rest)

	table.acquire("bob", "203.0.113.1", true, before)

	check := func(step string, totals fairTotals) {
		t.Helper()

		require.True(t, assertFairInvariant(t, table, "alice", totals), step)
		require.True(t, assertFairInvariant(t, table, "bob", fairTotals{}), "%s: bob", step)
		assert.False(t, rest.ceiling.installed(), "%s: the rest entry never gets a ceiling", step)
	}

	apply := func(totals fairTotals) {
		table.applyFair(func(name string) (fairTotals, bool) {
			if name == "alice" {
				return totals, true
			}

			return fairTotals{}, true
		})
	}

	check("creation", fairTotals{})

	on := fairTotals{Speed: 4 << 20}
	apply(on)
	check("fair share on", on)

	table.acquire("alice", "203.0.113.3", true, entryInit{FairTotals: on})
	check("an entry made after", on)

	withUp := fairTotals{Speed: 4 << 20, Up: 1 << 20}
	apply(withUp)
	check("speed-up added", withUp)

	resized := fairTotals{Speed: 64 << 20, Up: 1 << 20}
	apply(resized)
	check("speed raised past a burst bound", resized)

	upOnly := fairTotals{Up: 1 << 20}
	apply(upOnly)
	check("speed removed", upOnly)

	apply(fairTotals{})
	check("fair share off", fairTotals{})
}

// A tracker whose fair limiter is installed, or installed again, starts empty:
// time it gathered in an earlier fair period -- a wait at a share that was then
// taken away -- would land in the first tick and could start a hysteresis
// nobody earned. A limiter a reload keeps keeps its tracker as it is.
func TestApplyFairResetsTheTrackerOfAnInstalledLimiter(t *testing.T) {
	t.Parallel()

	table, clock := newTestClientTable(t)

	speedOnly := fairTotals{Speed: fairTestTotal}
	entry := table.acquire("alice", "203.0.113.1", true, entryInit{FairTotals: speedOnly})

	start := clock.read()
	entry.blockedUp.enter(start)
	entry.blockedUp.leave(start.Add(800 * time.Millisecond))
	entry.blockedSpeed.enter(start)
	entry.blockedSpeed.leave(start.Add(300 * time.Millisecond))

	table.mu.Lock()
	entry.fair.buckets[fairUpBucket].hold = fairHoldTicks
	table.mu.Unlock()

	clock.advance(fairTestTick)

	table.applyFair(func(string) (fairTotals, bool) {
		return fairTotals{Speed: fairTestTotal, Up: fairTestTotal}, true
	})

	clock.advance(fairTestTick)

	assert.Zero(t, entry.blockedUp.snapshot(clock.read()), "the earlier period's blocked time is gone")
	assert.Zero(t, fairStateOf(table, entry, fairUpBucket).hold, "and so is its hysteresis")
	assert.Equal(t, 300*time.Millisecond, entry.blockedSpeed.snapshot(clock.read()),
		"a share the reload kept keeps what it has measured")
}

// A level belongs to the total it was computed for. A reload that changes
// nothing hands nobody a fresh bucket and keeps the level; one that changes a
// total forgets it, and the entries run at the new total until the next tick
// measures again.
func TestApplyFairKeepsTheLevelOnlyForTheSameTotal(t *testing.T) {
	t.Parallel()

	sim := newFairSim(t, fairDownBucket)
	first := sim.join(t, "203.0.113.1", true, 1, sim.init(0))
	second := sim.join(t, "203.0.113.2", true, 1, sim.init(0))

	sim.prime()
	sim.step()

	require.EqualValues(t, fairTestTotal/2, fairLevelOf(sim.table, "alice", fairDownBucket))

	object := first.entry.fairDown.limiter.Load()
	lastTick := func() time.Time {
		sim.table.mu.Lock()
		defer sim.table.mu.Unlock()

		return sim.table.secrets["alice"].fair.lastTick
	}
	ticked := lastTick()

	sim.table.applyFair(func(string) (fairTotals, bool) { return sim.secret.totals, true })

	assert.Same(t, object, first.entry.fairDown.limiter.Load(), "the same limiter: no fresh bucket")
	assert.EqualValues(t, fairTestTotal/2, fairRate(first.entry, fairDownBucket))
	assert.EqualValues(t, fairTestTotal/2, fairLevelOf(sim.table, "alice", fairDownBucket))
	assert.Equal(t, ticked, lastTick(), "and no baseline tick: nothing changed")

	raised := fairTotals{Down: 2 * fairTestTotal}
	sim.table.applyFair(func(string) (fairTotals, bool) { return raised, true })

	assert.Zero(t, fairLevelOf(sim.table, "alice", fairDownBucket), "a new total has no level yet")
	assert.True(t, lastTick().IsZero(), "and the next tick takes a baseline for the new limiters")

	for _, e := range []*clientEntry{first.entry, second.entry} {
		assert.EqualValues(t, 2*fairTestTotal, fairRate(e, fairDownBucket))
		assert.Equal(t, fairBurst(2*fairTestTotal), installedLimiter(t, &e.fairDown).Burst())
	}
}

// Fair share turned off for ten seconds and on again: nothing ticked the secret
// in between, so the last tick is ten seconds old, and a tick measured across
// that gap would see an eleven-second average -- every address moving half the
// total, blocked a tenth of the time -- and hand both the whole total. The
// first tick after the reload only takes a baseline, and the one after it
// already divides the total by what the new limiters ran.
func TestApplyFairStartsTheNextTickFromABaseline(t *testing.T) {
	t.Parallel()

	table, clock := newTestClientTable(t)
	on := fairTotals{Down: fairTestTotal}
	secret := fairSecret{name: "alice", totals: on}

	first := table.acquire("alice", "203.0.113.1", true, entryInit{FairTotals: on})
	second := table.acquire("alice", "203.0.113.2", true, entryInit{FairTotals: on})

	busySecond := func(tracked bool) {
		start := clock.read()

		for _, e := range []*clientEntry{first, second} {
			e.bytesOut.Add(fairTestTotal / 2)

			if tracked {
				fairBlockTick(e, fairDownBucket, start)
			}
		}

		clock.advance(fairTestTick)
	}

	apply := func(totals fairTotals) {
		table.applyFair(func(string) (fairTotals, bool) { return totals, true })
	}

	table.tick(clock.read(), secret)
	busySecond(true)
	table.tick(clock.read(), secret)
	require.EqualValues(t, fairTestTotal/2, fairLevelOf(table, "alice", fairDownBucket))

	// Off: nothing brackets the waits and nothing ticks, for ten seconds.
	apply(fairTotals{})

	for range 10 {
		busySecond(false)
	}

	apply(on)

	busySecond(true)
	table.tick(clock.read(), secret)

	assert.Zero(t, fairLevelOf(table, "alice", fairDownBucket), "the first tick after the reload only takes a baseline")
	assert.False(t, fairStateOf(table, first, fairDownBucket).throttled)
	assert.EqualValues(t, fairTestTotal, fairRate(first, fairDownBucket), "and sets nothing: the new limiter runs at the total")

	busySecond(true)
	table.tick(clock.read(), secret)

	assert.EqualValues(t, fairTestTotal/2, fairLevelOf(table, "alice", fairDownBucket), "the next one divides the total")
	assert.True(t, fairStateOf(table, first, fairDownBucket).throttled)
	assert.True(t, fairStateOf(table, second, fairDownBucket).throttled)
	assert.EqualValues(t, fairTestTotal/2, fairRate(second, fairDownBucket))
}

// A secret the reload drops is left alone: the drop that follows forgets it
// and closes its streams, and lifting its limiters first would let those
// streams run unheld in between.
func TestApplyFairLeavesADroppedSecretToTheDrop(t *testing.T) {
	t.Parallel()

	table, _ := newTestClientTable(t)

	totals := fairTotals{Speed: fairTestTotal}
	entry := table.acquire("alice", "203.0.113.1", true, entryInit{FairTotals: totals})

	table.applyFair(func(string) (fairTotals, bool) { return fairTotals{}, false })

	assert.True(t, assertFairInvariant(t, table, "alice", totals))
	assert.EqualValues(t, fairTestTotal, fairRate(entry, fairSpeedBucket))
}
