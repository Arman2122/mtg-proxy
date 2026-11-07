package mtglib

import (
	"container/heap"
	"fmt"
	"math"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/time/rate"
)

// Fair share against a model of the whole data path, synthetically: no
// sockets, one fake clock, deterministic.
//
// What is real: the table and its tick, acquire, release and applyFair; every
// address's limiters, which the tick re-rates; the blocked trackers; and the
// user's buckets, rate.Limiters made as speedLimiter.set makes them, so the
// secret's bucket shares its tokens per connection exactly as the rate package
// does, burst and debt included. What is modelled is the relay around
// countingConn, as a discrete-event process: each stream has one piece in
// flight, cut as readAddress and writeAddress cut it, paid at each limiter in
// payAddress's order -- the ceiling, the combined and the direction's fair
// share, the user's combined and direction's bucket -- each wait as long as the
// limiter's reservation says, and bracketed by the trackers exactly as
// waitAddress and waitShared bracket them: never the ceiling, the user's
// bucket only behind a fair share of it.
//
// fair_share_test.go tests the decision rule by rule; this tests what those
// rules add up to: convergence, no flapping, no waste, no starvation.

// pathLinkRate is how fast a greedy client supplies bytes: far more than any
// limit here, so it always wants more than it gets.
const pathLinkRate = 1e9

// pathEvent is something that happens at an instant; seq orders events of one
// instant by when they were scheduled, so a run is deterministic.
type pathEvent struct {
	at  time.Time
	seq uint64
	run func()
}

type pathQueue []*pathEvent

func (q pathQueue) Len() int { return len(q) }

func (q pathQueue) Less(i, j int) bool {
	if !q[i].at.Equal(q[j].at) {
		return q[i].at.Before(q[j].at)
	}

	return q[i].seq < q[j].seq
}

func (q pathQueue) Swap(i, j int) { q[i], q[j] = q[j], q[i] }

func (q *pathQueue) Push(x any) { *q = append(*q, x.(*pathEvent)) }

func (q *pathQueue) Pop() any {
	old := *q
	last := old[len(old)-1]
	old[len(old)-1] = nil
	*q = old[:len(old)-1]

	return last
}

// pathStream is one connection: an upload or a download, greedy (demand
// +Inf) or a client asking for demand bytes a second, op bytes at a time.
type pathStream struct {
	up     bool
	demand float64
	op     int
	paused bool

	// gen tells a stream's current run from one a pause ended.
	gen int
}

// pathAddr is one address: its entry and streams, and what it moved since
// the last tick.
type pathAddr struct {
	entry   *clientEntry
	streams []*pathStream
	in, out int64
}

// pathRow is what one tick left: the level, and per address what it moved in
// the second before, its fair rate and the verdict.
type pathRow struct {
	level       int64
	moved       []int64
	rates       []int64
	throttled   []bool
	participant []bool
}

// pathStage is one wait of a piece: a limiter, nil for none, and the tracker
// that brackets it, nil for none.
type pathStage struct {
	limiter *rate.Limiter
	tracker *blockedTracker
}

type pathSim struct {
	t testing.TB

	now   time.Time
	seq   uint64
	queue pathQueue

	table  *clientTable
	totals fairTotals
	fairOn bool
	user   [fairBucketCount]*rate.Limiter

	// bucket is the one the rows record.
	bucket fairBucket

	addrs []*pathAddr
	rows  []pathRow

	// bracketUser is production: a wait at the user's bucket is bracketed
	// when the address has a fair share of it. False is a control run of the
	// model, the second review's lock-in: only the fair limiter's waits count.
	bracketUser bool
}

// pathGreedy is n streams that always want more; downloads unless up.
func pathGreedy(n int, up bool) []pathStream {
	out := make([]pathStream, n)
	for i := range out {
		out[i] = pathStream{up: up, demand: math.Inf(1)}
	}

	return out
}

// pathAsking is one download stream that asks for demand bytes a second.
func pathAsking(demand float64) []pathStream {
	return []pathStream{{demand: demand}}
}

// newPathSim is the secret "alice" with total in bucket b, fair share on, and
// its first tick due now. A benchmark drives it too (fair_share_bench_test.go).
func newPathSim(t testing.TB, b fairBucket, total int64) *pathSim {
	t.Helper()

	s := &pathSim{t: t, now: fakeAddrClockBase, bucket: b, fairOn: true, bracketUser: true}
	s.table = newClientTable(addrClock{now: func() time.Time { return s.now }})
	s.setTotal(b, total)
	s.at(s.now, s.tick)

	return s
}

func (s *pathSim) at(when time.Time, run func()) {
	s.seq++
	heap.Push(&s.queue, &pathEvent{at: when, seq: s.seq, run: run})
}

// setTotal sets the user's bucket b as speedLimiter.set does -- a new bucket
// full, an existing one re-rated in place -- and the total fair share divides.
func (s *pathSim) setTotal(b fairBucket, total int64) {
	switch b {
	case fairUpBucket:
		s.totals.Up = total
	case fairDownBucket:
		s.totals.Down = total
	default:
		s.totals.Speed = total
	}

	burst := int(min(total, maxSpeedBurst))

	if current := s.user[b]; current != nil {
		current.SetLimitAt(s.now, rate.Limit(total))
		current.SetBurstAt(s.now, burst)

		return
	}

	s.user[b] = rate.NewLimiter(rate.Limit(total), burst)
}

func (s *pathSim) secretTotals() fairTotals {
	if s.fairOn {
		return s.totals
	}

	return fairTotals{}
}

// reload is what a reload does to the table: applyFair with the totals now.
func (s *pathSim) reload() {
	s.table.applyFair(func(string) (fairTotals, bool) { return s.secretTotals(), true })
}

// join connects an address's streams, each holding its entry as admission
// would, and starts them a millisecond apart.
func (s *pathSim) join(key addressKey, keyed bool, ceiling int64, streams ...pathStream) *pathAddr {
	a := &pathAddr{}

	for i := range streams {
		st := &streams[i]

		st.op = DefaultBufferSize
		if !math.IsInf(st.demand, 1) {
			st.op = int(min(max(st.demand/5, 512), DefaultBufferSize))
		}

		entry := s.table.acquire("alice", key, keyed, entryInit{CeilingRate: ceiling, FairTotals: s.secretTotals()})
		require.NotNil(s.t, entry)

		a.entry = entry
		a.streams = append(a.streams, st)
		s.start(a, st, time.Duration(i)*time.Millisecond)
	}

	s.addrs = append(s.addrs, a)

	return a
}

func (s *pathSim) start(a *pathAddr, st *pathStream, after time.Duration) {
	st.paused = false
	st.gen++

	gen := st.gen
	s.at(s.now.Add(after), func() { s.op(a, st, st.op, gen) })
}

func (s *pathSim) pause(a *pathAddr) {
	for _, st := range a.streams {
		st.paused = true
		st.gen++
	}
}

func (s *pathSim) resume(a *pathAddr) {
	for i, st := range a.streams {
		s.start(a, st, time.Duration(i)*time.Millisecond)
	}
}

// op moves remaining bytes of one client operation a piece at a time, and
// then waits for the client's next one.
func (s *pathSim) op(a *pathAddr, st *pathStream, remaining, gen int) {
	if st.paused || gen != st.gen {
		return
	}

	if remaining <= 0 {
		supply := pathLinkRate
		if !math.IsInf(st.demand, 1) {
			supply = st.demand
		}

		s.at(s.now.Add(time.Duration(float64(st.op)/supply*float64(time.Second))), func() {
			s.op(a, st, st.op, gen)
		})

		return
	}

	e := a.entry
	direction := fairDownBucket

	if st.up {
		direction = fairUpBucket
	}

	piece := remaining

	for _, user := range []*rate.Limiter{s.user[fairSpeedBucket], s.user[direction]} {
		if user != nil {
			piece = clampChunk(piece, user.Burst())
		}
	}

	if st.up {
		if e.pacesUpload() {
			piece = e.cutUpload(piece)
		}

		// A read is paid for after the fact: counted, then held.
		e.bytesIn.Add(int64(piece))
		a.in += int64(piece)

		s.pay(piece, s.stages(e, direction), func() { s.op(a, st, remaining-piece, gen) })

		return
	}

	if e.pacesDownload() {
		piece = e.cutDownload(piece)
	}

	// A write is paid for in advance: held, then counted.
	s.pay(piece, s.stages(e, direction), func() {
		e.bytesOut.Add(int64(piece))
		a.out += int64(piece)
		s.op(a, st, remaining-piece, gen)
	})
}

// stages is payAddress for a piece in direction, or waitBoth for an entry
// with no limiter of its own in that direction.
func (s *pathSim) stages(e *clientEntry, direction fairBucket) []pathStage {
	paced := e.pacesDownload()
	if direction == fairUpBucket {
		paced = e.pacesUpload()
	}

	if !paced {
		return []pathStage{{s.user[fairSpeedBucket], nil}, {s.user[direction], nil}}
	}

	behind := func(b fairBucket) *blockedTracker {
		if s.bracketUser && e.fairLimiter(b).installed() {
			return e.fairBlocked(b)
		}

		return nil
	}

	return []pathStage{
		{e.ceiling.limiter.Load(), nil},
		{e.fairSpeed.limiter.Load(), &e.blockedSpeed},
		{e.fairLimiter(direction).limiter.Load(), e.fairBlocked(direction)},
		{s.user[fairSpeedBucket], behind(fairSpeedBucket)},
		{s.user[direction], behind(direction)},
	}
}

// pay waits for piece at each stage from the i-th on, and then calls done. A
// stage with no limiter is passed without a bracket, as waitAddress and
// waitShared pass one.
func (s *pathSim) pay(piece int, stages []pathStage, done func()) {
	for i, stage := range stages {
		if stage.limiter == nil {
			continue
		}

		if stage.tracker != nil {
			stage.tracker.enter(s.now)
		}

		reservation := stage.limiter.ReserveN(s.now, piece)
		require.True(s.t, reservation.OK(), "a piece of %d against a burst of %d", piece, stage.limiter.Burst())

		if delay := reservation.DelayFrom(s.now); delay > 0 {
			rest := stages[i+1:]

			s.at(s.now.Add(delay), func() {
				if stage.tracker != nil {
					stage.tracker.leave(s.now)
				}

				s.pay(piece, rest, done)
			})

			return
		}

		if stage.tracker != nil {
			stage.tracker.leave(s.now)
		}
	}

	done()
}

// tick is the fair-share tick, once a second, and a row of what it left.
func (s *pathSim) tick() {
	s.table.tick(s.now, fairSecret{name: "alice", totals: s.secretTotals()})

	row := pathRow{level: fairLevelOf(s.table, "alice", s.bucket)}

	for _, a := range s.addrs {
		state := fairStateOf(s.table, a.entry, s.bucket)

		row.moved = append(row.moved, fairBytes(s.bucket, a.in, a.out))
		row.rates = append(row.rates, fairRate(a.entry, s.bucket))
		row.throttled = append(row.throttled, state.throttled)
		row.participant = append(row.participant, state.participant)

		a.in, a.out = 0, 0
	}

	s.rows = append(s.rows, row)
	s.at(s.now.Add(time.Second), s.tick)
}

// run plays the model through n more ticks. Row i is the tick at second i,
// and what it moved is what moved in the second before.
func (s *pathSim) run(n int) {
	for target := len(s.rows) + n; len(s.rows) < target; {
		require.NotZero(s.t, s.queue.Len(), "the model ran out of events")

		event := heap.Pop(&s.queue).(*pathEvent)
		s.now = event.at
		event.run()
	}
}

// band requires address i to have moved within [lo, hi] at every tick in
// [from, to].
func (s *pathSim) band(from, to, i int, lo, hi int64, what string) {
	s.t.Helper()

	for tick := from; tick <= to; tick++ {
		moved := s.rows[tick].moved[i]
		assert.True(s.t, moved >= lo && moved <= hi, "%s: tick %d: address %d moved %d, outside [%d, %d]",
			what, tick, i, moved, lo, hi)
	}
}

// near is a band of ±percent around want.
func (s *pathSim) near(from, to, i int, want, percent int64, what string) {
	s.t.Helper()

	s.band(from, to, i, want*(100-percent)/100, want*(100+percent)/100, what)
}

// steady requires every address to keep its throttle verdict unchanged over
// [from, to] -- no flapping between +Inf and a finite demand -- to keep a fair
// rate above a byte a second, and the sum moved to be at least 95% of total:
// nothing wasted while somebody wants more.
func (s *pathSim) steady(from, to int, total int64) {
	s.t.Helper()

	for i := range s.addrs {
		flips := 0

		for tick := from + 1; tick <= to; tick++ {
			if s.rows[tick].throttled[i] != s.rows[tick-1].throttled[i] {
				flips++
			}

			if rate := s.rows[tick].rates[i]; rate != 0 {
				assert.Greater(s.t, rate, int64(1), "tick %d: address %d starved", tick, i)
			}
		}

		assert.Zero(s.t, flips, "address %d flapped over ticks %d-%d", i, from, to)
	}

	for tick := from; tick <= to; tick++ {
		var sum int64
		for _, moved := range s.rows[tick].moved {
			sum += moved
		}

		assert.GreaterOrEqual(s.t, sum, total*95/100, "tick %d: %d of %d moved", tick, sum, total)
	}
}

const pathTotal = int64(1_000_000)

// Review Focus 7 under the rate package's own dynamics, in the shape that
// locks in: four connections and one, already running 4:1 at the user's
// bucket when fair share is turned on, so both new fair limiters sit at the
// total above what each gets. The tick after the reload is a baseline; within
// five ticks of it the split is 1:1 and stays so, in every bucket. The control
// run is the model with the user bucket's waits taken out of the duty: the 4:1
// reports itself as two satisfied demands and stays.
func TestFairShareSimFourConnectionsAgainstOne(t *testing.T) {
	t.Parallel()

	run := func(t *testing.T, b fairBucket, bracketUser bool) *pathSim {
		t.Helper()

		s := newPathSim(t, b, pathTotal)
		s.bracketUser = bracketUser
		s.fairOn = false

		up := b == fairUpBucket
		s.join("203.0.113.4", true, 0, pathGreedy(4, up)...)
		s.join("198.51.100.1", true, 0, pathGreedy(1, up)...)

		s.run(6)
		s.near(3, 5, 0, 4*pathTotal/5, 5, "without fair share the user's bucket splits 4:1")

		s.fairOn = true
		s.reload()
		s.run(20)

		return s
	}

	for b := range fairBucketCount {
		t.Run(fairBucketName(b), func(t *testing.T) {
			t.Parallel()

			s := run(t, b, true)

			assert.Zero(t, s.rows[6].level, "the tick after the reload is a baseline")
			s.near(11, 25, 0, pathTotal/2, 5, "four connections at half")
			s.near(11, 25, 1, pathTotal/2, 5, "one connection at half")
			s.steady(11, 25, pathTotal)
		})
	}

	t.Run("control without the user bucket's waits", func(t *testing.T) {
		t.Parallel()

		s := run(t, fairDownBucket, false)

		s.near(11, 25, 0, 4*pathTotal/5, 5, "the 4:1 split locks in")
		s.near(11, 25, 1, pathTotal/5, 10, "the 4:1 split locks in")
	})
}

// Eight addresses, from a trickle to greedy: the five below the level get all
// they ask for, the one above it is capped at the level like the greedy ones,
// the total is used, and nobody flaps once settled.
func TestFairShareSimSpreadDemands(t *testing.T) {
	t.Parallel()

	s := newPathSim(t, fairDownBucket, pathTotal)

	demands := []float64{1_000, 5_000, 20_000, 50_000, 100_000, 300_000}
	for i, d := range demands {
		s.join(addressKey(fmt.Sprintf("203.0.113.%d", i+1)), true, 0, pathAsking(d)...)
	}

	s.join("198.51.100.1", true, 0, pathGreedy(1, false)...)
	s.join("198.51.100.2", true, 0, pathGreedy(2, false)...)

	s.run(41)

	level := waterLevel(pathTotal, []int64{1_000, 5_000, 20_000, 50_000, 100_000, 300_000, demandInfinite, demandInfinite})

	// One client operation wide for the small ones, a 16 KiB piece or two for
	// the rest.
	s.band(10, 40, 0, 512, 1_536, "1 KB/s met")
	s.band(10, 40, 1, 4_000, 6_000, "5 KB/s met")
	s.band(10, 40, 2, 16_000, 24_000, "20 KB/s met")
	s.band(10, 40, 3, 40_000, 60_000, "50 KB/s met")
	s.band(10, 40, 4, 81_000, 115_000, "100 KB/s met")
	s.band(10, 40, 5, level-35_000, level+20_000, "300 KB/s capped at the level")
	s.band(10, 40, 6, level-20_000, level+22_000, "greedy at the level")
	s.band(10, 40, 7, level-20_000, level+22_000, "greedy with two connections at the level")
	s.steady(10, 40, pathTotal)
}

// A downloader that pauses -- still connected -- hands its share to the other
// at once, and on resuming takes it back without a lock-in.
func TestFairShareSimAPauseAndAResume(t *testing.T) {
	t.Parallel()

	s := newPathSim(t, fairDownBucket, pathTotal)
	s.join("203.0.113.1", true, 0, pathGreedy(1, false)...)
	pausing := s.join("203.0.113.2", true, 0, pathGreedy(2, false)...)

	s.run(15)
	s.near(5, 14, 0, pathTotal/2, 5, "half each before the pause")

	s.pause(pausing)
	s.run(15)
	s.near(18, 29, 0, pathTotal, 5, "the other gets everything within three ticks of the pause")
	s.band(17, 29, 1, 0, 0, "the paused address moves nothing")

	s.resume(pausing)
	s.run(15)
	s.near(35, 44, 0, pathTotal/2, 5, "half each again within five ticks of the resume")
	s.near(35, 44, 1, pathTotal/2, 5, "half each again")
	s.steady(35, 44, pathTotal)
}

// A new address among three established ones starts at their level and has
// its quarter, as they do, within three ticks.
func TestFairShareSimANewArrival(t *testing.T) {
	t.Parallel()

	s := newPathSim(t, fairDownBucket, pathTotal)

	for i := range 3 {
		s.join(addressKey(fmt.Sprintf("203.0.113.%d", i+1)), true, 0, pathGreedy(1, false)...)
	}

	s.run(15)

	arrival := s.join("198.51.100.9", true, 0, pathGreedy(1, false)...)
	assert.EqualValues(t, fairLevelOf(s.table, "alice", fairDownBucket), fairRate(arrival.entry, fairDownBucket),
		"the arrival starts at the level")

	s.run(15)

	for i := range 4 {
		s.near(18, 29, i, pathTotal/4, 6, "a quarter each within three ticks")
	}

	s.steady(18, 29, pathTotal)
}

// An address its own ceiling holds is never fair-throttled, reports the
// ceiling as its demand, and the other gets the rest.
func TestFairShareSimACeilingHeldAddress(t *testing.T) {
	t.Parallel()

	s := newPathSim(t, fairDownBucket, pathTotal)
	s.join("203.0.113.1", true, 200_000, pathGreedy(2, false)...)
	s.join("203.0.113.2", true, 0, pathGreedy(1, false)...)

	s.run(30)

	s.band(6, 29, 0, 180_000, 220_000, "held at its ceiling")
	s.band(6, 29, 1, 780_000, 820_000, "the other gets the rest")
	s.steady(6, 29, pathTotal)

	for tick := 6; tick < 30; tick++ {
		assert.False(t, s.rows[tick].throttled[0], "tick %d: a ceiling is not a fair throttle", tick)
	}
}

// A reload that doubles the total, then fair share off and on again: after
// each the split settles to half each within five ticks, and the tick right
// after turning it back on is a baseline, not an average across the ten
// seconds it was off.
func TestFairShareSimReloadsAndToggles(t *testing.T) {
	t.Parallel()

	s := newPathSim(t, fairDownBucket, pathTotal)
	s.join("203.0.113.4", true, 0, pathGreedy(4, false)...)
	s.join("198.51.100.1", true, 0, pathGreedy(1, false)...)

	s.run(15)
	s.near(5, 14, 0, pathTotal/2, 5, "half each")

	s.setTotal(fairDownBucket, 2*pathTotal)
	s.reload()
	s.run(15)
	s.near(20, 29, 0, pathTotal, 5, "half of the doubled total each within five ticks")
	s.near(20, 29, 1, pathTotal, 5, "half of the doubled total each")

	s.fairOn = false
	s.reload()
	s.run(10)
	s.near(33, 39, 0, 8*pathTotal/5, 6, "fair share off: the user's bucket splits 4:1 again")

	s.fairOn = true
	s.reload()
	s.run(15)

	assert.Zero(t, s.rows[40].level, "the first tick after turning it on is a baseline")
	s.near(45, 54, 0, pathTotal, 5, "half each again within five ticks")
	s.near(45, 54, 1, pathTotal, 5, "half each again")
	s.steady(45, 54, 2*pathTotal)
}

// The tiny-level regime: 100 KB/s among seventy greedy addresses, ten of them
// with four connections, is about 1.4 KB/s each, so a 16 KiB write waits more
// than ten seconds at its share and moves nothing meanwhile. Blocked, it is
// still asking: every address stays a participant at every tick, so the level
// is exactly the total over seventy and the rates set add up to the total --
// the fair limiters, not the user bucket's split by connection, decide. Over
// ten minutes every address, four connections or one, gets its share within
// a tenth, and the total is used.
//
// Measured on this model: every address within 51-56 pieces of a fair 52.3,
// the four-connection ones the highest. With an address dropped from the
// participants after ten seconds without a byte, about ten are out at any
// tick, the level runs up to twice the share, and the four-connection
// addresses take a quarter more than their share at the one-connection ones'
// cost.
func TestFairShareSimTinyLevelKeepsEveryAddressTakingPart(t *testing.T) {
	t.Parallel()

	const (
		total  = int64(100_000)
		n      = 70
		from   = 30
		window = 600
	)

	s := newPathSim(t, fairDownBucket, total)

	for i := range n {
		conns := 1
		if i < 10 {
			conns = 4
		}

		s.join(syntheticClientKey(i), true, 0, pathGreedy(conns, false)...)
	}

	s.run(from + window + 1)

	share := total / n

	for tick := from; tick <= from+window; tick++ {
		row := s.rows[tick]

		require.EqualValues(t, share, row.level, "tick %d: the level is the total over every address", tick)

		for i := range n {
			require.True(t, row.participant[i], "tick %d: address %d left the participants", tick, i)
		}
	}

	var sum int64

	for i := range n {
		var moved int64
		for tick := from; tick < from+window; tick++ {
			moved += s.rows[tick].moved[i]
		}

		sum += moved

		assert.InDelta(t, float64(share*window), float64(moved), float64(share*window)/10,
			"address %d (four connections: %v) over ten minutes", i, i < 10)
	}

	assert.GreaterOrEqual(t, sum, total*window*95/100, "the total is used")
}
