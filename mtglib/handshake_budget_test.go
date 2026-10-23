package mtglib

import (
	"fmt"
	"math"
	"math/rand/v2"
	"net"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The handshake budget on its own, on a clock the test moves by hand and with
// the cost of a block injected, so every number below is arithmetic and none of
// it depends on the machine.

// budgetClock is the budget's clock in these tests. It never moves by itself.
type budgetClock struct {
	mu sync.Mutex
	at time.Time
}

func newBudgetClock() *budgetClock {
	return &budgetClock{at: time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)}
}

func (c *budgetClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.at
}

func (c *budgetClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.at = c.at.Add(d)
}

func testBudget(cfg scanBudgetConfig) (*scanBudget, *budgetClock) {
	clock := newBudgetClock()

	return newScanBudget(cfg, clock.now), clock
}

// globalAvailable is what the process-wide bucket holds now, for a scan of
// candidates candidates (the burst floor depends on it).
func (b *scanBudget) globalAvailable(candidates int) float64 {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.globalState.available(b.global.rate, b.burstFor(b.global, candidates), b.now())
}

// addressAvailable is what ip's bucket holds now, and whether it has one. It
// looks without promoting, so it changes nothing.
func (b *scanBudget) addressAvailable(ip net.IP, candidates int) (float64, bool) {
	key, ok := hintKey(ip)
	if !ok {
		return 0, false
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	st, ok := b.current[key]
	if !ok {
		st, ok = b.previous[key]
	}

	if !ok {
		return 0, false
	}

	return st.available(b.perIP.rate, b.burstFor(b.perIP, candidates), b.now()), true
}

// addresses is how many per-address buckets the budget holds.
func (b *scanBudget) addresses() int {
	b.mu.Lock()
	defer b.mu.Unlock()

	return len(b.current) + len(b.previous)
}

// verdicts reserves n times and tallies what came back.
func verdicts(b *scanBudget, ip net.IP, blocks, candidates, n int) map[budgetVerdict]int {
	got := make(map[budgetVerdict]int)

	for range n {
		_, _, v := b.reserve(ip, blocks, candidates)
		got[v]++
	}

	return got
}

// drainBudget reserves from ip until the budget refuses, and returns the verdict
// that refused. The clock is the test's, so this ends.
func drainBudget(t testing.TB, b *scanBudget, ip net.IP, blocks, candidates int) budgetVerdict {
	t.Helper()

	for range 1_000_000 {
		if _, _, v := b.reserve(ip, blocks, candidates); v != budgetGranted {
			return v
		}
	}

	t.Fatal("the budget never refused")

	return budgetGranted
}

// nsPerBlockForTests is a microsecond a block: rates come out in round numbers.
const nsPerBlockForTests = 1000

// spacious is a process-wide bucket no test of the address bucket can reach:
// 100% of 1,000 cores at a microsecond a block is 1e9 blocks a second.
func spacious(cfg scanBudgetConfig) scanBudgetConfig {
	cfg.CPUPercent, cfg.Procs = 100, 1000

	if cfg.NsPerBlock == 0 {
		cfg.NsPerBlock = nsPerBlockForTests
	}

	return cfg
}

func TestPerAddressBurstThenRefill(t *testing.T) {
	t.Parallel()

	// 50 ms of scan CPU a second at 1 us a block: 50,000 blocks a second, a
	// burst of four seconds' worth (200,000), and a debt of at most 150 ms'
	// worth (7,500). A hello of 12 blocks against 1,000 candidates costs 12,000.
	b, clock := testBudget(spacious(scanBudgetConfig{}))
	ip := net.ParseIP("203.0.113.7")

	for i := range 16 {
		res, wait, v := b.reserve(ip, 12, 1000)
		require.Equal(t, budgetGranted, v, "hello %d is within the burst", i)
		require.NotNil(t, res)
		require.Zero(t, wait, "hello %d", i)
	}

	got, ok := b.addressAvailable(ip, 1000)
	require.True(t, ok)
	assert.InDelta(t, 8000, got, 1e-6, "sixteen hellos spent 192,000 of 200,000")

	// 8,000 left, 12,000 asked: 4,000 short, which is 80 ms of refill.
	_, wait, v := b.reserve(ip, 12, 1000)
	require.Equal(t, budgetGranted, v)
	assert.InDelta(t, float64(80*time.Millisecond), float64(wait), float64(time.Microsecond),
		"a hello the burst cannot cover waits for the refill")

	// 16,000 short is 320 ms: past the wait, refused, and nothing changes.
	res, wait, v := b.reserve(ip, 12, 1000)
	assert.Equal(t, budgetDeniedIP, v)
	assert.Nil(t, res)
	assert.Zero(t, wait)

	got, _ = b.addressAvailable(ip, 1000)
	assert.InDelta(t, -4000, got, 1e-6, "a refusal leaves the bucket as it was")

	_, wait, v = b.reserve(net.ParseIP("203.0.113.8"), 12, 1000)
	assert.Equal(t, budgetGranted, v, "another address has a bucket of its own")
	assert.Zero(t, wait)

	// A second of refill: -4,000 + 50,000.
	clock.advance(time.Second)

	got, _ = b.addressAvailable(ip, 1000)
	assert.InDelta(t, 46000, got, 1e-6)

	for i := range 3 {
		_, wait, v := b.reserve(ip, 12, 1000)
		require.Equal(t, budgetGranted, v, "refilled hello %d", i)
		require.Zero(t, wait)
	}

	_, wait, v = b.reserve(ip, 12, 1000)
	require.Equal(t, budgetGranted, v)
	assert.InDelta(t, float64(40*time.Millisecond), float64(wait), float64(time.Microsecond))

	clock.advance(time.Hour)

	got, _ = b.addressAvailable(ip, 1000)
	assert.InDelta(t, 200000, got, 1e-6, "an idle bucket refills to its burst and no further")
}

// The headline property: the per-address bucket is no CPU bound against many
// addresses, and the process-wide one is. 10,000 distinct /64s are cheap to come
// by.
func TestManyAddressesAreStoppedByTheProcessWideBucket(t *testing.T) {
	t.Parallel()

	// 25% of 4 cores at 1 us a block: 1e6 blocks a second, a burst of one
	// second's worth, a debt of at most 150,000. Each address's own bucket
	// (200,000) never binds: one hello there costs 1,200.
	const (
		rate      = 1e6
		cost      = 100 * 12
		addresses = 10_000
	)

	b, clock := testBudget(scanBudgetConfig{NsPerBlock: nsPerBlockForTests, CPUPercent: 25, Procs: 4})

	place := func(round, i int) net.IP {
		return net.ParseIP(fmt.Sprintf("2001:db8:%x:%x::1", round, i))
	}

	ceiling := rate + rate*0.150
	want := int(ceiling / cost) // 958

	got := make(map[budgetVerdict]int)

	for i := range addresses {
		_, _, v := b.reserve(place(1, i), 12, 100)
		got[v]++
	}

	assert.Equal(t, map[budgetVerdict]int{budgetGranted: want, budgetDeniedGlobal: addresses - want}, got,
		"the burst and 150 ms of debt, then nothing, however many addresses ask")
	assert.LessOrEqual(t, float64(got[budgetGranted]*cost), ceiling)
	assert.Equal(t, want, b.addresses(), "a refused address is not even remembered")

	// A second later the bucket has refilled by one second's worth, and that is
	// all the next 10,000 get.
	clock.advance(time.Second)

	again := make(map[budgetVerdict]int)

	for i := range addresses {
		_, _, v := b.reserve(place(2, i), 12, 100)
		again[v]++
	}

	assert.Zero(t, again[budgetDeniedIP])
	assert.LessOrEqual(t, float64((got[budgetGranted]+again[budgetGranted])*cost), rate+rate*1+rate*0.150,
		"over a second: the burst, a second of refill and the debt")
	// What the first round left (-149,600), a second of refill and the debt:
	// (850,400 + 150,000) / 1,200 = 833.
	assert.Equal(t, int(((rate-float64(want*cost))+rate*1+rate*0.150)/cost), again[budgetGranted])
}

// A PROXY-protocol listener takes the client address from a header anyone can
// send. Forged addresses -- more of them than the address map holds, mixed with
// unkeyed and v4-mapped ones -- buy nothing past the process-wide ceiling.
func TestForgedAddressesDoNotEscapeTheCeiling(t *testing.T) {
	t.Parallel()

	const (
		rate   = 1e6
		cost   = 12
		forged = 120_000
	)

	b, _ := testBudget(scanBudgetConfig{NsPerBlock: nsPerBlockForTests, CPUPercent: 25, Procs: 4})

	got := make(map[budgetVerdict]int)

	for i := range forged {
		var ip net.IP

		switch i % 10 {
		case 0:
			ip = nil
		case 1:
			ip = net.ParseIP("127.0.0.1")
		case 2:
			ip = net.ParseIP(fmt.Sprintf("::ffff:11.%d.%d.%d", byte(i>>16), byte(i>>8), byte(i)))
		default:
			ip = net.IPv4(11, byte(i>>16), byte(i>>8), byte(i))
		}

		_, _, v := b.reserve(ip, 12, 1)
		got[v]++
	}

	ceiling := rate + rate*0.150

	assert.Equal(t, int(ceiling/cost), got[budgetGranted], "exactly what the process-wide bucket allows")
	assert.LessOrEqual(t, float64(got[budgetGranted]*cost), ceiling)
	assert.Zero(t, got[budgetDeniedIP], "every forged address is new, with a full bucket of its own")
	assert.Equal(t, maxBudgetAddresses, b.addresses(), "and the address map stops at its cap")
}

func TestTheQueueAdmitsASmallHerdAndRefusesPastTheWait(t *testing.T) {
	t.Parallel()

	b, clock := testBudget(scanBudgetConfig{NsPerBlock: nsPerBlockForTests, CPUPercent: 25, Procs: 4})

	// Empty the process-wide bucket to exactly zero: 10,000 candidates x 100
	// blocks is its whole burst of 1e6.
	_, wait, v := b.reserve(nil, 100, 10_000)
	require.Equal(t, budgetGranted, v)
	require.Zero(t, wait)
	require.InDelta(t, 0, b.globalAvailable(1000), 1e-6)

	// A herd of hellos each costing 40,000 (40 ms of refill): they queue.
	for i, want := range []time.Duration{40 * time.Millisecond, 80 * time.Millisecond, 120 * time.Millisecond} {
		_, wait, v := b.reserve(nil, 40, 1000)
		require.Equal(t, budgetGranted, v, "herd member %d", i)
		assert.InDelta(t, float64(want), float64(wait), float64(time.Microsecond), "herd member %d", i)
	}

	// The fourth would wait 160 ms: refused, and the queue is as it was.
	for range 3 {
		_, wait, v = b.reserve(nil, 40, 1000)
		assert.Equal(t, budgetDeniedGlobal, v)
		assert.Zero(t, wait)
	}

	assert.InDelta(t, -120000, b.globalAvailable(1000), 1e-6)

	// The queue drains in time: 120 ms later the debt is paid and the next
	// hello waits its own 40 ms only.
	clock.advance(120 * time.Millisecond)

	_, wait, v = b.reserve(nil, 40, 1000)
	require.Equal(t, budgetGranted, v)
	assert.InDelta(t, float64(40*time.Millisecond), float64(wait), float64(time.Microsecond))
}

func TestACostAboveWhatTheWaitAllowsIsRefused(t *testing.T) {
	t.Parallel()

	t.Run("the process-wide bucket", func(t *testing.T) {
		t.Parallel()

		b, _ := testBudget(scanBudgetConfig{NsPerBlock: nsPerBlockForTests, CPUPercent: 25, Procs: 4})

		// A full bucket of 1e6 and 150,000 of debt cannot pay 1.28e6.
		res, wait, v := b.reserve(nil, 128, 10_000)
		assert.Equal(t, budgetDeniedGlobal, v)
		assert.Nil(t, res)
		assert.Zero(t, wait)
		assert.InDelta(t, 1e6, b.globalAvailable(10_000), 1e-6, "and the bucket is untouched")

		_, wait, v = b.reserve(nil, 12, 10_000)
		assert.Equal(t, budgetGranted, v, "the control: the same candidates at 12 blocks fit")
		assert.Zero(t, wait)
	})

	t.Run("an address bucket", func(t *testing.T) {
		t.Parallel()

		b, _ := testBudget(spacious(scanBudgetConfig{}))
		ip := net.ParseIP("203.0.113.5")

		// A burst of 200,000 and 7,500 of debt cannot pay 256,000.
		res, wait, v := b.reserve(ip, 128, 2000)
		assert.Equal(t, budgetDeniedIP, v)
		assert.Nil(t, res)
		assert.Zero(t, wait)
		assert.Zero(t, b.addresses(), "a refused address is not added")
		assert.InDelta(t, 1e9, b.globalAvailable(2000), 1e-6, "neither bucket changes on a refusal")

		_, wait, v = b.reserve(ip, 12, 2000)
		assert.Equal(t, budgetGranted, v, "the control")
		assert.Zero(t, wait)
	})

	t.Run("one bucket refusing leaves the other untouched", func(t *testing.T) {
		t.Parallel()

		b, _ := testBudget(scanBudgetConfig{NsPerBlock: nsPerBlockForTests, CPUPercent: 25, Procs: 4})
		ip := net.ParseIP("203.0.113.6")

		// The address has a bucket with room in it; the process has none left.
		_, _, v := b.reserve(ip, 12, 10)
		require.Equal(t, budgetGranted, v)
		require.Equal(t, budgetDeniedGlobal, drainBudget(t, b, nil, 12, 10))

		address, held := b.addressAvailable(ip, 10)
		require.True(t, held)

		global := b.globalAvailable(10)

		_, _, v = b.reserve(ip, 12, 10)
		assert.Equal(t, budgetDeniedGlobal, v)

		after, _ := b.addressAvailable(ip, 10)
		assert.InDelta(t, address, after, 0, "the address's bucket could pay, and is not charged")
		assert.InDelta(t, global, b.globalAvailable(10), 0)
	})
}

func TestChargeIsRefundedExactlyOnceAndOnlyOnSuccess(t *testing.T) {
	t.Parallel()

	b, clock := testBudget(scanBudgetConfig{NsPerBlock: nsPerBlockForTests, CPUPercent: 25, Procs: 4})
	ip := net.ParseIP("203.0.113.10")

	const cost = 100 * 12

	both := func() (float64, float64) {
		t.Helper()

		addr, ok := b.addressAvailable(ip, 100)
		require.True(t, ok)

		return addr, b.globalAvailable(100)
	}

	kept, _, v := b.reserve(ip, 12, 100)
	require.Equal(t, budgetGranted, v)

	kept.settle(false)

	addr0, global0 := both()
	assert.InDelta(t, 200000-cost, addr0, 1e-6, "a failure keeps the charge")
	assert.InDelta(t, 1e6-cost, global0, 1e-6)

	kept.settle(true)

	addr, global := both()
	assert.InDelta(t, addr0, addr, 1e-6, "a settled reservation cannot be refunded afterwards")
	assert.InDelta(t, global0, global, 1e-6)

	refunded, _, v := b.reserve(ip, 12, 100)
	require.Equal(t, budgetGranted, v)

	addr, global = both()
	require.InDelta(t, addr0-cost, addr, 1e-6)
	require.InDelta(t, global0-cost, global, 1e-6)

	refunded.settle(true)

	addr, global = both()
	assert.InDelta(t, addr0, addr, 1e-6, "a success refunds in full, to both buckets")
	assert.InDelta(t, global0, global, 1e-6)

	refunded.settle(true)
	refunded.settle(false)

	addr, global = both()
	assert.InDelta(t, addr0, addr, 1e-6, "and only once")
	assert.InDelta(t, global0, global, 1e-6)

	var none *scanReservation

	assert.NotPanics(t, func() { none.settle(true) }, "no reservation is nothing to settle")

	t.Run("capped at the burst", func(t *testing.T) {
		b, clock := testBudget(scanBudgetConfig{NsPerBlock: nsPerBlockForTests, CPUPercent: 25, Procs: 4})

		early, _, v := b.reserve(ip, 12, 100)
		require.Equal(t, budgetGranted, v)

		// An hour on, the bucket is full again; a fresh charge and its refund
		// put it back at the burst, and the early refund must not lift it above.
		clock.advance(time.Hour)

		late, _, v := b.reserve(ip, 12, 100)
		require.Equal(t, budgetGranted, v)

		late.settle(true)
		early.settle(true)

		b.mu.Lock()
		defer b.mu.Unlock()

		assert.LessOrEqual(t, b.globalState.tokens, b.burstFor(b.global, 100))

		key, _ := hintKey(ip)
		assert.LessOrEqual(t, b.current[key].tokens, b.burstFor(b.perIP, 100))
	})

	t.Run("to the bucket it was charged to, after the map has rotated", func(t *testing.T) {
		res, _, v := b.reserve(ip, 12, 100)
		require.Equal(t, budgetGranted, v)
		require.Equal(t, 2, res.n, "both buckets were charged")

		charged := res.charges[0].bucket
		require.NotSame(t, &b.globalState, charged, "the address bucket is charged first")

		before := charged.tokens

		b.rotate()
		b.rotate()

		_, held := b.addressAvailable(ip, 100)
		require.False(t, held, "two rotations forget the address")

		assert.NotPanics(t, func() { res.settle(true) })
		assert.InDelta(t, before+cost, charged.tokens, 1e-6, "the refund lands on the object it was taken from")

		clock.advance(time.Millisecond)

		_, _, v = b.reserve(ip, 12, 100)
		require.Equal(t, budgetGranted, v)

		got, held := b.addressAvailable(ip, 100)
		require.True(t, held)
		assert.InDelta(t, 200000-cost, got, 1e-6, "the address starts again from a full burst")
	})
}

func TestBurstFloorIsFourTimesCandidatesTimesTwelve(t *testing.T) {
	t.Parallel()

	for _, n := range []int{1, 7, 1000, 100_000} {
		assert.InDelta(t, float64(4*n*12), burstFloor(n), 0, "the floor for %d candidates", n)
	}

	// Base bursts far below the floor: 1 ms a second per address is 1,000
	// blocks a second (a base burst of 4,000), and 1% of one core is 10,000 a
	// second (a base burst of 10,000). At 1,000 candidates the floor is 48,000.
	cfg := scanBudgetConfig{NsPerBlock: nsPerBlockForTests, PerIPMillis: 1, CPUPercent: 1, Procs: 1}

	t.Run("a flood of large hellos does not raise its own cap", func(t *testing.T) {
		t.Parallel()

		b, _ := testBudget(cfg)

		// 1,000 x 128 = 128,000. A floor that grew with the hello's size
		// (4 x 1,000 x 128 = 512,000) would grant every one of these.
		for i := range 100 {
			_, _, v := b.reserve(net.IPv4(198, 51, 100, byte(i)), 128, 1000)
			require.NotEqual(t, budgetGranted, v, "large hello %d", i)
		}

		assert.InDelta(t, 48000, b.globalAvailable(1000), 1e-6, "and they cost nothing")

		ip := net.ParseIP("203.0.113.30")

		for i := range 4 {
			_, wait, v := b.reserve(ip, 12, 1000)
			require.Equal(t, budgetGranted, v, "a real client's hello %d fits the floor", i)
			require.Zero(t, wait)
		}

		_, _, v := b.reserve(ip, 12, 1000)
		assert.Equal(t, budgetDeniedIP, v, "four of them, not five")
	})

	t.Run("a large secret count is never starved for good", func(t *testing.T) {
		t.Parallel()

		b, clock := testBudget(cfg)

		// 100,000 candidates: a 12-block hello costs 1.2e6, over a hundred
		// times the process-wide base burst. The floor (4.8e6) still lets four
		// through, and the refill lets the next one through in time.
		for i := range 4 {
			_, wait, v := b.reserve(nil, 12, 100_000)
			require.Equal(t, budgetGranted, v, "hello %d", i)
			require.Zero(t, wait)
		}

		_, _, v := b.reserve(nil, 12, 100_000)
		require.Equal(t, budgetDeniedGlobal, v)

		clock.advance(120 * time.Second) // 1.2e6 at 10,000 a second

		_, wait, v := b.reserve(nil, 12, 100_000)
		assert.Equal(t, budgetGranted, v, "admitted again once the refill has paid for it")
		assert.Zero(t, wait)
	})
}

func TestAFullAddressMapGivesNewAddressesNoEntryAndNeverResets(t *testing.T) {
	t.Parallel()

	// A process-wide bucket nothing here reaches (100% of a million cores at
	// 10 ns a block), and an address bucket of 100,000 blocks a second whose
	// burst at 10,000 candidates is the floor, 480,000: four hellos of 120,000.
	b, clock := testBudget(scanBudgetConfig{NsPerBlock: 10, PerIPMillis: 1, CPUPercent: 100, Procs: 1_000_000})

	const candidates = 10_000

	drained := net.ParseIP("203.0.113.77")

	require.Equal(t, budgetDeniedIP, drainBudget(t, b, drained, 12, candidates))

	// 120,000 a hello, and 150 ms of 100,000 a second is 15,000 of debt.
	before, ok := b.addressAvailable(drained, candidates)
	require.True(t, ok)
	require.Less(t, before-120000, -15000.0, "it cannot afford another hello")

	forged := func(batch, i int) net.IP {
		return net.IPv4(byte(11+batch), byte(i>>16), byte(i>>8), byte(i))
	}

	for i := range maxBudgetAddresses - 1 {
		_, _, v := b.reserve(forged(0, i), 12, candidates)
		require.Equal(t, budgetGranted, v)
	}

	require.Equal(t, maxBudgetAddresses, b.addresses(), "the map is full")

	// As many new addresses again: none gets an entry, every one is served by
	// the process-wide bucket, and nothing already held is pushed out.
	for i := range maxBudgetAddresses {
		_, _, v := b.reserve(forged(1, i), 12, candidates)
		require.Equal(t, budgetGranted, v)
	}

	assert.Equal(t, maxBudgetAddresses, b.addresses(), "a full map takes no new address")

	after, ok := b.addressAvailable(drained, candidates)
	require.True(t, ok, "the draining address is still held")
	assert.InDelta(t, before, after, 1e-6, "and its bucket was not reset")

	_, _, v := b.reserve(drained, 12, candidates)
	assert.Equal(t, budgetDeniedIP, v, "so it is still refused")

	// A new address has no bucket of its own to drain: ten hellos, more than
	// twice its burst, all go through the process-wide one.
	fresh := net.ParseIP("203.0.113.78")

	assert.Equal(t, map[budgetVerdict]int{budgetGranted: 10}, verdicts(b, fresh, 12, candidates, 10))

	_, held := b.addressAvailable(fresh, candidates)
	assert.False(t, held)

	// Only the timer forgets: two rotations and the map is empty, and the
	// drained address starts again from a full bucket.
	b.rotate()
	b.rotate()

	assert.Zero(t, b.addresses())

	clock.advance(time.Millisecond)

	_, _, v = b.reserve(drained, 12, candidates)
	assert.Equal(t, budgetGranted, v)
}

func TestAdmissionIsSizeUniform(t *testing.T) {
	t.Parallel()

	key := keyFilledFrom(3)
	blocksOf := func(size int) int {
		if size == 0 {
			return parsedHello(t, fakeTLSClientHello(t, key, govCoverHost, make([]byte, 32)), govCoverHost).Blocks()
		}

		return parsedHello(t, fakeTLSClientHelloPadded(t, key, govCoverHost, make([]byte, 32), size), govCoverHost).Blocks()
	}

	short, typical, large := blocksOf(0), blocksOf(517), blocksOf(4096)

	require.Less(t, short, 12, "the forged hello is shorter than a real client's")
	require.Equal(t, 12, typical)
	require.Equal(t, 68, large)

	const candidates = 10

	costOf := func(blocks int) float64 {
		b, _ := testBudget(scanBudgetConfig{NsPerBlock: nsPerBlockForTests, CPUPercent: 25, Procs: 4})
		full := b.globalAvailable(candidates)

		_, _, v := b.reserve(nil, blocks, candidates)
		require.Equal(t, budgetGranted, v)

		return full - b.globalAvailable(candidates)
	}

	// A 100-byte record is 3 + ceil(109/64) = 5 blocks.
	assert.InDelta(t, 12*candidates, costOf(5), 1e-6, "a 100-byte hello costs what a real one does")
	assert.InDelta(t, 12*candidates, costOf(short), 1e-6)
	assert.InDelta(t, 12*candidates, costOf(typical), 1e-6)
	assert.InDelta(t, 68*candidates, costOf(large), 1e-6, "a 4 KiB hello costs its size")
	assert.InDelta(t, 128*candidates, costOf(128), 1e-6)
}

func TestOversizedIsRefusedWithoutScanning(t *testing.T) {
	t.Parallel()

	b, _ := testBudget(scanBudgetConfig{NsPerBlock: nsPerBlockForTests, CPUPercent: 25, Procs: 4})
	ip := net.ParseIP("203.0.113.90")

	assert.False(t, b.oversized(maxScanBlocks))
	assert.True(t, b.oversized(maxScanBlocks+1))

	res, wait, v := b.reserve(ip, maxScanBlocks+1, 10)
	assert.Equal(t, budgetOversized, v)
	assert.Nil(t, res)
	assert.Zero(t, wait)

	// Review Focus 7: the largest hello the reader accepts, fragmented across
	// records, is 1,028 blocks.
	wire := fakeTLSClientHelloPadded(t, keyFilledFrom(9), govCoverHost, make([]byte, 32), 65540)
	require.Greater(t, len(wire), 65540, "it arrives as several records")

	blocks := parsedHello(t, wire, govCoverHost).Blocks()
	require.Equal(t, 1028, blocks)

	assert.True(t, b.oversized(blocks))

	_, _, v = b.reserve(ip, blocks, 10)
	assert.Equal(t, budgetOversized, v)

	assert.Zero(t, b.addresses(), "an oversized hello is not charged to its address")
	assert.InDelta(t, 1e6, b.globalAvailable(10), 1e-6, "nor to the process")

	_, _, v = b.reserve(ip, maxScanBlocks, 10)
	assert.Equal(t, budgetGranted, v, "the cap itself is within it")
}

// Review Focus 2: an address that does not stand for one place has no bucket of
// its own -- behind a carrier every client presents it -- and is held to the
// process-wide bucket only.
func TestUnkeyedPeersUseOnlyTheProcessWideBucket(t *testing.T) {
	t.Parallel()

	// An address bucket allows 17 hellos of 12,000 here (16 from the burst, one
	// more inside the wait); each unkeyed peer below sends 40.
	const (
		hellos = 40
		cost   = 1000 * 12
	)

	b, _ := testBudget(spacious(scanBudgetConfig{}))

	unkeyed := []net.IP{
		nil,
		net.ParseIP("127.0.0.1"),
		net.ParseIP("::1"),
		net.ParseIP("10.1.2.3"),
		net.ParseIP("172.16.0.1"),
		net.ParseIP("192.168.1.1"),
		net.ParseIP("fd00::1"),
		net.ParseIP("169.254.1.1"),
		net.ParseIP("fe80::1"),
		net.ParseIP("0.0.0.0"),
		net.ParseIP("::"),
		net.ParseIP("224.0.0.1"),
		net.ParseIP("::ffff:10.1.2.3"),
	}

	full := b.globalAvailable(1000)

	for _, ip := range unkeyed {
		assert.Equal(t, map[budgetVerdict]int{budgetGranted: hellos}, verdicts(b, ip, 12, 1000, hellos), "%v", ip)
	}

	assert.Zero(t, b.addresses(), "no unkeyed peer has a bucket")
	assert.InDelta(t, full-float64(len(unkeyed)*hellos*cost), b.globalAvailable(1000), 1e-3,
		"every one of them was charged to the process-wide bucket")

	// The control: a public address is held to its own bucket.
	got := verdicts(b, net.ParseIP("203.0.113.9"), 12, 1000, hellos)
	assert.Equal(t, 17, got[budgetGranted])
	assert.Equal(t, hellos-17, got[budgetDeniedIP])
}

// Review Focus 1: the key is the hint key -- the IPv4 address unmapped, the
// IPv6 /64.
func TestMappedAndSameSlash64PeersShareOneAddressBucket(t *testing.T) {
	t.Parallel()

	b, _ := testBudget(spacious(scanBudgetConfig{}))

	require.Equal(t, budgetDeniedIP, drainBudget(t, b, net.ParseIP("203.0.113.9"), 12, 1000))

	_, _, v := b.reserve(net.ParseIP("::ffff:203.0.113.9"), 12, 1000)
	assert.Equal(t, budgetDeniedIP, v, "the v4-mapped form is the same address")

	_, _, v = b.reserve(net.IPv4(203, 0, 113, 9).To4(), 12, 1000)
	assert.Equal(t, budgetDeniedIP, v, "and so is the 4-byte form")

	require.Equal(t, budgetDeniedIP, drainBudget(t, b, net.ParseIP("2001:db8:1:2::1"), 12, 1000))

	_, _, v = b.reserve(net.ParseIP("2001:db8:1:2:ffff::9"), 12, 1000)
	assert.Equal(t, budgetDeniedIP, v, "another host in the same /64 is the same place")

	_, _, v = b.reserve(net.ParseIP("2001:db8:1:3::1"), 12, 1000)
	assert.Equal(t, budgetGranted, v, "the next /64 is not")

	assert.Equal(t, 3, b.addresses())
}

func TestPerIPZeroDisablesOnlyTheAddressBucket(t *testing.T) {
	t.Parallel()

	// 1e6 blocks a second process-wide, 12,000 a hello: 95 hellos (the burst
	// and 150 ms of debt) and then the process-wide refusal.
	cfg := scanBudgetConfig{NsPerBlock: nsPerBlockForTests, CPUPercent: 25, Procs: 4}
	ip := net.ParseIP("203.0.113.9")

	off := cfg
	off.PerIPDisabled = true

	b, _ := testBudget(off)

	assert.Equal(t, map[budgetVerdict]int{budgetGranted: 95, budgetDeniedGlobal: 5}, verdicts(b, ip, 12, 1000, 100),
		"one address takes the whole process-wide bucket, and that bucket still refuses")
	assert.Zero(t, b.addresses())

	on, _ := testBudget(cfg)

	got := verdicts(on, ip, 12, 1000, 100)
	assert.Equal(t, 17, got[budgetGranted], "the control: with the address bucket on, it binds first")
	assert.Equal(t, 83, got[budgetDeniedIP])
}

// observe mode is the evidence for turning enforce on, so it has to see what
// enforce would do: the same charges, the same would-refuse decisions, the same
// refunds. It only never waits and (at the door) never refuses.
func TestObserveShadowAccountingDrainsLikeEnforce(t *testing.T) {
	t.Parallel()

	type step struct {
		ip         string
		blocks     int
		candidates int
		settle     string // "", "ok" or "fail": settle this step's reservation
		advance    time.Duration
	}

	script := []step{}

	// One address works through its bucket and past it, some of its hellos
	// succeeding, while other addresses and unkeyed peers drain the process.
	for i := range 60 {
		s := step{ip: "203.0.113.50", blocks: 12, candidates: 500}

		switch i % 5 {
		case 1:
			s.settle = "ok"
		case 3:
			s.settle = "fail"
		}

		if i%7 == 0 {
			s.ip = fmt.Sprintf("198.51.100.%d", i)
			s.blocks = 128
		}

		if i%11 == 0 {
			s.ip = ""
		}

		if i%13 == 0 {
			s.advance = 30 * time.Millisecond
		}

		script = append(script, s)
	}

	type outcome struct {
		verdict          budgetVerdict
		waited           bool
		global, address  float64
		addressHeld      bool
		addressesTracked int
	}

	run := func(mode budgetMode) []outcome {
		// 20,000 blocks a second per address (a burst of 80,000), 400,000 for
		// the process: the address the script leans on runs dry first, then
		// the large hellos run the process dry.
		cfg := scanBudgetConfig{
			Mode: mode, NsPerBlock: nsPerBlockForTests, PerIPMillis: 20, CPUPercent: 40, Procs: 1,
		}
		b, clock := testBudget(cfg)

		outcomes := make([]outcome, 0, len(script))

		for _, s := range script {
			clock.advance(s.advance)

			res, wait, v := b.reserve(net.ParseIP(s.ip), s.blocks, s.candidates)

			switch s.settle {
			case "ok":
				res.settle(true)
			case "fail":
				res.settle(false)
			}

			addr, held := b.addressAvailable(net.ParseIP("203.0.113.50"), 500)

			outcomes = append(outcomes, outcome{
				verdict:          v,
				waited:           wait > 0,
				global:           b.globalAvailable(500),
				address:          addr,
				addressHeld:      held,
				addressesTracked: b.addresses(),
			})
		}

		return outcomes
	}

	enforce, observe := run(budgetEnforce), run(budgetObserve)

	seen := make(map[budgetVerdict]bool)
	waits := 0

	for i := range script {
		seen[enforce[i].verdict] = true

		if enforce[i].waited {
			waits++
		}

		assert.False(t, observe[i].waited, "step %d: observe never waits", i)

		observe[i].waited = enforce[i].waited
		assert.Equal(t, enforce[i], observe[i], "step %d: the same decision and the same buckets", i)
	}

	// Without these the comparison could be two runs that never drained.
	assert.True(t, seen[budgetDeniedIP], "the script reaches an address refusal")
	assert.True(t, seen[budgetDeniedGlobal], "and a process-wide one")
	assert.Positive(t, waits, "and enforce queues some hellos")
}

func TestOffNeverRefusesNorCapsSize(t *testing.T) {
	t.Parallel()

	off, _ := testBudget(scanBudgetConfig{Mode: budgetOff, NsPerBlock: nsPerBlockForTests, PerIPMillis: 1, CPUPercent: 1, Procs: 1})

	var none *scanBudget

	for name, b := range map[string]*scanBudget{"off": off, "nil": none} {
		assert.False(t, b.enforced(), name)
		assert.False(t, b.oversized(1028), "%s: no scan cap", name)

		for range 1000 {
			res, wait, v := b.reserve(net.ParseIP("203.0.113.1"), 1028, 1_000_000)
			require.Equal(t, budgetGranted, v, name)
			require.Nil(t, res, "%s: nothing is charged", name)
			require.Zero(t, wait, name)
		}
	}

	observe, _ := testBudget(scanBudgetConfig{Mode: budgetObserve, NsPerBlock: nsPerBlockForTests})
	enforce, _ := testBudget(scanBudgetConfig{NsPerBlock: nsPerBlockForTests})

	assert.False(t, observe.enforced())
	assert.True(t, enforce.enforced(), "the zero mode is enforce")
	assert.True(t, observe.oversized(129), "observe counts what enforce would cap")
}

func TestBucketsStayWithinTheirBounds(t *testing.T) {
	t.Parallel()

	const candidates = 50

	b, clock := testBudget(scanBudgetConfig{
		NsPerBlock: nsPerBlockForTests, PerIPMillis: 5, CPUPercent: 2, Procs: 1, MaxWait: 150 * time.Millisecond,
	})

	addressBurst := b.burstFor(b.perIP, candidates)
	globalBurst := b.burstFor(b.global, candidates)
	addressDebt := b.perIP.rate * 0.150
	globalDebt := b.global.rate * 0.150

	places := []net.IP{nil, net.ParseIP("203.0.113.1"), net.ParseIP("203.0.113.2"), net.ParseIP("2001:db8::1")}
	random := rand.New(rand.NewPCG(7, 11)) // a reproducible schedule

	var open []*scanReservation

	check := func(step int) {
		t.Helper()

		b.mu.Lock()
		defer b.mu.Unlock()

		for key, st := range b.current {
			require.LessOrEqual(t, st.tokens, addressBurst, "step %d, %v: above the burst", step, key)
			require.GreaterOrEqual(t, st.tokens, -addressDebt-1e-6, "step %d, %v: below the debt floor", step, key)
		}

		require.LessOrEqual(t, b.globalState.tokens, globalBurst, "step %d: above the burst", step)
		require.GreaterOrEqual(t, b.globalState.tokens, -globalDebt-1e-6, "step %d: below the debt floor", step)
	}

	for step := range 20_000 {
		switch roll := random.IntN(10); {
		case roll < 6:
			res, _, v := b.reserve(places[random.IntN(len(places))], 1+random.IntN(140), candidates)
			if v == budgetGranted {
				open = append(open, res)
			}
		case roll < 8 && len(open) > 0:
			at := random.IntN(len(open))
			open[at].settle(random.IntN(2) == 0)
			open = append(open[:at], open[at+1:]...)
		case roll == 8:
			clock.advance(time.Duration(random.IntN(int(2 * time.Second))))
		default:
			// A clock that steps back must not be read as negative refill.
			clock.advance(-time.Duration(random.IntN(int(time.Second))))
		}

		check(step)
	}

	// A clock that steps back neither refills nor drains: the bucket holds
	// what it was left with.
	back, backClock := testBudget(scanBudgetConfig{NsPerBlock: nsPerBlockForTests, CPUPercent: 25, Procs: 4})

	_, _, v := back.reserve(nil, 12, 10)
	require.Equal(t, budgetGranted, v)

	backClock.advance(-time.Second)
	assert.InDelta(t, 1e6-120, back.globalAvailable(10), 0, "a step back in time is no time at all")

	clock.advance(24 * time.Hour)

	got := b.globalAvailable(candidates)
	assert.InDelta(t, globalBurst, got, 0, "a day idle is exactly the burst")
	assert.False(t, math.IsInf(got, 0) || math.IsNaN(got))

	clock.advance(100 * 365 * 24 * time.Hour)

	got = b.globalAvailable(candidates)
	assert.InDelta(t, globalBurst, got, 0, "and so is a century")

	addr, ok := b.addressAvailable(places[1], candidates)
	require.True(t, ok)
	assert.InDelta(t, addressBurst, addr, 0)
}

func TestCalibrationRunsOncePerProcess(t *testing.T) {
	t.Parallel()

	t.Run("one measurement however many ask", func(t *testing.T) {
		t.Parallel()

		var measured int

		c := &calibration{measure: func() float64 {
			measured++

			return 321
		}}

		var (
			wg     sync.WaitGroup
			mu     sync.Mutex
			firsts int
			values []float64
		)

		for range 32 {
			wg.Go(func() {
				ns, first := c.value()

				mu.Lock()
				defer mu.Unlock()

				values = append(values, ns)

				if first {
					firsts++
				}
			})
		}

		wg.Wait()

		assert.Equal(t, 1, measured)
		assert.Equal(t, 1, firsts, "exactly one caller is told it took the measurement")
		assert.EqualValues(t, 1, c.runs.Load())

		for _, ns := range values {
			assert.InDelta(t, 321, ns, 0)
		}
	})

	t.Run("the process's", func(t *testing.T) {
		t.Parallel()

		// The one test that takes the real measurement -- or finds it taken by
		// whichever proxy this test binary built first.
		for range 2 {
			opts, _ := servingOpts(t)

			proxy, err := NewProxy(opts)
			require.NoError(t, err)
			t.Cleanup(proxy.Shutdown)

			assert.InDelta(t, blockNanos(), proxy.scanBudget.nsPerBlock, 0, "every proxy uses the one measurement")
		}

		assert.EqualValues(t, 1, processCalibration.runs.Load(), "measured once, for the whole process")

		ns := blockNanos()
		assert.InDelta(t, ns, blockNanos(), 0)
		assert.GreaterOrEqual(t, ns, float64(minBlockNanos))
		assert.LessOrEqual(t, ns, float64(maxBlockNanos))
	})
}

// The calibration has to time what the budget charges for, or every rate is off
// by a factor that depends on the CPU: one timed call is one verification of a
// real client's 517-byte hello, which is exactly what the door charges 12
// blocks for (the cost floor).
func TestCalibrationTimesWhatTheBudgetCharges(t *testing.T) {
	t.Parallel()

	hello := fakeTLSClientHelloPadded(t, keyFilledFrom(5), govCoverHost, make([]byte, 32), calibrationHelloSize)
	require.Len(t, hello, calibrationHelloSize)

	assert.Equal(t, parsedHello(t, hello, govCoverHost).Blocks(), calibrationCallBlocks,
		"a timed call is charged what the door charges that hello")
	assert.Equal(t, 12, calibrationCallBlocks)
	assert.Equal(t, minCostBlocks, calibrationCallBlocks, "a real client's hello is the cost floor")

	// A run of no length still makes one call, and counts it at that cost.
	blocks, _ := hmacFor(0)
	assert.Equal(t, calibrationCallBlocks, blocks)
}

// The virtual schedule rests on one invariant: no interval of time is refilled
// twice. A reservation whose clock reading is older than the bucket's last
// charge -- a caller that read the clock and then waited for the lock while
// another went first -- must not move the bucket's time back.
func TestAReservationReadAtAnOlderTimeRefillsNothingTwice(t *testing.T) {
	t.Parallel()

	// 1e6 blocks a second for the process.
	b, clock := testBudget(scanBudgetConfig{NsPerBlock: nsPerBlockForTests, CPUPercent: 25, Procs: 4})

	// Well below the burst, so a refill is not hidden by the cap: 900,000 of
	// 1e6 spent, 100,000 left.
	_, _, v := b.reserve(nil, 100, 9000)
	require.Equal(t, budgetGranted, v)
	require.InDelta(t, 100000, b.globalAvailable(10), 1e-6)

	// A millisecond earlier than that charge: no refill, 120 more spent.
	clock.advance(-time.Millisecond)

	_, _, v = b.reserve(nil, 12, 10)
	require.Equal(t, budgetGranted, v)

	// Ten milliseconds after the first charge: 10,000 of refill since then, and
	// not 11,000 -- the millisecond before it was never the bucket's to refill.
	clock.advance(11 * time.Millisecond)

	assert.InDelta(t, 100000-120+10000, b.globalAvailable(10), 1e-6, "the overlap is refilled once")
}

func TestCalibrationIsClamped(t *testing.T) {
	t.Parallel()

	timer := func(nsPerBlock ...float64) func(time.Duration) (int, time.Duration) {
		calls := 0

		return func(d time.Duration) (int, time.Duration) {
			if d != calibrationRun {
				t.Errorf("a run of %v, not %v", d, calibrationRun)
			}

			ns := nsPerBlock[calls%len(nsPerBlock)]
			calls++

			const blocks = 1025

			return blocks, time.Duration(ns * blocks)
		}
	}

	assert.InDelta(t, 325, measureBlockNanosWith(timer(400, 325, 500)), 1e-9, "the fastest of three runs")
	assert.InDelta(t, minBlockNanos, measureBlockNanosWith(timer(0.001)), 0, "an impossibly fast clock")
	assert.InDelta(t, minBlockNanos, measureBlockNanosWith(timer(0)), 0, "a clock that did not move")
	assert.InDelta(t, maxBlockNanos, measureBlockNanosWith(timer(1e9)), 0, "a run stalled for a second a block")

	runs := 0

	assert.InDelta(t, maxBlockNanos, measureBlockNanosWith(func(time.Duration) (int, time.Duration) {
		runs++

		return 0, time.Millisecond
	}), 0, "no reading at all is the slowest machine, not a division by zero")
	assert.Equal(t, calibrationRuns, runs)

	for in, want := range map[float64]float64{
		math.NaN(): maxBlockNanos, math.Inf(1): maxBlockNanos, math.Inf(-1): minBlockNanos,
		-5: minBlockNanos, 9.99: minBlockNanos, 10: 10, 325: 325, 2000: 2000, 2000.01: maxBlockNanos,
	} {
		assert.InDelta(t, want, clampBlockNanos(in), 0, "clamp(%v)", in)
	}
}

func TestHandshakeBudgetOptsAreValidated(t *testing.T) {
	t.Parallel()

	uintOf := func(v uint) *uint { return &v }

	for _, tc := range []struct {
		name   string
		mode   string
		perIP  *uint
		cpu    uint
		errors string
	}{
		{name: "the zero values"},
		{name: "enforce", mode: "enforce"},
		{name: "observe", mode: "observe"},
		{name: "off", mode: "off"},
		{name: "upper case", mode: "OBSERVE"},
		{name: "per-ip 0", perIP: uintOf(0)},
		{name: "per-ip 1000", perIP: uintOf(1000)},
		{name: "cpu 100", cpu: 100},
		{name: "an unknown mode", mode: "audit", errors: "audit"},
		{name: "per-ip 1001", perIP: uintOf(1001), errors: "1001"},
		{name: "cpu 101", cpu: 101, errors: "101"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			opts, _ := servingOpts(t)
			opts.HandshakeBudgetMode = tc.mode
			opts.HandshakeBudgetPerIPMillis = tc.perIP
			opts.HandshakeBudgetCPUPercent = tc.cpu

			err := opts.valid()

			if tc.errors == "" {
				assert.NoError(t, err)

				return
			}

			require.Error(t, err)
			assert.ErrorContains(t, err, tc.errors)

			_, err = NewProxy(opts)
			assert.Error(t, err, "NewProxy refuses it too")
		})
	}
}

func TestNewProxyBuildsTheBudgetTheOptsAskFor(t *testing.T) {
	t.Parallel()

	uintOf := func(v uint) *uint { return &v }
	procs := float64(runtime.GOMAXPROCS(0))

	for _, tc := range []struct {
		name       string
		mode       string
		perIP      *uint
		cpu        uint
		wantMode   budgetMode
		wantPerIP  float64 // ms a second; 0 is no address bucket
		wantGlobal float64 // percent of the cores
	}{
		{"the defaults", "", nil, 0, budgetEnforce, 50, 25},
		{"observe", "observe", nil, 0, budgetObserve, 50, 25},
		{"off", "off", nil, 0, budgetOff, 50, 25},
		{"per-ip 0 disables the address bucket", "", uintOf(0), 0, budgetEnforce, 0, 25},
		{"set explicitly", "enforce", uintOf(200), 60, budgetEnforce, 200, 60},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			opts, _ := servingOpts(t)
			opts.HandshakeBudgetMode = tc.mode
			opts.HandshakeBudgetPerIPMillis = tc.perIP
			opts.HandshakeBudgetCPUPercent = tc.cpu

			proxy, err := NewProxy(opts)
			require.NoError(t, err)
			t.Cleanup(proxy.Shutdown)

			b := proxy.scanBudget
			require.NotNil(t, b)

			ns := blockNanos()

			assert.Equal(t, tc.wantMode, b.mode)
			assert.Equal(t, tc.wantMode == budgetEnforce, b.enforced())
			assert.InDelta(t, ns, b.nsPerBlock, 0)
			assert.InDelta(t, tc.wantPerIP*1e6/ns, b.perIP.rate, 1e-6, "blocks a second per address")
			assert.InDelta(t, 4*tc.wantPerIP*1e6/ns, b.perIP.burst, 1e-6, "four seconds' worth")
			assert.InDelta(t, tc.wantGlobal/100*procs*1e9/ns, b.global.rate, 1e-3, "blocks a second for the process")
			assert.InDelta(t, tc.wantGlobal/100*procs*1e9/ns, b.global.burst, 1e-3, "one second's worth")
			assert.Equal(t, defaultBudgetMaxWait, b.maxWait)
		})
	}
}
