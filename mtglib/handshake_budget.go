package mtglib

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"math"
	"net"
	"net/netip"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// The FakeTLS door's work budget. A hello no hint matched is verified against
// every hosted secret, one HMAC each, and that scan is the one cost an attacker
// can buy with a single hello: on the bench box about 3.9 us per secret for a
// real 517-byte hello, and up to a hundred times that for the largest hello the
// reader accepts. The budget bounds the CPU those scans may take, in two
// buckets: one per client address, so one source cannot take it all, and one for
// the whole process, which is the real bound -- per-address limits are evaded by
// many addresses and forged behind a PROXY-protocol listener.
//
// Costs are in SHA-256 blocks (see fake.Parsed.Blocks) and rates in blocks a
// second, converted from real CPU time by what a block of the door's own work
// costs, measured once on this machine by timing the verification of a real
// client's hello (see measureBlockNanos): about 340 ns a block on a CPU without
// SHA extensions and about 35 ns on one with them, so a budget in fixed units
// would be wrong by an order of magnitude on one or the other.

const (
	// defaultBudgetPerIPMillis is how much scan CPU one address may spend a
	// second, in milliseconds; maxBudgetPerIPMillis is the most it may be set
	// to.
	defaultBudgetPerIPMillis = 50
	maxBudgetPerIPMillis     = 1000

	// defaultBudgetCPUPercent is the share of the cores the whole process may
	// spend scanning; maxBudgetCPUPercent is the most it may be set to.
	defaultBudgetCPUPercent = 25
	maxBudgetCPUPercent     = 100

	// perIPBurst and globalBurst are how many seconds of refill each bucket
	// holds when full.
	perIPBurst  = 4 * time.Second
	globalBurst = time.Second

	// defaultBudgetMaxWait is the longest a scan may be made to wait for budget.
	// A scan that would have to wait longer is refused, and its hello is
	// fronted at once; one that would not waits, and runs. It smooths a burst of
	// real clients (a restart, a network coming back) into a short queue rather
	// than refusals.
	defaultBudgetMaxWait = 150 * time.Millisecond

	// minCostBlocks is the least one candidate is charged for: what a real
	// client's 517-byte hello costs. A smaller hello is charged as much, so a
	// 100-byte probe cannot get in where a real client would be refused.
	minCostBlocks = 12

	// burstFloorHellos is how many scans of a real client's hello a full
	// bucket can always pay for, however many secrets are hosted: without it a
	// large secret count would make one scan cost more than a whole burst, and
	// nobody would ever be scanned. The floor is in units of minCostBlocks and
	// never of the hello's own size, so a flood of large hellos cannot raise
	// its own cap.
	burstFloorHellos = 4

	// maxBudgetAddresses bounds the address buckets held across both
	// generations. When it is reached a new address gets no bucket of its own
	// -- the process-wide bucket still holds it -- and nothing held is pushed
	// out: pushing out would hand a drained bucket back full.
	maxBudgetAddresses = 32768

	// budgetRotation is how often the older generation of address buckets is
	// dropped. A bucket idle that long has refilled anyway.
	budgetRotation = 30 * time.Minute
)

// budgetMode is what the door does with a scan the budget would refuse.
type budgetMode int

const (
	// budgetEnforce fronts it. The zero value, and the default.
	budgetEnforce budgetMode = iota

	// budgetObserve keeps the same accounting but never waits and never
	// refuses: the door counts what enforce would have done and scans anyway.
	budgetObserve

	// budgetOff has no budget and no scan cap.
	budgetOff
)

// parseBudgetMode reads ProxyOpts.HandshakeBudgetMode.
func parseBudgetMode(value string) (budgetMode, error) {
	switch strings.ToLower(value) {
	case "", "enforce":
		return budgetEnforce, nil
	case "observe":
		return budgetObserve, nil
	case "off":
		return budgetOff, nil
	}

	return budgetEnforce, fmt.Errorf(`unknown handshake budget mode %q: use "enforce", "observe" or "off"`, value)
}

// budgetVerdict is what reserve decided.
type budgetVerdict int

const (
	budgetGranted budgetVerdict = iota
	// budgetDeniedIP: the address's bucket cannot pay within the wait.
	budgetDeniedIP
	// budgetDeniedGlobal: the process-wide bucket cannot.
	budgetDeniedGlobal
	// budgetOversized: the hello is above the scan cap, maxScanBlocks.
	budgetOversized
)

// scanBudgetConfig is how a budget is built. A zero field is the default.
type scanBudgetConfig struct {
	Mode budgetMode

	// PerIPMillis is the per-address refill in milliseconds of scan CPU a
	// second (0 is 50), unless PerIPDisabled turns the address buckets off.
	PerIPMillis   uint
	PerIPDisabled bool

	// CPUPercent is the process-wide refill as a share of Procs cores (0 is
	// 25); Procs is GOMAXPROCS (0 reads it).
	CPUPercent uint
	Procs      int

	// NsPerBlock is what a SHA-256 block costs here (0 is the process's own
	// measurement, blockNanos).
	NsPerBlock float64

	// MaxWait is the longest a scan may wait for budget (0 is 150 ms).
	MaxWait time.Duration
}

// bucketParams are one kind of bucket's refill rate in blocks a second and its
// base burst. A rate of zero is a bucket that is not there.
type bucketParams struct {
	rate  float64
	burst float64
}

// bucketState is one token bucket on a virtual schedule: tokens as of last,
// refilled lazily when next asked. Tokens are float64, so a long idle cannot
// overflow, and may be negative -- a granted scan that had to wait is a debt
// the refill pays off -- but never by more than rate x the wait, since a larger
// debt is refused. A bucket never charged (last is zero) is full.
type bucketState struct {
	tokens float64
	last   time.Time
}

// available is what st holds at now, refilling at rate up to burst. A clock
// that went backwards refills nothing.
func (st *bucketState) available(rate, burst float64, now time.Time) float64 {
	if st.last.IsZero() {
		return burst
	}

	elapsed := now.Sub(st.last).Seconds()
	if elapsed < 0 {
		elapsed = 0
	}

	return math.Min(burst, st.tokens+elapsed*rate)
}

// burstFloor is the least a bucket holds when full for a scan of candidates:
// burstFloorHellos real clients' hellos.
func burstFloor(candidates int) float64 {
	return float64(burstFloorHellos * candidates * minCostBlocks)
}

// scanBudget is the two-bucket budget. One mutex covers the process-wide bucket
// and the address map, so both buckets are reserved together or neither is.
//
// The address map is two generations, like obfuscatedLimiter's, with the two
// differences matchHints has: a full map takes no new address rather than
// rotating, and a hit in the older generation is moved, not copied, so an
// address is counted once.
//
// Every method is safe on a nil receiver, which is "budget off".
type scanBudget struct {
	mode       budgetMode
	now        func() time.Time
	maxWait    time.Duration
	nsPerBlock float64
	perIP      bucketParams
	global     bucketParams

	mu          sync.Mutex
	globalState bucketState
	current     map[netip.Addr]*bucketState
	previous    map[netip.Addr]*bucketState
}

// newScanBudget builds a budget from cfg on the clock now. Its address buckets
// are only rotated by run.
func newScanBudget(cfg scanBudgetConfig, now func() time.Time) *scanBudget {
	nsPerBlock := cfg.NsPerBlock
	if nsPerBlock <= 0 {
		nsPerBlock = blockNanos()
	}

	procs := cfg.Procs
	if procs <= 0 {
		procs = runtime.GOMAXPROCS(0)
	}

	perIPMillis := cfg.PerIPMillis
	if perIPMillis == 0 {
		perIPMillis = defaultBudgetPerIPMillis
	}

	cpuPercent := cfg.CPUPercent
	if cpuPercent == 0 {
		cpuPercent = defaultBudgetCPUPercent
	}

	maxWait := cfg.MaxWait
	if maxWait <= 0 {
		maxWait = defaultBudgetMaxWait
	}

	// Real CPU time a second, divided by what a block costs.
	var perIPRate float64
	if !cfg.PerIPDisabled {
		perIPRate = float64(perIPMillis) * float64(time.Millisecond) / nsPerBlock
	}

	globalRate := float64(cpuPercent) / 100 * float64(procs) * float64(time.Second) / nsPerBlock

	return &scanBudget{
		mode:       cfg.Mode,
		now:        now,
		maxWait:    maxWait,
		nsPerBlock: nsPerBlock,
		perIP:      bucketParams{rate: perIPRate, burst: perIPRate * perIPBurst.Seconds()},
		global:     bucketParams{rate: globalRate, burst: globalRate * globalBurst.Seconds()},
		current:    make(map[netip.Addr]*bucketState),
	}
}

// run rotates the address buckets until ctx is done.
func (b *scanBudget) run(ctx context.Context) {
	ticker := time.NewTicker(budgetRotation)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			b.rotate()
		}
	}
}

// rotate drops the older generation of address buckets and demotes the current
// one.
func (b *scanBudget) rotate() {
	if b == nil {
		return
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	b.previous = b.current
	b.current = make(map[netip.Addr]*bucketState)
}

// enforced reports whether a refusal is acted on: enforce mode, and nothing
// else.
func (b *scanBudget) enforced() bool {
	return b != nil && b.mode == budgetEnforce
}

// blockNanos is what the budget believes one SHA-256 block costs, in
// nanoseconds, as /stats reports it: the process's calibrated reading, or an
// injected one. A nil budget has none and says zero.
func (b *scanBudget) blockNanos() float64 {
	if b == nil {
		return 0
	}

	return b.nsPerBlock
}

// oversized reports whether a hello of blocks is above the scan cap, which only
// a budget that is on has.
func (b *scanBudget) oversized(blocks int) bool {
	return b != nil && b.mode != budgetOff && blocks > maxScanBlocks
}

// burstFor is a bucket's burst for a scan of candidates: its base burst, or the
// floor if that is more.
func (b *scanBudget) burstFor(p bucketParams, candidates int) float64 {
	return math.Max(p.burst, burstFloor(candidates))
}

// reserve charges the scan of candidates candidates for a hello of blocks
// blocks from ip, against ip's bucket and the process-wide one, and returns
// how long the scan must wait for them to have paid for it.
//
// The scan is refused -- and neither bucket changes -- when either would have to
// wait longer than the budget's MaxWait: budgetDeniedIP when ip's bucket is the
// one (it is asked first), budgetDeniedGlobal otherwise. A hello above the scan
// cap is budgetOversized. An address that does not stand for one place (see
// hintKey), or that the full map has no bucket for, is held to the process-wide
// bucket alone.
//
// In observe mode the accounting is the same and wait is always zero. A budget
// that is off grants everything and charges nothing, whatever the size.
func (b *scanBudget) reserve(ip net.IP, blocks, candidates int) (*scanReservation, time.Duration, budgetVerdict) {
	if b == nil || b.mode == budgetOff {
		return nil, 0, budgetGranted
	}

	if blocks > maxScanBlocks {
		return nil, 0, budgetOversized
	}

	if candidates <= 0 {
		return nil, 0, budgetGranted
	}

	cost := float64(candidates) * float64(min(max(blocks, minCostBlocks), maxScanBlocks))

	var (
		key   netip.Addr
		keyed bool
	)

	if b.perIP.rate > 0 {
		key, keyed = hintKey(ip)
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	// Read under the lock, so reservations commit in the order they read the
	// clock; the commit below is monotone as well, for a clock that is not.
	now := b.now()

	var (
		address *bucketState
		isNew   bool
		charges [2]budgetCharge
		n       int
		wait    float64 // seconds: the longer of the two buckets' shortfalls
	)

	if keyed {
		address, isNew = b.addressLocked(key)
	}

	if address != nil {
		charge, delay, ok := b.check(address, b.perIP, candidates, cost, now)
		if !ok {
			return nil, 0, budgetDeniedIP
		}

		charges[n], n, wait = charge, n+1, delay
	}

	charge, delay, ok := b.check(&b.globalState, b.global, candidates, cost, now)
	if !ok {
		return nil, 0, budgetDeniedGlobal
	}

	charges[n], n, wait = charge, n+1, max(wait, delay)

	// Both can pay: only now does anything change.
	if isNew {
		b.current[key] = address
	}

	// tokens is the level as of the later of now and the bucket's own time
	// (available refills nothing for a now behind it), and a bucket's time
	// never goes back: moving it back would refill that stretch a second time.
	for _, c := range charges[:n] {
		c.bucket.tokens = c.after

		if now.After(c.bucket.last) {
			c.bucket.last = now
		}
	}

	res := &scanReservation{budget: b, charges: charges, n: n}

	if b.mode == budgetObserve {
		return res, 0, budgetGranted
	}

	return res, time.Duration(math.Ceil(wait * float64(time.Second))), budgetGranted
}

// check works out what charging cost to st would leave and how many seconds
// of refill the shortfall is, without changing st; ok is false when that is
// longer than the wait allows.
func (b *scanBudget) check(
	st *bucketState, p bucketParams, candidates int, cost float64, now time.Time,
) (budgetCharge, float64, bool) {
	burst := b.burstFor(p, candidates)
	after := st.available(p.rate, burst, now) - cost
	charge := budgetCharge{bucket: st, cost: cost, burst: burst, after: after}

	if after >= 0 {
		return charge, 0, true
	}

	if -after > p.rate*b.maxWait.Seconds() {
		return budgetCharge{}, 0, false
	}

	return charge, -after / p.rate, true
}

// addressLocked finds key's bucket in either generation, moving a hit in the
// older one to the current one. When key has none it returns a new, full,
// not-yet-stored bucket -- stored only if the reservation is granted -- or nil
// when the map is full.
func (b *scanBudget) addressLocked(key netip.Addr) (*bucketState, bool) {
	if st, ok := b.current[key]; ok {
		return st, false
	}

	if st, ok := b.previous[key]; ok {
		// Moved, not copied: the address is counted once either way.
		delete(b.previous, key)
		b.current[key] = st

		return st, false
	}

	if len(b.current)+len(b.previous) >= maxBudgetAddresses {
		return nil, false
	}

	return &bucketState{}, true
}

// budgetCharge is one bucket's part of a reservation: what was taken from it,
// and its burst at the time, which a refund is capped at. after is the level
// the charge left, used while the reservation is being made.
type budgetCharge struct {
	bucket *bucketState
	cost   float64
	burst  float64
	after  float64
}

// scanReservation is what one scan was charged. It is settled once: a success
// refunds it in full, anything else keeps it. The refund goes to the bucket
// objects that were charged, not to whatever bucket the address maps to now, so
// a rotation in between cannot send it astray.
type scanReservation struct {
	budget  *scanBudget
	charges [2]budgetCharge
	n       int
	settled bool
}

// settle ends the reservation: success refunds every charge in full, capped at
// the bucket's burst; failure keeps them. Only the first call does anything,
// and a nil reservation (nothing was charged) is a no-op.
func (r *scanReservation) settle(success bool) {
	if r == nil {
		return
	}

	r.budget.mu.Lock()
	defer r.budget.mu.Unlock()

	if r.settled {
		return
	}

	r.settled = true

	if !success {
		return
	}

	for _, c := range r.charges[:r.n] {
		c.bucket.tokens = math.Min(c.burst, c.bucket.tokens+c.cost)
	}
}

// Calibration: what one block of the door's own work costs on this machine.

const (
	// minBlockNanos and maxBlockNanos bound a measurement. One verification of
	// a 517-byte hello -- the call the calibration times -- costs about 35 ns a
	// block on a CPU with SHA extensions and about 340 ns on one without (the
	// bench box: 4.1 us a candidate at 12 blocks). A reading outside these
	// bounds is a disturbed run, not a machine.
	minBlockNanos = 10.0
	maxBlockNanos = 2000.0

	// calibrationRuns are taken and the fastest kept: a run can only be slowed
	// by whatever else the machine is doing, never sped up.
	calibrationRuns = 3
	calibrationRun  = 4 * time.Millisecond

	// calibrationHelloSize is the hello one timed call verifies: a real
	// client's, as one record.
	calibrationHelloSize = 517

	// calibrationCallBlocks is what the door charges one candidate for that
	// hello, counted the way fake.Parsed.Blocks counts: the key's inner pad
	// block, the record and SHA-256's 9 bytes of padding, and the outer hash's
	// two. It is minCostBlocks, the cost floor.
	calibrationCallBlocks = 3 + (calibrationHelloSize+9+sha256.BlockSize-1)/sha256.BlockSize
)

// calibration is a measurement taken once and shared. runs counts how many were
// taken, which is one.
type calibration struct {
	once    sync.Once
	measure func() float64
	runs    atomic.Int32
	ns      float64
}

// value is the measurement, taken on the first call; first reports whether this
// call is the one that took it.
func (c *calibration) value() (ns float64, first bool) {
	c.once.Do(func() {
		c.ns = c.measure()
		c.runs.Add(1)
		first = true
	})

	return c.ns, first
}

// processCalibration is the process's one measurement: every proxy built shares
// it, so a test binary that builds hundreds measures once.
var processCalibration = &calibration{measure: measureBlockNanos}

// blockNanos is what a block of the door's work costs on this machine in ns,
// measured the first time anything asks.
func blockNanos() float64 {
	ns, _ := processCalibration.value()

	return ns
}

// measureBlockNanos times the door's own work here: the fastest of three runs
// of about 4 ms, clamped to 10 ns to 2 us a block.
//
// What is timed is the plain HMAC, the slower of the door's two ways to verify
// a candidate. Where the door verifies with precomputed key pads, a block
// really costs less than the budget believes, so the budget errs strict, never
// loose. The same holds for a hello larger than 517 bytes (more blocks for the
// same per-call overhead) and a smaller one (charged the cost floor of 12).
func measureBlockNanos() float64 {
	return measureBlockNanosWith(hmacFor)
}

// measureBlockNanosWith is measureBlockNanos with the timed run supplied: each
// call works for about the given time and reports the blocks it did and the
// time it took.
func measureBlockNanosWith(run func(time.Duration) (blocks int, elapsed time.Duration)) float64 {
	best := math.Inf(1)

	for range calibrationRuns {
		blocks, elapsed := run(calibrationRun)
		if blocks <= 0 {
			continue
		}

		if ns := float64(elapsed) / float64(blocks); ns < best {
			best = ns
		}
	}

	return clampBlockNanos(best)
}

// clampBlockNanos bounds a measurement. A run with no reading at all counts as
// the slowest machine: the budget is then the strictest it can be, never
// unbounded.
func clampBlockNanos(ns float64) float64 {
	switch {
	case math.IsNaN(ns), ns > maxBlockNanos:
		return maxBlockNanos
	case ns < minBlockNanos:
		return minBlockNanos
	}

	return ns
}

// hmacFor verifies a 517-byte hello the way the door's plain path does -- a
// fresh HMAC-SHA256 under a 16-byte key, over the whole record -- over and over
// for at least d (at least once), and reports the blocks the budget charges for
// that, calibrationCallBlocks a call, and how long it took. Each digest is
// written back into the hello, so no call can be skipped as unused.
func hmacFor(d time.Duration) (int, time.Duration) {
	key := make([]byte, SecretKeyLength)
	hello := make([]byte, calibrationHelloSize)

	var blocks int

	started := time.Now()

	for {
		mac := hmac.New(sha256.New, key)
		mac.Write(hello)
		copy(hello, mac.Sum(nil))

		blocks += calibrationCallBlocks

		if elapsed := time.Since(started); elapsed >= d {
			return blocks, elapsed
		}
	}
}
