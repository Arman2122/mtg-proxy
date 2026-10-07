package mtglib

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The handshake budget at the FakeTLS door, end to end through ServeConn. The
// budget runs on a clock the test moves (budgetClock), so a drained bucket stays
// drained until the test says time has passed; the waits the door does are real
// timers. Connections from dialProxy are loopback, which is unkeyed: they meet
// the process-wide bucket only. dialProxyFrom stamps an address of the test's
// choosing, which has a bucket of its own.

// budgetHarness is the ee governance harness with a budget built from cfg. The
// harness is a Proxy literal, which has none.
func budgetHarness(
	t *testing.T, secrets map[string]Secret, limits map[string]SecretLimits, cfg scanBudgetConfig,
) (*entryHarness, *budgetClock) {
	t.Helper()

	h := fakeTLSDoor().harness(t, secrets, limits)
	clock := newBudgetClock()
	h.proxy.scanBudget = newScanBudget(cfg, clock.now)

	return h, clock
}

// roomyBudget is enforce with room for every honest hello a test sends: 1e6
// blocks a second for the process, 50,000 for each address.
func roomyBudget() scanBudgetConfig {
	return scanBudgetConfig{NsPerBlock: nsPerBlockForTests, CPUPercent: 25, Procs: 4}
}

// budgetTally is everything the door counts.
type budgetTally struct {
	verifications, hinted, scanned, unmatched, deniedIP, deniedGlobal, oversized, overBudgetMatched int64
}

func budgetTallyOf(p *Proxy) budgetTally {
	s := &p.fakeStats

	return budgetTally{
		verifications:     s.verifications.Load(),
		hinted:            s.hinted.Load(),
		scanned:           s.scanned.Load(),
		unmatched:         s.unmatched.Load(),
		deniedIP:          s.deniedIP.Load(),
		deniedGlobal:      s.deniedGlobal.Load(),
		oversized:         s.oversized.Load(),
		overBudgetMatched: s.overBudgetMatched.Load(),
	}
}

func (d budgetTally) minus(o budgetTally) budgetTally {
	return budgetTally{
		verifications:     d.verifications - o.verifications,
		hinted:            d.hinted - o.hinted,
		scanned:           d.scanned - o.scanned,
		unmatched:         d.unmatched - o.unmatched,
		deniedIP:          d.deniedIP - o.deniedIP,
		deniedGlobal:      d.deniedGlobal - o.deniedGlobal,
		oversized:         d.oversized - o.oversized,
		overBudgetMatched: d.overBudgetMatched - o.overBudgetMatched,
	}
}

// budgetLevels is what the process-wide bucket and place's bucket hold now, for
// a scan of every candidate the door has. An address with no bucket yet reads
// as the full one it would be given.
func budgetLevels(t *testing.T, h *entryHarness, place string) (global, address float64) {
	t.Helper()

	b := h.proxy.scanBudget
	candidates := len(h.proxy.secrets.Load().cands)

	address, held := b.addressAvailable(net.ParseIP(place), candidates)
	if !held {
		address = b.burstFor(b.perIP, candidates)
	}

	return b.globalAvailable(candidates), address
}

// coverSite is a cover site that records what each fronted connection
// delivered to it, in full: it reads to EOF and answers nothing.
type coverSite struct {
	got chan []byte
}

func newCoverSite(t *testing.T, h *entryHarness) *coverSite {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	t.Cleanup(func() { listener.Close() }) //nolint: errcheck

	h.proxy.domainFrontingHost = "127.0.0.1"
	h.proxy.domainFrontingPort = listener.Addr().(*net.TCPAddr).Port

	site := &coverSite{got: make(chan []byte, 16)}

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}

			go func() {
				defer conn.Close() //nolint: errcheck

				conn.SetReadDeadline(time.Now().Add(10 * time.Second)) //nolint: errcheck

				received, _ := io.ReadAll(conn)
				site.got <- received
			}()
		}
	}()

	return site
}

// front sends wire to the door from loopback, ends the client's side, and
// returns everything the cover site received for it.
func (c *coverSite) front(t *testing.T, h *entryHarness, wire []byte) []byte {
	t.Helper()

	client, done := h.dialProxy(t, nil)

	_, err := client.Write(wire)
	require.NoError(t, err)
	require.NoError(t, client.(*net.TCPConn).CloseWrite())

	var received []byte

	select {
	case received = <-c.got:
	case <-time.After(5 * time.Second):
		require.FailNow(t, "the cover site received nothing: the hello was not fronted")
	}

	require.True(t, govAwait(done, govDenyBudget))

	return received
}

// refuseLoopback is refuseFrom for a loopback client.
func refuseLoopback(t *testing.T, h *entryHarness, key [SecretKeyLength]byte) {
	t.Helper()

	client, done := h.dialProxy(t, nil)
	fakeTLSDoor().openEntry(t, client, key)

	require.True(t, govAwait(done, govDenyBudget), "the hello must be refused, not relayed")
}

// A hello refused by the budget is fronted through the same call as a hello
// that matched nothing: the cover site gets the same bytes, which are the
// client's own.
func TestARefusedHelloIsFrontedLikeANoMatch(t *testing.T) {
	t.Parallel()

	ec := fakeTLSDoor()

	// 1% of one core at 1 us a block: 10,000 blocks a second, so the bucket
	// drains in a few hundred reservations.
	h, _ := budgetHarness(t, map[string]Secret{"alice": ec.secret(t)}, nil,
		scanBudgetConfig{NsPerBlock: nsPerBlockForTests, CPUPercent: 1, Procs: 1})
	cover := newCoverSite(t, h)

	hello := fakeTLSClientHello(t, ec.secret(t).Key, govCoverHost, bytes.Repeat([]byte{0x5c}, 32))

	before := budgetTallyOf(h.proxy)
	scanned := cover.front(t, h, hello)
	afterScan := budgetTallyOf(h.proxy)

	require.Equal(t, budgetTally{verifications: 1, unmatched: 1}, afterScan.minus(before),
		"with budget to spare the hello is scanned and matches nothing")

	require.Equal(t, budgetDeniedGlobal, drainBudget(t, h.proxy.scanBudget, nil, 12, 1))

	refused := cover.front(t, h, hello)

	assert.Equal(t, budgetTally{deniedGlobal: 1}, budgetTallyOf(h.proxy).minus(afterScan),
		"over budget: refused once, before a single verification")
	assert.Equal(t, hello, scanned, "the cover site gets the client's bytes")
	assert.Equal(t, scanned, refused, "and the same bytes either way")
	assert.Equal(t, 2, h.events.frontings())
}

// Review Focus 6: a charge is refunded only when the whole handshake succeeds.
// A replay of a captured valid hello matched a secret and keeps its charge.
func TestAReplayedValidHelloKeepsItsCharge(t *testing.T) {
	t.Parallel()

	const (
		place = "198.51.100.40"
		cost  = 1 * 12
	)

	ec := fakeTLSDoor()
	alice := ec.secret(t)
	h, _ := budgetHarness(t, map[string]Secret{"alice": alice}, nil, roomyBudget())

	global0, address0 := budgetLevels(t, h, place)

	connectFrom(t, h, ec, tcpFrom(place, 51001), "alice", alice.Key)

	global1, address1 := budgetLevels(t, h, place)
	require.InDelta(t, global0, global1, 0, "the control: a whole success is refunded in full")
	require.InDelta(t, address0, address1, 0)

	// The original, from loopback and straight through the door: it is seen,
	// and the copy below is a replay.
	hello := ec.clientHello(t, alice.Key, bytes.Repeat([]byte{0x6a}, 32))

	_, ok := h.fakeTLSAttempt(t, hello)
	require.True(t, ok)

	global2, address2 := budgetLevels(t, h, place)

	client, done := dialProxyFrom(t, h, nil, tcpFrom(place, 51002))

	_, err := client.Write(hello)
	require.NoError(t, err)
	require.True(t, govAwait(done, govDenyBudget))
	require.Equal(t, 1, h.events.replays(), "refused as a replay")

	global3, address3 := budgetLevels(t, h, place)
	assert.InDelta(t, global2-cost, global3, 1e-9, "the replay keeps its charge")
	assert.InDelta(t, address2-cost, address3, 1e-9, "on its address too")
}

func TestADeniedUserKeepsItsCharge(t *testing.T) {
	t.Parallel()

	const (
		place = "198.51.100.41"
		cost  = 2 * 12 // two candidates
	)

	ec := fakeTLSDoor()
	alice, bob := ec.secret(t), ec.secret(t)
	h, _ := budgetHarness(t, map[string]Secret{"alice": alice, "bob": bob},
		map[string]SecretLimits{"alice": {Disabled: true}}, roomyBudget())

	global0, address0 := budgetLevels(t, h, place)

	connectFrom(t, h, ec, tcpFrom(place, 51101), "bob", bob.Key)

	global1, address1 := budgetLevels(t, h, place)
	require.InDelta(t, global0, global1, 0, "the control: bob is admitted and refunded")
	require.InDelta(t, address0, address1, 0)

	assert.Equal(t, doorTally{verifications: 1, scanned: 1},
		refusedFrom(t, h, tcpFrom(place, 51102), alice.Key), "alice matched, and counts as her match")
	require.Equal(t, 1, h.events.frontings(), "refused by her limit")

	global2, address2 := budgetLevels(t, h, place)
	assert.InDelta(t, global1-cost, global2, 1e-9, "a disabled user keeps the charge")
	assert.InDelta(t, address1-cost, address2, 1e-9)
}

func TestAnIPLimitRefusedUserKeepsItsCharge(t *testing.T) {
	t.Parallel()

	const (
		held    = "198.51.100.42"
		refused = "198.51.100.43"
		cost    = 1 * 12
	)

	ec := fakeTLSDoor()
	alice := ec.secret(t)
	h, _ := budgetHarness(t, map[string]Secret{"alice": alice},
		map[string]SecretLimits{"alice": {IPLimit: 1}}, roomyBudget())

	global0, heldAddress0 := budgetLevels(t, h, held)
	_, refusedAddress0 := budgetLevels(t, h, refused)

	first, firstDone := dialProxyFrom(t, h, ec.policy, tcpFrom(held, 51201))
	firstUp := connectThrough(t, ec, h, first, "alice", alice.Key)

	defer endStream(first, firstUp, firstDone)

	global1, heldAddress1 := budgetLevels(t, h, held)
	require.InDelta(t, global0, global1, 0, "the control: the first place is admitted and refunded")
	require.InDelta(t, heldAddress0, heldAddress1, 0)

	refuseFrom(t, ec, h, alice.Key, tcpFrom(refused, 51202))
	require.EqualValues(t, 1, h.proxy.stats.users["alice"].ipLimitRefused.Load(), "refused by the address limit")

	global2, heldAddress2 := budgetLevels(t, h, held)
	_, refusedAddress2 := budgetLevels(t, h, refused)

	assert.InDelta(t, global1-cost, global2, 1e-9, "an address-limited user keeps the charge")
	assert.InDelta(t, refusedAddress0-cost, refusedAddress2, 1e-9, "on the address it came from")
	assert.InDelta(t, heldAddress1, heldAddress2, 0, "and nowhere else")
}

// The shared-address scenario the budget has to survive: a phone behind a NAT
// keeps retrying a secret that was removed, until the NAT's bucket is spent.
// The NAT's other users are not locked out: one with a hint gets straight in,
// one without is fronted while the bucket is spent and gets in on a retry, after
// a short wait.
func TestSharedAddressStaleSecretDoesNotLockOutNewUsers(t *testing.T) {
	t.Parallel()

	const nat = "198.51.100.60"

	ec := fakeTLSDoor()
	secrets := map[string]Secret{"alice": ec.secret(t), "bob": ec.secret(t), "carol": ec.secret(t), "dave": ec.secret(t)}

	for i := range 96 {
		secrets[fmt.Sprintf("d%02d", i)] = ec.secret(t)
	}

	// 1,000 blocks a second for the address, at most 50 ms (50 blocks) of
	// debt; 100 candidates put the burst at its floor, 4,800 blocks, which is
	// four scans. The process-wide bucket is out of reach.
	cfg := scanBudgetConfig{
		NsPerBlock: nsPerBlockForTests, PerIPMillis: 1, CPUPercent: 100, Procs: 1000, MaxWait: 50 * time.Millisecond,
	}

	h, clock := budgetHarness(t, secrets, nil, cfg)
	h.proxy.hints = newMatchHints(h.proxy.ctx)

	port := 52000
	from := func() net.Addr {
		port++

		return tcpFrom(nat, port)
	}

	connectFrom(t, h, ec, from(), "bob", secrets["bob"].Key)
	connectFrom(t, h, ec, from(), "dave", secrets["dave"].Key)

	stale := secrets["dave"].Key

	delete(secrets, "dave")
	reloadSecrets(t, h.proxy, secrets)

	// dave's phone retries: each retry is a full scan that matches nothing, and
	// keeps its charge, until the NAT's bucket refuses.
	retries := 0

	for ; retries < 20; retries++ {
		got := refusedFrom(t, h, from(), stale)
		if h.proxy.fakeStats.deniedIP.Load() > 0 {
			assert.Zero(t, got.unmatched, "the refused retry is not scanned")

			break
		}

		require.EqualValues(t, 1, got.unmatched, "retry %d is scanned and matches nothing", retries)
	}

	require.EqualValues(t, 1, h.proxy.fakeStats.deniedIP.Load(), "the stale phone spends the NAT's bucket")
	assert.Equal(t, 4, retries, "the burst floor is four scans")

	// bob has a hint: verified against it first, exempt, in at once.
	assert.Equal(t, doorTally{verifications: 1, hinted: 1},
		connectFrom(t, h, ec, from(), "bob", secrets["bob"].Key))

	// carol has none. Her first hello finds the bucket spent: fronted, after
	// trying the one hint the NAT holds that still names a candidate.
	before := budgetTallyOf(h.proxy)

	refuseFrom(t, ec, h, secrets["carol"].Key, from())

	assert.Equal(t, budgetTally{verifications: 1, deniedIP: 1}, budgetTallyOf(h.proxy).minus(before))

	// A moment later her retry. The bucket has refilled to 25 blocks short of
	// what her scan costs: 25 ms of refill, which she waits, and she is in.
	remaining := len(h.proxy.secrets.Load().cands) - 1
	cost := float64(remaining * 12)
	_, level := budgetLevels(t, h, nat)

	clock.advance(time.Duration((cost - level - 25) / 1000 * float64(time.Second)))

	started := time.Now()

	// bob's hint, then the scan over the rest: alice, then carol.
	assert.Equal(t, doorTally{verifications: 3, scanned: 1},
		connectFrom(t, h, ec, from(), "carol", secrets["carol"].Key), "admitted on her second attempt")
	assert.GreaterOrEqual(t, time.Since(started), 20*time.Millisecond, "after the wait")
}

// Review Focus 3: a hello that names no hosted cover site is fronted at the SNI
// gate, before the budget: it costs nothing and counts nothing.
func TestAHelloThatFailsTheSNIGateCostsNoBudget(t *testing.T) {
	t.Parallel()

	const place = "203.0.113.70"

	ec := fakeTLSDoor()
	alice := ec.secret(t)
	h, _ := budgetHarness(t, map[string]Secret{"alice": alice}, nil, roomyBudget())

	global0, _ := budgetLevels(t, h, place)
	before := budgetTallyOf(h.proxy)

	client, done := dialProxyFrom(t, h, nil, tcpFrom(place, 53001))

	_, err := client.Write(fakeTLSClientHello(t, alice.Key, "elsewhere.example.org", bytes.Repeat([]byte{0x71}, 32)))
	require.NoError(t, err)
	require.True(t, govAwait(done, govDenyBudget))

	require.Equal(t, 1, h.events.frontings(), "fronted at the gate")

	global1, _ := budgetLevels(t, h, place)
	assert.InDelta(t, global0, global1, 0, "the process-wide bucket is untouched")
	assert.Zero(t, h.proxy.scanBudget.addresses(), "and the address never got one")
	assert.Equal(t, budgetTally{}, budgetTallyOf(h.proxy).minus(before), "and nothing is counted")
}

func TestHintedClientsAreExemptFromTheBudget(t *testing.T) {
	t.Parallel()

	const place = "203.0.113.71"

	ec := fakeTLSDoor()
	alice, bob := ec.secret(t), ec.secret(t)
	h, _ := budgetHarness(t, map[string]Secret{"alice": alice, "bob": bob}, nil, roomyBudget())
	h.proxy.hints = newMatchHints(h.proxy.ctx)

	connectFrom(t, h, ec, tcpFrom(place, 54001), "alice", alice.Key)

	// Both buckets spent, in units of what bob's scan below costs (one
	// candidate once alice's hint is tried): the address's, then the process's.
	b := h.proxy.scanBudget
	require.Equal(t, budgetDeniedIP, drainBudget(t, b, net.ParseIP(place), 12, 1))
	require.Equal(t, budgetDeniedGlobal, drainBudget(t, b, nil, 12, 1))

	global0, address0 := budgetLevels(t, h, place)
	before := budgetTallyOf(h.proxy)

	assert.Equal(t, doorTally{verifications: 1, hinted: 1},
		connectFrom(t, h, ec, tcpFrom(place, 54002), "alice", alice.Key), "a hinted client gets in regardless")
	assert.Equal(t, budgetTally{verifications: 1, hinted: 1}, budgetTallyOf(h.proxy).minus(before), "uncharged and unrefused")

	global1, address1 := budgetLevels(t, h, place)
	assert.InDelta(t, global0, global1, 0)
	assert.InDelta(t, address0, address1, 0)

	// The control: bob, from the same place with no hint of his own, is refused
	// by the address's bucket after alice's hint is tried.
	before = budgetTallyOf(h.proxy)

	refuseFrom(t, ec, h, bob.Key, tcpFrom(place, 54003))

	assert.Equal(t, budgetTally{verifications: 1, deniedIP: 1}, budgetTallyOf(h.proxy).minus(before))
}

// The spec's table (section 5): in enforce mode every hello past the SNI gate
// moves exactly one of the door's outcome counters.
func TestEveryOutcomeMovesExactlyOneCounter(t *testing.T) {
	t.Parallel()

	const (
		place = "203.0.113.80"
		other = "203.0.113.81"
	)

	ec := fakeTLSDoor()

	outcomes := func(p *Proxy) map[string]int64 {
		s := &p.fakeStats

		return map[string]int64{
			"hinted":              s.hinted.Load(),
			"scanned":             s.scanned.Load(),
			"unmatched":           s.unmatched.Load(),
			"denied_ip":           s.deniedIP.Load(),
			"denied_global":       s.deniedGlobal.Load(),
			"oversized":           s.oversized.Load(),
			"over_budget_matched": s.overBudgetMatched.Load(),
		}
	}

	for _, tc := range []struct {
		name   string
		limits SecretLimits
		moves  string // "" is none: the hello never got past the gate
		setup  func(t *testing.T, h *entryHarness, alice Secret)
		act    func(t *testing.T, h *entryHarness, alice Secret)
	}{
		{
			name:  "a hinted match",
			moves: "hinted",
			setup: func(t *testing.T, h *entryHarness, alice Secret) {
				t.Helper()
				connectFrom(t, h, ec, tcpFrom(place, 55001), "alice", alice.Key)
			},
			act: func(t *testing.T, h *entryHarness, alice Secret) {
				t.Helper()
				connectFrom(t, h, ec, tcpFrom(place, 55002), "alice", alice.Key)
			},
		},
		{
			name:  "a scanned match",
			moves: "scanned",
			act: func(t *testing.T, h *entryHarness, alice Secret) {
				t.Helper()
				connectFrom(t, h, ec, tcpFrom(place, 55003), "alice", alice.Key)
			},
		},
		{
			name:  "no match",
			moves: "unmatched",
			act: func(t *testing.T, h *entryHarness, _ Secret) {
				t.Helper()
				refusedFrom(t, h, tcpFrom(place, 55004), ec.secret(t).Key)
			},
		},
		{
			name:  "refused by the address's bucket",
			moves: "denied_ip",
			setup: func(t *testing.T, h *entryHarness, _ Secret) {
				t.Helper()
				// In units of the scan below: two candidates, the short hello.
				require.Equal(t, budgetDeniedIP, drainBudget(t, h.proxy.scanBudget, net.ParseIP(place), 12, 2))
			},
			act: func(t *testing.T, h *entryHarness, alice Secret) {
				t.Helper()
				refuseFrom(t, ec, h, alice.Key, tcpFrom(place, 55005))
			},
		},
		{
			name:  "refused by the process-wide bucket",
			moves: "denied_global",
			setup: func(t *testing.T, h *entryHarness, _ Secret) {
				t.Helper()
				require.Equal(t, budgetDeniedGlobal, drainBudget(t, h.proxy.scanBudget, nil, 12, 2))
			},
			act: func(t *testing.T, h *entryHarness, alice Secret) {
				t.Helper()
				refuseFrom(t, ec, h, alice.Key, tcpFrom(other, 55006))
			},
		},
		{
			name:  "above the scan cap",
			moves: "oversized",
			act: func(t *testing.T, h *entryHarness, alice Secret) {
				t.Helper()
				refuseFrom(t, ec.withHelloSize(7992), h, alice.Key, tcpFrom(place, 55007))
			},
		},
		{
			name:  "a replay after a match",
			moves: "scanned",
			setup: func(t *testing.T, h *entryHarness, alice Secret) {
				t.Helper()
				_, ok := h.fakeTLSAttempt(t, ec.clientHello(t, alice.Key, bytes.Repeat([]byte{0x7a}, 32)))
				require.True(t, ok)
			},
			act: func(t *testing.T, h *entryHarness, alice Secret) {
				t.Helper()

				client, done := dialProxyFrom(t, h, nil, tcpFrom(place, 55008))

				_, err := client.Write(ec.clientHello(t, alice.Key, bytes.Repeat([]byte{0x7a}, 32)))
				require.NoError(t, err)
				require.True(t, govAwait(done, govDenyBudget))
				require.Equal(t, 1, h.events.replays())
			},
		},
		{
			name:   "a disabled user after a match",
			limits: SecretLimits{Disabled: true},
			moves:  "scanned",
			act: func(t *testing.T, h *entryHarness, alice Secret) {
				t.Helper()
				refusedFrom(t, h, tcpFrom(place, 55009), alice.Key)
			},
		},
		{
			name:   "an ip-limit-refused user after a match",
			limits: SecretLimits{IPLimit: 1},
			moves:  "scanned",
			setup: func(t *testing.T, h *entryHarness, alice Secret) {
				t.Helper()

				first, done := dialProxyFrom(t, h, ec.policy, tcpFrom(other, 55010))
				up := connectThrough(t, ec, h, first, "alice", alice.Key)

				t.Cleanup(func() { endStream(first, up, done) })
			},
			act: func(t *testing.T, h *entryHarness, alice Secret) {
				t.Helper()
				refuseFrom(t, ec, h, alice.Key, tcpFrom(place, 55011))
			},
		},
		{
			name:  "a hello that fails the SNI gate",
			moves: "",
			act: func(t *testing.T, h *entryHarness, alice Secret) {
				t.Helper()

				client, done := dialProxyFrom(t, h, nil, tcpFrom(place, 55012))

				_, err := client.Write(fakeTLSClientHello(t, alice.Key, "elsewhere.example.org", make([]byte, 32)))
				require.NoError(t, err)
				require.True(t, govAwait(done, govDenyBudget))
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			alice := ec.secret(t)
			h, _ := budgetHarness(t, map[string]Secret{"alice": alice, "zed": ec.secret(t)},
				map[string]SecretLimits{"alice": tc.limits}, roomyBudget())
			h.proxy.hints = newMatchHints(h.proxy.ctx)

			if tc.setup != nil {
				tc.setup(t, h, alice)
			}

			before := outcomes(h.proxy)

			tc.act(t, h, alice)

			after := outcomes(h.proxy)
			want := make(map[string]int64, len(before))

			for name, value := range before {
				want[name] = value
			}

			if tc.moves != "" {
				want[tc.moves]++
			}

			assert.Equal(t, want, after)
		})
	}
}

// observe mode's whole job: during a flood, show the legitimate hellos enforce
// would have fronted. Every would-refuse is counted with the scan it did anyway.
func TestObserveReportsOverBudgetMatchedDuringAFlood(t *testing.T) {
	t.Parallel()

	ec := fakeTLSDoor()

	t.Run("an address's bucket", func(t *testing.T) {
		t.Parallel()

		const place = "203.0.113.90"

		secrets, name := hostedAmongDecoys(t, ec, 100, "last")

		// 1,000 blocks a second for the address; 100 candidates put its burst
		// at the floor, four scans.
		h, _ := budgetHarness(t, secrets, nil, scanBudgetConfig{
			Mode: budgetObserve, NsPerBlock: nsPerBlockForTests, PerIPMillis: 1, CPUPercent: 100, Procs: 1000,
		})

		stranger := ec.secret(t).Key
		port := 56000

		for flood := 1; ; flood++ {
			require.LessOrEqual(t, flood, 20, "the flood never went over budget")

			port++
			before := budgetTallyOf(h.proxy)

			refusedFrom(t, h, tcpFrom(place, port), stranger)

			got := budgetTallyOf(h.proxy).minus(before)
			require.EqualValues(t, 1, got.unmatched, "flood hello %d is scanned, over budget or not", flood)
			require.EqualValues(t, 100, got.verifications)

			if got.deniedIP > 0 {
				assert.Equal(t, 5, flood, "four scans fit, the fifth is over")

				break
			}
		}

		before := budgetTallyOf(h.proxy)

		connectFrom(t, h, ec, tcpFrom(place, port+1), name, secrets[name].Key)

		assert.Equal(t, budgetTally{verifications: 100, scanned: 1, deniedIP: 1, overBudgetMatched: 1},
			budgetTallyOf(h.proxy).minus(before), "a legitimate hello during the flood: served, and reported")
	})

	t.Run("the process-wide bucket", func(t *testing.T) {
		t.Parallel()

		secrets, name := hostedAmongDecoys(t, ec, 100, "last")

		// 10,000 blocks a second for the process, 1,500 of debt: eight scans
		// of 1,200 fit the burst and one more the debt.
		h, _ := budgetHarness(t, secrets, nil, scanBudgetConfig{
			Mode: budgetObserve, NsPerBlock: nsPerBlockForTests, CPUPercent: 1, Procs: 1,
		})

		stranger := ec.secret(t).Key

		for flood := 1; ; flood++ {
			require.LessOrEqual(t, flood, 30, "the flood never went over budget")

			before := budgetTallyOf(h.proxy)

			refuseLoopback(t, h, stranger)

			got := budgetTallyOf(h.proxy).minus(before)
			require.EqualValues(t, 1, got.unmatched, "flood hello %d is scanned", flood)

			if got.deniedGlobal > 0 {
				assert.Equal(t, 10, flood)

				break
			}
		}

		before := budgetTallyOf(h.proxy)

		stream := ec.connect(t, h, name, secrets[name].Key)
		stream.close()

		assert.Equal(t, budgetTally{verifications: 100, scanned: 1, deniedGlobal: 1, overBudgetMatched: 1},
			budgetTallyOf(h.proxy).minus(before))
	})
}

// The twin of TestAnOversizedHelloNeverConsultsHints's 129-block row: observe
// mode counts what enforce would have capped, and scans it anyway.
func TestAnOversizedHelloIsScannedInObserveMode(t *testing.T) {
	t.Parallel()

	const (
		hosted = 20
		place  = "203.0.113.51"
	)

	ec := fakeTLSDoor()
	secrets, name := hostedAmongDecoys(t, ec, hosted, "last")
	key := secrets[name].Key

	h, _ := budgetHarness(t, secrets, nil, scanBudgetConfig{
		Mode: budgetObserve, NsPerBlock: nsPerBlockForTests, CPUPercent: 25, Procs: 4,
	})
	h.proxy.hints = newMatchHints(h.proxy.ctx)

	connectFrom(t, h, ec, tcpFrom(place, 57001), name, key)

	before := budgetTallyOf(h.proxy)

	connectFrom(t, h, ec.withHelloSize(7992), tcpFrom(place, 57002), name, key)

	assert.Equal(t, budgetTally{verifications: hosted, scanned: 1, oversized: 1, overBudgetMatched: 1},
		budgetTallyOf(h.proxy).minus(before), "129 blocks: counted as over the cap, not hinted, scanned and served")
}

// Review Focus 7: the largest hello the reader accepts, fragmented across
// records, is above the scan cap. It is fronted unscanned, and the hint its
// address holds is not tried either.
func TestAFragmented64KiBHelloIsFrontedUnscanned(t *testing.T) {
	t.Parallel()

	const place = "203.0.113.52"

	ec := fakeTLSDoor()
	alice := ec.secret(t)
	h, _ := budgetHarness(t, map[string]Secret{"alice": alice}, nil, roomyBudget())
	h.proxy.hints = newMatchHints(h.proxy.ctx)

	connectFrom(t, h, ec, tcpFrom(place, 58001), "alice", alice.Key)
	require.Equal(t, []string{"alice"}, h.proxy.hints.recall(net.ParseIP(place)))

	global0, address0 := budgetLevels(t, h, place)
	before := budgetTallyOf(h.proxy)

	refuseFrom(t, ec.withHelloSize(65540), h, alice.Key, tcpFrom(place, 58002))

	assert.Equal(t, budgetTally{oversized: 1}, budgetTallyOf(h.proxy).minus(before), "no verification at all")
	assert.Equal(t, 1, h.events.frontings())
	assert.Equal(t, []string{"alice"}, h.proxy.hints.recall(net.ParseIP(place)))

	global1, address1 := budgetLevels(t, h, place)
	assert.InDelta(t, global0, global1, 0, "and no charge")
	assert.InDelta(t, address0, address1, 0)
}

// A hello the budget can pay for only after a refill waits for it. Measured at
// the client, from the hello going out to the server's flight coming back.
func TestAGrantedHelloWaitsItsTurn(t *testing.T) {
	t.Parallel()

	ec := fakeTLSDoor()
	secrets, name := hostedAmongDecoys(t, ec, 100, "last")

	// 10,000 blocks a second for the process, up to 300 ms of debt.
	h, _ := budgetHarness(t, secrets, nil, scanBudgetConfig{
		NsPerBlock: nsPerBlockForTests, CPUPercent: 1, Procs: 1, MaxWait: 300 * time.Millisecond,
	})

	// Exactly empty: 100 candidates x 100 blocks is the whole burst.
	_, _, v := h.proxy.scanBudget.reserve(nil, 100, 100)
	require.Equal(t, budgetGranted, v)

	// The scan costs 1,200: 120 ms of refill.
	client, done := h.dialProxy(t, nil)

	started := time.Now()

	ec.openEntry(t, client, secrets[name].Key)

	require.NoError(t, client.SetReadDeadline(time.Now().Add(5*time.Second)))

	var first [1]byte

	_, err := io.ReadFull(client, first[:])
	require.NoError(t, err, "admitted after the wait")
	require.EqualValues(t, 0x16, first[0])

	assert.GreaterOrEqual(t, time.Since(started), 115*time.Millisecond, "the door waited for the refill")

	client.Close() //nolint: errcheck
	<-done
}

// A wait the stream cannot finish -- the proxy shutting down under it -- ends the
// handshake without fronting a client nobody is serving any more, and gives the
// charge back: no scan was done.
func TestAWaitCutShortByTheProxyRefundsAndDoesNotFront(t *testing.T) {
	t.Parallel()

	ec := fakeTLSDoor()
	secrets, name := hostedAmongDecoys(t, ec, 100, "last")

	// 100 blocks a second for the process; 100 candidates put the burst at the
	// floor, 4,800. With 30 s of debt allowed, the next scan of 1,200 waits 12 s.
	h, _ := budgetHarness(t, secrets, nil, scanBudgetConfig{
		NsPerBlock: 100_000, CPUPercent: 1, Procs: 1, MaxWait: 30 * time.Second,
	})

	b := h.proxy.scanBudget

	for range 4 {
		_, _, v := b.reserve(nil, 12, 100)
		require.Equal(t, budgetGranted, v)
	}

	require.InDelta(t, 0, b.globalAvailable(100), 1e-9)

	before := budgetTallyOf(h.proxy)

	client, done := h.dialProxy(t, nil)
	ec.openEntry(t, client, secrets[name].Key)

	require.Eventually(t, func() bool { return b.globalAvailable(100) < 0 }, 5*time.Second, time.Millisecond,
		"the door reserves and starts to wait")

	h.proxy.ctxCancel()

	require.True(t, govAwait(done, 5*time.Second), "the wait ends with the proxy")

	assert.InDelta(t, 0, b.globalAvailable(100), 1e-9, "the charge is given back")
	assert.Zero(t, h.events.frontings(), "nobody is fronted")
	assert.Equal(t, budgetTally{}, budgetTallyOf(h.proxy).minus(before), "and nothing was scanned")
}
