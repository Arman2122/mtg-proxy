package mtglib

import "sync/atomic"

// fakeTLSCounters count what the FakeTLS door decided about each hello that got
// past the SNI gate. Like obfuscatedCounters they live on Proxy, and the
// reporting side reads them with Load(); nothing reports them yet.
//
// Under the handshake budget's enforce mode the door moves exactly one of
// hinted, scanned, unmatched, deniedIP, deniedGlobal and oversized for each such
// hello, and adds what it verified to verifications. A replay or a denied user
// after a match counts as its match: the counter names how the secret was found,
// not what happened after. The one exit that moves none is a wait for budget cut
// short by the proxy shutting down: nothing was decided about that hello.
//
// In observe mode deniedIP, deniedGlobal and oversized count what enforce would
// have refused, and move together with the scanned or unmatched of the scan
// that went ahead anyway; overBudgetMatched counts those that then matched.
type fakeTLSCounters struct {
	hinted            atomic.Int64
	scanned           atomic.Int64
	unmatched         atomic.Int64
	deniedIP          atomic.Int64
	deniedGlobal      atomic.Int64
	oversized         atomic.Int64
	overBudgetMatched atomic.Int64

	// verifications is how many candidates were verified, hint tries and scan
	// tries alike: the HMACs the door actually ran. It is for tests and is not
	// reported.
	verifications atomic.Int64
}

// OnHinted counts one hello matched by a secret its address matched before.
func (c *fakeTLSCounters) OnHinted() { c.hinted.Add(1) }

// OnScanned counts one hello matched by the scan.
func (c *fakeTLSCounters) OnScanned() { c.scanned.Add(1) }

// OnUnmatched counts one hello the scan found no secret for.
func (c *fakeTLSCounters) OnUnmatched() { c.unmatched.Add(1) }

// OnDeniedIP counts one hello refused by its address's budget.
func (c *fakeTLSCounters) OnDeniedIP() { c.deniedIP.Add(1) }

// OnDeniedGlobal counts one hello refused by the process-wide budget.
func (c *fakeTLSCounters) OnDeniedGlobal() { c.deniedGlobal.Add(1) }

// OnOversized counts one hello above the scan cap.
func (c *fakeTLSCounters) OnOversized() { c.oversized.Add(1) }

// OnOverBudgetMatched counts one hello that matched a secret although the
// budget would have refused it (observe mode).
func (c *fakeTLSCounters) OnOverBudgetMatched() { c.overBudgetMatched.Add(1) }

// addVerifications adds the candidates one handshake verified. It is called once
// per handshake with the total, not once per candidate.
func (c *fakeTLSCounters) addVerifications(n int) { c.verifications.Add(int64(n)) }
