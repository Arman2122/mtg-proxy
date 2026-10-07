package mtglib

import (
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"time"

	"github.com/Arman2122/mtg-proxy/essentials"
	"github.com/Arman2122/mtg-proxy/mtglib/internal/relay"
	"github.com/Arman2122/mtg-proxy/mtglib/internal/tls"
	"github.com/Arman2122/mtg-proxy/mtglib/internal/tls/fake"
	"github.com/Arman2122/mtg-proxy/mtglib/obfuscation"
)

// Entry: the client-facing handshakes. A connection arrives through one of
// two doors -- FakeTLS or obfuscated2 -- and either becomes a stream or is
// refused in a way a prober cannot tell from a website.

func (p *Proxy) doFakeTLSHandshake(ctx *streamContext) bool {
	rewind := newConnRewind(ctx.client())

	// Read the active secret snapshot once so a concurrent ReloadSecrets swap
	// cannot desync the candidates, hostnames and the index a match maps back to
	// mid-handshake.
	set := p.secrets.Load()

	// The hello is read and put through the SNI gate once; what is tried against
	// it is set.cands, which are the HOSTED secrets only. The gate matches SNI
	// against the global hostname list, so a hostless key among the candidates
	// would let a client borrow another secret's hostname to authenticate with it.
	parsed, err := fake.ParseClientHelloFor(rewind, set.hostnames)
	if err != nil {
		p.logger.InfoError("cannot read client hello", err)
		p.doDomainFrontingForHost(ctx, rewind, set.frontHost)

		return false
	}

	// The scan cap, past the SNI gate and before anything is verified: a hello
	// above it is never hinted and never scanned. Observe mode counts it and
	// goes on.
	overBudget := p.scanBudget.oversized(parsed.Blocks())
	if overBudget {
		p.fakeStats.OnOversized()

		if p.scanBudget.enforced() {
			p.refuseOverBudget(ctx, rewind, parsed, "oversized")

			return false
		}
	}

	// First the secrets this client's address completed a handshake with
	// before, if any: a returning client is found here in one verification.
	// Hinted verification is outside the budget; it is bounded by the cap.
	hinted := p.hintedPositions(ctx, parsed, set)

	pos, tried := p.verifyHinted(parsed, set, hinted)
	if pos >= 0 {
		p.fakeStats.addVerifications(tried)
		p.fakeStats.OnHinted()

		return p.completeFakeTLS(ctx, rewind, set, parsed, set.candIdx[pos])
	}

	// Then the scan, over every candidate the hints did not already try, which
	// the budget has to pay for first.
	res, overBudget, ok := p.reserveScan(ctx, rewind, parsed, len(set.cands)-tried, overBudget)
	if !ok {
		p.fakeStats.addVerifications(tried)

		return false
	}

	pos, scanned := p.scanCandidates(parsed, set, skipPositions(hinted))
	p.fakeStats.addVerifications(tried + scanned)

	if pos < 0 {
		// The charge is kept: a hello that matched nothing is what the budget
		// is for.
		p.fakeStats.OnUnmatched()
		p.logger.InfoError("cannot read client hello", fake.ErrBadDigest)
		p.doDomainFrontingForHost(ctx, rewind, parsed.MatchedHost)

		return false
	}

	p.fakeStats.OnScanned()

	if overBudget {
		p.fakeStats.OnOverBudgetMatched()
	}

	// Refunded only once the whole handshake has succeeded, which is decided
	// after this returns: ServeConn settles it once admit has. Every exit
	// before that -- a replay, a denied user, a refused admission -- keeps it.
	ctx.scanRes = res

	// pos is a position in set.cands; map it back into the full secret list
	// before anything reads names, limits or ad tags by it.
	return p.completeFakeTLS(ctx, rewind, set, parsed, set.candIdx[pos])
}

// reserveScan has the budget pay for scanning remaining candidates, and waits
// until it has. It returns the reservation to settle once the handshake is
// decided (nil when nothing was charged), whether the scan is over budget --
// which only observe mode goes on with -- and false when the hello has been
// disposed of and must not be scanned: fronted because enforce refused it, or
// abandoned because the stream ended during the wait.
//
// overBudget comes in true for an oversized hello in observe mode, which has
// been counted already and is not charged: enforce would have refused it
// without charging, and observe keeps enforce's accounting.
func (p *Proxy) reserveScan(
	ctx *streamContext, rewind *connRewind, parsed *fake.Parsed, remaining int, overBudget bool,
) (*scanReservation, bool, bool) {
	if overBudget || remaining <= 0 {
		return nil, overBudget, true
	}

	res, wait, verdict := p.scanBudget.reserve(ctx.ClientIP(), parsed.Blocks(), remaining)

	var reason string

	switch verdict {
	case budgetGranted:
	case budgetDeniedIP:
		p.fakeStats.OnDeniedIP()

		reason = "denied_ip"
	case budgetDeniedGlobal:
		p.fakeStats.OnDeniedGlobal()

		reason = "denied_global"
	case budgetOversized:
		// Unreachable today: the cap is applied, and the hello counted as
		// oversized, before the hints, and a budget that is off grants before it
		// looks at the size. It counts nothing here on purpose: were it ever
		// reachable, the hello would already have been counted, and a second
		// count would break the one-counter-per-hello rule. It only names the
		// reason, so the switch says what every verdict means.
		reason = "oversized"
	}

	if reason != "" {
		if p.scanBudget.enforced() {
			p.refuseOverBudget(ctx, rewind, parsed, reason)

			return nil, true, false
		}

		return nil, true, true
	}

	if wait > 0 && !waitForBudget(ctx, wait) {
		// The stream ended while it waited -- the proxy is shutting down --
		// so nothing was scanned and nobody is left to front.
		res.settle(true)

		return nil, false, false
	}

	return res, false, true
}

// refuseOverBudget fronts a hello the budget refused, through the same call a
// hello that matched nothing takes: the cover site gets the same bytes. What
// differs is the time to the first fronted byte -- a no-match is fronted after
// its scan, a refusal at once (a scan that is granted may wait, but then it
// runs and is not refused) -- the same kind of difference hello size and the
// SNI gate already made.
func (p *Proxy) refuseOverBudget(ctx *streamContext, rewind *connRewind, parsed *fake.Parsed, reason string) {
	ctx.logger.BindStr("reason", reason).Info("ee hello refused by the scan budget")
	p.doDomainFrontingForHost(ctx, rewind, parsed.MatchedHost)
}

// waitForBudget waits d, or until ctx is done; it reports whether the wait ran
// its course.
func waitForBudget(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()

	select {
	case <-timer.C:
		return true
	case <-ctx.Done():
		return false
	}
}

// completeFakeTLS is what follows a hello that matched one secret, idx being its
// index into set.secrets: the replay check, the per-user limits, and the
// server's flight.
func (p *Proxy) completeFakeTLS(
	ctx *streamContext,
	rewind *connRewind,
	set *secretSet,
	parsed *fake.Parsed,
	idx int,
) bool {
	if p.antiReplayCache.SeenBefore(parsed.Hello.SessionID) {
		p.logger.Warning("replay attack has been detected!")
		p.eventStream.Send(p.ctx, NewEventReplayAttack(ctx.streamID))
		p.doDomainFrontingForHost(ctx, rewind, parsed.MatchedHost)

		return false
	}

	// Enforce per-user governance limits before we speak TLS back. A denied
	// user (disabled, expired, or over quota) is routed to the cover site just
	// like a wrong secret, so the outcome is indistinguishable to a prober.
	if reason := p.attribute(ctx, set, idx); reason != DenyNone {
		p.doDomainFrontingForHost(ctx, rewind, parsed.MatchedHost)

		return false
	}

	gangerNoise := p.doppelGanger.NoiseParamsFor(parsed.MatchedHost)
	noiseParams := fake.NoiseParams{Mean: gangerNoise.Mean, Jitter: gangerNoise.Jitter}

	if err := fake.SendServerHello(ctx.client(), set.secrets[idx].Key[:], parsed.Hello, noiseParams); err != nil {
		p.logger.InfoError("cannot send welcome packet", err)
		return false
	}

	ctx.setClient(tls.New(ctx.client(), true, false))

	return true
}

// scanCandidates verifies parsed against set.cands in order and returns the
// position of the first that matches, or -1; tried is how many it verified.
// Positions skip reports true for are passed over, unverified and uncounted;
// nil skips none. A set with no candidates is scanned for nothing: -1, 0.
func (p *Proxy) scanCandidates(parsed *fake.Parsed, set *secretSet, skip func(pos int) bool) (pos, tried int) {
	for at, cand := range set.cands {
		if skip != nil && skip(at) {
			continue
		}

		tried++

		if parsed.Verify(cand, p.tolerateTimeSkewness) {
			return at, tried
		}
	}

	return -1, tried
}

// hintedPositions resolves the names this client's address completed a
// handshake with before into positions in set.cands, in the order to try them.
// It is nil when hints do not apply: the cache is off, the address is unkeyed or
// has none, or the hello is above maxScanBlocks.
//
// A hint is a name, and only the snapshot this hello met says where that name
// is, so a reload between the write and now cannot misdirect it: a name the set
// no longer holds as a candidate is skipped, a re-keyed name is tried under its
// new key, and a re-sorted name is found where it is now.
func (p *Proxy) hintedPositions(ctx *streamContext, parsed *fake.Parsed, set *secretSet) []int {
	if p.hints == nil || parsed.Blocks() > maxScanBlocks {
		return nil
	}

	names := p.hints.recall(ctx.ClientIP())
	if len(names) == 0 {
		return nil
	}

	positions := make([]int, 0, len(names))

	for _, name := range names {
		if pos, ok := set.candByName[name]; ok && !slices.Contains(positions, pos) {
			positions = append(positions, pos)
		}
	}

	return positions
}

// verifyHinted verifies parsed against the candidates at positions, in order,
// and returns the first that matches, or -1; tried is how many it verified.
func (p *Proxy) verifyHinted(parsed *fake.Parsed, set *secretSet, positions []int) (pos, tried int) {
	for _, at := range positions {
		tried++

		if parsed.Verify(set.cands[at], p.tolerateTimeSkewness) {
			return at, tried
		}
	}

	return -1, tried
}

// skipPositions is the scanCandidates skip that passes over positions already
// verified, or nil when there are none.
func skipPositions(positions []int) func(pos int) bool {
	if len(positions) == 0 {
		return nil
	}

	return func(pos int) bool {
		return slices.Contains(positions, pos)
	}
}

// obfuscatedDrainBytes bounds the drain disposal by volume; the handshake
// deadline bounds it in time. Together they stop a prober from filling the
// worker pool with connections that will never be served.
const obfuscatedDrainBytes = 8 << 10

// doObfuscatedEntry identifies a stream that arrived on a plaintext
// obfuscated2 listener: the secret is unknown until the 64-byte frame is
// trial-decrypted, so attribution happens here and nothing may be accounted
// before it.
func (p *Proxy) doObfuscatedEntry(ctx *streamContext, policy ListenerPolicy) bool {
	// The budget decides only whether the TRIAL LOOP runs. It never short-cuts
	// the 64-byte read, because that read is the whole of what a peer observes
	// before we answer: refusing before it closed a rate-limited peer in ~0ms
	// with nothing read, while a peer with budget sat in io.ReadFull for the
	// full handshake timeout -- so a censor burned the budget with junk, opened
	// one silent connection, and the instant close named the listener. It also
	// left 64 unread bytes in the receive queue on the frame probe, and closing
	// a socket in that state sends a reset where a no-match sends a FIN.
	//
	// Consulting Allow first and then handing MatchHandshake an EMPTY candidate
	// list is exactly "read the frame, then refuse": the same io.ReadFull of the
	// same 64 bytes against the same deadline, then the same exit. Allow is a
	// pure query -- only Fail spends a token, and refill is a function of the
	// last Fail and now -- so asking early has no effect a peer could see. It
	// also has to be asked early: on a silent connection the answer would
	// otherwise be computed a whole handshakeTimeout later, by which time the
	// bucket has refilled and the peer is no longer limited at all.
	//
	// The loop is all the limiter ever protected: the read is two syscalls, the
	// loop is N key schedules bought with 64 bytes of attacker traffic.
	allowed := p.obfsLimiter.Allow(policy, ctx.ClientIP())

	// One snapshot for the whole handshake, exactly as doFakeTLSHandshake does,
	// so a concurrent ReloadSecrets cannot desync the key list and the matched
	// index.
	set := p.secrets.Load()

	var keys [][]byte

	if allowed {
		keys = make([][]byte, len(set.secrets))
		for i := range set.secrets {
			keys[i] = set.secrets[i].Key[:]
		}

		p.obfsStats.OnObfuscatedTrial()
	}

	res, err := obfuscation.MatchHandshake(ctx.client(), keys, policy.Tags())

	switch {
	case err != nil && !errors.Is(err, obfuscation.ErrNoMatchingSecret):
		// Short read: the peer left before 64 bytes. Nothing to drain, nothing
		// to attribute, and it already went away.
		ctx.logger.InfoError("cannot read obfuscated handshake", err)

		return false
	case !allowed:
		// The frame is read and discarded unexamined. No candidate ran.
		p.obfsStats.OnObfuscatedRateLimited()

		return p.denyRateLimited(ctx, policy)
	case err != nil:
		p.obfsStats.OnObfuscatedMiss()
		p.obfsLimiter.Fail(policy, ctx.ClientIP())

		return p.denyObfuscated(ctx, policy)
	}

	// Checked only AFTER a secret matched. AntiReplayCache.SeenBefore is
	// TestAndAdd on a STABLE bloom filter -- every insert evicts cells -- so
	// letting unauthenticated 64-byte probes write into it would be a remote
	// eraser for the FakeTLS session ids the public listener depends on.
	if p.antiReplayCache.SeenBefore(res.ReplayKey()) {
		p.logger.Warning("replay attack has been detected!")
		p.eventStream.Send(p.ctx, NewEventReplayAttack(ctx.streamID))

		return p.denyObfuscated(ctx, policy)
	}

	if reason := p.attribute(ctx, set, res.Index); reason != DenyNone {
		return p.denyObfuscated(ctx, policy)
	}

	ctx.dc = res.DC
	ctx.connTag = res.Tag
	ctx.setClient(res.Conn)
	ctx.logger = ctx.logger.BindInt("dc", res.DC).BindStr("conn_tag", res.Tag.String())

	return true
}

// denyObfuscated disposes of a connection the obfuscated entry refused: no
// secret matched, the tag is not honoured on this listener, the frame is a
// replay, the user is disabled, expired or over quota, or the user is
// throttled. Every one of those takes the SAME exit, so none is
// distinguishable from the others. (A rate-limited peer is the one deliberate
// exception -- see denyRateLimited.)
//
// Never domain fronting. This listener does not speak TLS, so relaying a probe
// to an HTTPS cover site would pipe that site's TLS alert back out of a
// plaintext port -- a stronger tell than either close or drain -- and on the
// loopback deployment it would turn 64 local bytes into an outbound dial and a
// held relay pair, a pure amplifier with no censor present to fool.
//
// It also writes nothing back, ever.
//
// INVARIANT: every call site sits before ServeConn clears the handshake
// deadline. The drain deliberately runs under that deadline instead of setting
// one of its own; moving the clear earlier would hand a refused peer an
// unbounded hold.
func (p *Proxy) denyObfuscated(ctx *streamContext, policy ListenerPolicy) bool {
	p.obfsStats.OnObfuscatedDenied()

	if policy.OnUnknownSecret == UnknownSecretClose {
		return false // ctx.Close() in ServeConn's defer closes the socket
	}

	// The drain inherits ServeConn's now+handshakeTimeout deadline rather than
	// opening a fresh window. A fresh 20s made the worst-case hold
	// handshakeTimeout+20s -- connect, idle until just before the deadline, send
	// 64 non-matching bytes, then dribble -- which at DefaultConcurrency is only
	// ~140 conn/s to saturate the worker pool and start dropping legitimate
	// clients with ErrPoolOverload. Inheriting it bounds EVERY disposal on this
	// listener by handshakeTimeout, and has the drain end at the same instant a
	// silent connection does instead of at a window of its own. The byte bound
	// below is the other half.
	//
	// On the throttled and replay exits the conn is already the obfuscation
	// wrapper, so this decrypts as it discards. That is harmless and deliberate:
	// the bytes go to io.Discard either way, and reaching around the wrapper
	// would be code for no gain.
	p.obfsStats.OnObfuscatedDrainStart()
	defer p.obfsStats.OnObfuscatedDrainEnd()

	io.CopyN(io.Discard, ctx.client(), obfuscatedDrainBytes) //nolint: errcheck

	return false
}

// denyRateLimited is the exit for a peer that has spent its per-IP failure
// budget. It has already read the frame, so up to here it is byte-identical to
// a no-match, and it writes nothing back either -- but it never drains.
//
// The drain is the longest hold this listener offers, and handing it to a peer
// whose budget is already gone inverts the point of the budget: one IP could
// hold a worker slot for a full handshakeTimeout, over and over, and the
// per-IP budget would do nothing about it. On a close listener -- the default,
// and the right answer on loopback -- this is indistinguishable from a
// no-match. On a drain listener it is a deliberate, documented timing
// difference (SECURITY.md): a public drain listener any single IP can wedge is
// the worse of the two.
func (p *Proxy) denyRateLimited(ctx *streamContext, policy ListenerPolicy) bool {
	closeOnly := policy
	closeOnly.OnUnknownSecret = UnknownSecretClose

	return p.denyObfuscated(ctx, closeOnly)
}

func (p *Proxy) doObfuscatedHandshake(ctx *streamContext) error {
	// Use the secret key that was matched during the FakeTLS handshake.
	obfs := obfuscation.Obfuscator{
		Secret: ctx.matchedSecretKey,
	}

	// The FakeTLS entry honours padded-intermediate and nothing else, exactly as
	// it always has: ee clients send 0xdddddddd.
	dc, tag, conn, err := obfs.ReadHandshake(ctx.client(), obfuscation.TagSetOf(obfuscation.TagPaddedIntermediate))
	if err != nil {
		return fmt.Errorf("cannot process client handshake: %w", err)
	}

	ctx.dc = dc
	ctx.connTag = tag
	ctx.setClient(conn)
	ctx.logger = ctx.logger.BindInt("dc", dc)

	return nil
}

func (p *Proxy) doDomainFrontingForHost(ctx *streamContext, conn *connRewind, host string) {
	addr := p.domainFrontingAddressForHost(host)
	if addr == "" {
		// net.Dial treats an empty host as the local system, so
		// JoinHostPort("", "443") would dial our OWN bind-to and each probe
		// would recurse into a fresh self-connection. Close instead.
		// Config.Validate and swapSecretConfigLocked make this unreachable; it
		// is the last guard.
		p.logger.Warning("no domain fronting target is configured; closing")

		return
	}

	p.eventStream.Send(p.ctx, NewEventDomainFronting(ctx.streamID))
	conn.Rewind()

	nativeDialer := p.network.NativeDialer()
	fConn, err := nativeDialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		p.logger.WarningError("cannot dial to the fronting domain", err)

		return
	}

	frontConn := essentials.WrapNetConn(fConn)

	if p.domainFrontingProxyProtocol {
		frontConn = newConnProxyProtocol(ctx.client(), frontConn)
	}

	frontConn = p.wrapTraffic(frontConn, ctx)

	tracker := newIdleTracker(p.idleTimeout)

	relay.Relay(
		ctx,
		ctx.logger.Named("domain-fronting"),
		connIdleTimeout{Conn: frontConn, tracker: tracker},
		connIdleTimeout{Conn: conn, tracker: tracker},
	)
}
