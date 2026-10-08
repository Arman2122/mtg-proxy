package mtglib

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/Arman2122/mtg-proxy/essentials"
	"github.com/Arman2122/mtg-proxy/mtglib/internal/relay"
	"github.com/panjf2000/ants/v2"
)

// Serving: the accept loop, admission of a connection, and the registry of
// live streams that reload and the stats report both read.

// entryKind is the door a stream came in through.
type entryKind uint8

const (
	entryFakeTLS entryKind = iota
	entryObfuscated
)

// ServeConn serves a connection. We do not check IP blocklist and concurrency
// limit here.
func (p *Proxy) ServeConn(conn essentials.Conn) {
	p.streamWaitGroup.Add(1)
	defer p.streamWaitGroup.Done()

	// The listener's policy travels on the conn: MultiListener fans several
	// sockets into one Accept and the PROXY-protocol adapter rewrites LocalAddr
	// from a peer-supplied header, so it cannot be recovered from the addresses.
	// Anything unstamped -- an embedder calling ServeConn directly, a test -- is
	// FakeTLS-only. Failing closed here is what keeps a wiring mistake from
	// turning a public port into an obfuscated2 oracle.
	policy := DefaultListenerPolicy
	if pc, ok := conn.(policyConn); ok {
		policy, conn = pc.policy, pc.Conn
	}

	ctx := newStreamContext(p.ctx, p.logger, conn)
	defer ctx.Close()

	if err := ctx.client().SetDeadline(time.Now().Add(p.handshakeTimeout)); err != nil {
		ctx.logger.WarningError("cannot set handshake timeout", err)
		return
	}

	stop := context.AfterFunc(ctx, func() {
		ctx.Close()
	})
	defer stop()

	p.eventStream.Send(ctx, NewEventStart(ctx.streamID, ctx.ClientIP()))
	ctx.logger.Info("Stream has been started")

	defer func() {
		p.eventStream.Send(ctx, NewEventFinish(ctx.streamID))
		ctx.logger.Info("Stream has been finished")
	}()

	// Phase 1: identify. On success ctx.secretName, ctx.matchedSecretKey,
	// ctx.adTag, ctx.entry and ctx.logger are set, and the per-user limit check
	// has already run -- on BOTH paths. Without this, every dd/plain user's
	// traffic would be billed to the "" bucket, throttling and quota would do
	// nothing, and revocation-by-hot-reload could not find their connections.
	if !p.doEntry(ctx, policy) {
		return
	}

	afterAttributeHook(ctx)

	// Phase 2: admission. The same code in the same order as today, now reached
	// with a real secret name whichever door the client came in.
	if !p.admit(ctx) {
		// A throttled stream is a refusal like any other, and on an obfuscated
		// listener every refusal has to take the one exit: same counter, same
		// disposal, no branch a prober can time apart. Without this it closed at
		// once while an unknown secret on the same listener was drained -- the
		// deny reason readable in one connection. The FakeTLS door keeps its own
		// behaviour: it has already spoken TLS by this point, so the disposal
		// that hides an obfuscated refusal does not apply to it.
		if ctx.entry == entryObfuscated {
			p.denyObfuscated(ctx, policy)
		}

		return
	}

	defer p.release(ctx)

	// The whole FakeTLS success path is behind us -- the hello verified, not a
	// replay, the user within its limits, admitted -- so this client's address
	// may now remember the name, and the scan that found it is refunded to the
	// handshake budget. Nothing before this line may write a hint or refund a
	// scan: a replay, a denied, throttled or address-limited user must not
	// leave a hint, and keeps its charge.
	if ctx.entry == entryFakeTLS {
		p.hints.remember(ctx.ClientIP(), ctx.secretName)
		ctx.scanRes.settle(true)
	}

	// Phase 3: the FakeTLS write framing.
	//
	// doppel.Conn.start() emits records through tls.WriteRecordInPlace and
	// tls.New(conn, true, false) is a write pass-through, so the doppelganger is
	// the WRITE HALF of the faketls record layer, not a generic noise wrapper. On
	// a plaintext listener it would frame obfuscated2 inside TLS records --
	// breaking the client and stamping a TLS header onto a non-TLS port. It
	// belongs to this path and no other, and so does the obfuscated handshake
	// that has to be read back out through it.
	if ctx.entry == entryFakeTLS {
		clientConn, err := p.doppelGanger.NewConn(ctx.client())
		if err != nil {
			ctx.logger.InfoError("cannot wrap into doppelganger connection", err)
			return
		}
		defer clientConn.Stop()

		ctx.setClient(clientConn)

		if err := p.doObfuscatedHandshake(ctx); err != nil {
			ctx.logger.InfoError("obfuscated handshake is failed", err)
			return
		}
	}

	if err := ctx.client().SetDeadline(time.Time{}); err != nil {
		ctx.logger.WarningError("cannot set deadline", err)
		return
	}

	if err := p.doTelegramCall(ctx); err != nil {
		ctx.logger.WarningError("cannot dial to telegram", err)
		return
	}

	// A stream revoked while it dialled -- a reload, a kick, the proxy stopping
	// -- has had its upstream closed by setTelegram rather than kept. There is
	// nothing to relay to, and a relay handed no upstream would panic.
	telegram := ctx.telegram()
	if telegram == nil {
		ctx.logger.Info("stream was closed while dialling telegram")
		return
	}

	tracker := newIdleTracker(p.idleTimeout)

	relay.Relay(
		ctx,
		ctx.logger.Named("relay"),
		connIdleTimeout{Conn: telegram, tracker: tracker},
		newCountingConn(ctx.ctx, ctx.Close, connIdleTimeout{Conn: ctx.client(), tracker: tracker}, p.stats, ctx.secretName).
			withActivity(&ctx.lastActiveUnix).
			withClient(&ctx.addrEntry),
	)
}

// doEntry runs the identification handshake the accepting socket serves.
func (p *Proxy) doEntry(ctx *streamContext, policy ListenerPolicy) bool {
	if policy.Obfuscated() {
		ctx.entry = entryObfuscated

		return p.doObfuscatedEntry(ctx, policy)
	}

	ctx.entry = entryFakeTLS

	return p.doFakeTLSHandshake(ctx)
}

// attribute is the shared tail of both entry paths: bind the secret name, ad tag
// and logger, then enforce the per-user governance limits. Extracted so the two
// paths cannot drift on what "attributed" means -- quota, expiry, disable,
// throttling and revocation-by-hot-reload all key on the name it sets.
//
// It returns why it refused, or DenyNone when the stream may go on. Both doors
// turn every reason away as they turn away a secret that matched nothing --
// fronted on FakeTLS before the server's flight, disposed of silently on the
// obfuscated door -- and they are handed the reason so a rule can treat one
// differently without attribute knowing about doors: a ban is charged to the
// obfuscated door's failure limiter, which needs the listener policy only that
// door has.
//
// A ban is checked here, after the user's own limits, against the place the
// connection comes from, and checked again when the stream registers (see
// tryRegisterConn): this check reads the ban list without liveMu, so a ban
// recorded a moment later is the re-check's to find. Any place with an address
// can be banned, whether or not it stands for one place: an unkeyed address is
// banned only by an operator who said force, and then it is to be refused.
func (p *Proxy) attribute(ctx *streamContext, set *secretSet, i int) DenyReason {
	ctx.matchedSecretKey = set.secrets[i].Key[:]
	ctx.attrSet = set
	ctx.secretName = set.names[i]
	ctx.adTag = set.effectiveAdTag(i)
	ctx.ipLimit = set.limits[i].IPLimit
	ctx.clientConns = set.limits[i].ClientConns
	ctx.logger = ctx.logger.BindStr("secret_name", ctx.secretName)

	allowed, reason := p.checkLimits(ctx.secretName, set.limits[i])
	if allowed && p.bannedFrom(ctx.secretName, ctx.ClientIP()) {
		allowed, reason = false, DenyBanned
	}

	if allowed {
		return DenyNone
	}

	ctx.logger.BindStr("deny_reason", reason.String()).Info("connection denied by per-user limit")

	return reason
}

// admit performs the throttle check, the address-limit check and the
// accounting that must not happen before the secret is known.
func (p *Proxy) admit(ctx *streamContext) bool {
	if !p.stats.CanConnect(ctx.secretName) {
		ctx.logger.Info("connection throttled")
		p.eventStream.Send(ctx, NewEventThrottled(ctx.streamID, ctx.secretName))

		return false
	}

	// The address gate and the registration are one critical section, and
	// both come before OnConnect: a refused connection must never have been
	// counted, and two new addresses arriving together must not both read
	// "one below the limit". The log line adds the reason; the stream logger's
	// own fields, client-ip among them, come with it, as on every other refusal.
	if reason := p.tryRegisterConn(ctx); reason != DenyNone {
		p.countAdmissionRefusal(ctx, reason)

		return false
	}

	p.stats.OnConnect(ctx.secretName)
	p.stats.UpdateLastSeen(ctx.secretName)
	ctx.lastActiveUnix.Store(time.Now().Unix())

	// Only once the secret is known, for the same reason nothing is billed
	// before attribution: on the dd/plain door the name does not exist until
	// the frame is trial-decrypted, and an address recorded earlier would be
	// filed under the empty name for every obfuscated user at once.
	if p.trackClientIPs {
		if ip, ok := acceptedClientIP(ctx.client().RemoteAddr()); ok {
			p.stats.SetLastIP(ctx.secretName, ip.String())
		}
	}

	return true
}

// bannedFrom says whether the place ip is at is banned from the named secret.
// A connection with no address is at no place and cannot be. With no ban held
// it answers before building the place's key, so a hello that matched a secret
// pays nothing for the question in the common case.
func (p *Proxy) bannedFrom(name string, ip net.IP) bool {
	if p.bans.none() {
		return false
	}

	key, ok := addressKeyOf(ip)

	return ok && p.bannedAt(name, key)
}

// bannedAt is bannedFrom for a place whose key the caller has already built:
// one that asks about several secrets for the same place builds the key once.
func (p *Proxy) bannedAt(name string, key addressKey) bool {
	return p.bans.banned(name, key)
}

// countAdmissionRefusal is the accounting of a connection tryRegisterConn
// refused, one rule per reason. The address limit keeps its counter and its
// event. The connection cap has a counter of its own and no event: a new event
// type reaches the observer interface and every metric backend, and the counter
// is what an operator reads. A ban is an operator's decision and not a limit
// being felt, so it is logged and nothing more; so is a key the secret no
// longer has, which a reload or a mutation took away and no limit was felt in.
// Whatever the reason, the log line adds it; the stream logger's own fields,
// client-ip among them, come with it, as on every other refusal.
//
// A reason with no rule here is still a refusal -- admit has already said no --
// and only goes uncounted: an unknown reason must never be let through.
func (p *Proxy) countAdmissionRefusal(ctx *streamContext, reason DenyReason) {
	ctx.logger.BindStr("deny_reason", reason.String()).Info("connection denied by per-user limit")

	switch reason {
	case DenyIPLimit:
		p.stats.OnIPLimitRefused(ctx.secretName)
		p.eventStream.Send(ctx, NewEventIPLimited(ctx.streamID, ctx.secretName))
	case DenyClientConns:
		p.stats.OnClientConnsRefused(ctx.secretName)
	case DenyBanned: // the operator's own decision: logged above, not counted
	case DenyKeyRevoked: // a key the set took away: logged above, not counted
	default: // a reason nothing produces yet: logged above, not counted
	}
}

// release undoes admit. The order is today's defer-LIFO order exactly:
// unregisterConn then OnDisconnect.
func (p *Proxy) release(ctx *streamContext) {
	p.unregisterConn(ctx)
	p.stats.OnDisconnect(ctx.secretName)
}

// acceptedClientIP returns the client IP of an accepted connection, or false
// when there is none to read.
//
// This is not a formality. With proxy-protocol-listener on, RemoteAddr comes
// from a PROXY header the peer sends, and a v2 header may declare a UDP, Unix
// or UNSPEC transport -- for which go-proxyproto hands back a *net.UDPAddr, a
// *net.UnixAddr, or a nil net.Addr. A type assert on any of those panics on the
// accept loop, and Serve runs in a bare goroutine, so the panic ends the whole
// process and every client on it. Refusing the connection is the answer; a TCP
// listener has no business with an address that is not a TCP one.
func acceptedClientIP(addr net.Addr) (net.IP, bool) {
	tcpAddr, ok := addr.(*net.TCPAddr)
	if !ok || tcpAddr == nil || len(tcpAddr.IP) == 0 {
		return nil, false
	}

	return tcpAddr.IP, true
}

// The accept loop's backoff. A transient accept error is retried after a pause
// that starts at acceptRetryMin, doubles on every consecutive failure and is
// capped at acceptRetryMax; any accepted connection resets it. The numbers are
// net/http's, which has ridden out the same bursts for a decade.
const (
	acceptRetryMin = 5 * time.Millisecond
	acceptRetryMax = time.Second
)

// nextAcceptRetry is the pause after one more consecutive accept failure.
func nextAcceptRetry(current time.Duration) time.Duration {
	if current == 0 {
		return acceptRetryMin
	}

	if next := current * 2; next < acceptRetryMax {
		return next
	}

	return acceptRetryMax
}

// isTransientAcceptError says whether the kernel will stop returning this error
// by itself: the descriptor table filling up, a connection the peer aborted
// between the kernel's accept and ours. The net package classifies exactly
// these as temporary on every platform, and that classification is asked for
// through a local interface rather than net.Error, whose Temporary method is
// deprecated for every purpose except this one.
func isTransientAcceptError(err error) bool {
	var transient interface{ Temporary() bool }

	return errors.As(err, &transient) && transient.Temporary()
}

// Serve starts a proxy on a given listener with the default (FakeTLS-only)
// policy.
func (p *Proxy) Serve(listener net.Listener) error {
	return p.ServeWithPolicy(listener, DefaultListenerPolicy)
}

// ServeWithPolicy is Serve for a listener whose socket honours something other
// than FakeTLS. It is Serve's body with one line changed: the accepted conn is
// stamped with policy before it goes into the worker pool.
func (p *Proxy) ServeWithPolicy(listener net.Listener, policy ListenerPolicy) error {
	p.streamWaitGroup.Add(1)
	defer p.streamWaitGroup.Done()

	var retryIn time.Duration

	for {
		conn, err := listener.Accept()
		if err != nil {
			// The listener was closed, or the proxy is stopping. Both are the
			// caller's doing, and neither is an error to report.
			if errors.Is(err, net.ErrClosed) || p.ctx.Err() != nil {
				return nil
			}

			// A socket that is broken rather than busy -- a descriptor closed
			// underneath us, a listener that was never listening -- is not
			// coming back, and retrying it would only hide that. It is returned
			// so the caller can decide what a dead listener means; for the
			// public port, that the process must not go on looking healthy.
			if !isTransientAcceptError(err) {
				return fmt.Errorf("cannot accept a new connection: %w", err)
			}

			// Busy, not broken: the descriptor table is full, or a peer reset
			// between the kernel's accept and ours. This used to return, and
			// the caller discarded the error, so one such moment took the
			// listener off the air for good while the process stayed up and
			// reported itself healthy. Pause and try again, backing off the way
			// net/http does, so a burst is ridden out rather than spun on.
			retryIn = nextAcceptRetry(retryIn)
			p.logger.BindStr("retry_in", retryIn.String()).
				WarningError("cannot accept a new connection, retrying", err)

			timer := time.NewTimer(retryIn)

			select {
			case <-timer.C:
			case <-p.ctx.Done():
				timer.Stop()

				return nil
			}

			continue
		}

		retryIn = 0

		ipAddr, ok := acceptedClientIP(conn.RemoteAddr())
		if !ok {
			conn.Close() //nolint: errcheck
			p.logger.Info("connection has no usable client address")

			continue
		}

		logger := p.logger.BindStr("ip", ipAddr.String())

		if !p.allowlist.Contains(ipAddr) {
			conn.Close() //nolint: errcheck
			logger.Info("ip was rejected by allowlist")
			p.eventStream.Send(p.ctx, NewEventIPAllowlisted(ipAddr))

			continue
		}

		if p.blocklist.Contains(ipAddr) {
			conn.Close() //nolint: errcheck
			logger.Info("ip was blacklisted")
			p.eventStream.Send(p.ctx, NewEventIPBlocklisted(ipAddr))

			continue
		}

		err = p.workerPool.Invoke(policyConn{Conn: essentials.WrapNetConn(conn), policy: policy})

		switch {
		case err == nil:
		case errors.Is(err, ants.ErrPoolClosed):
			return nil
		case errors.Is(err, ants.ErrPoolOverload):
			conn.Close() //nolint: errcheck
			logger.Info("connection was concurrency limited")
			p.eventStream.Send(p.ctx, NewEventConcurrencyLimited())
		}
	}
}

// registerStep names a point between the steps of tryRegisterConn.
type registerStep uint8

const (
	// stepLedgerAdmitted is after the address ledger has counted the stream and
	// before the per-address table is asked for its entry.
	stepLedgerAdmitted registerStep = iota + 1

	// stepEntryAcquired is after the per-address table has given the stream
	// its entry, if its secret needs one, and before the stream is entered
	// into the registry.
	stepEntryAcquired
)

// registerStepHook runs at each registerStep, under liveMu, and a reason other
// than DenyNone refuses the stream at that point as a step of its own would. A
// no-op in production. A test uses it to refuse at a later step and see that the
// refusal gives back what an earlier step took, which nothing in production can
// do yet. A variable so it can be replaced; a test that does must restore it and
// must not run in parallel, and the hook must not take liveMu.
var registerStepHook = func(registerStep, *streamContext) DenyReason { return DenyNone }

// beforeRegisterLockHook runs in tryRegisterConn immediately before it takes
// liveMu, and afterAttributeHook in ServeConn once the entry has attributed the
// stream and before admission. Both are no-ops in production. A test uses them
// to run a whole secret swap at those two instants. A swap run just before the
// lock tells a set loaded above the hook from one loaded under liveMu, and no
// more: a load between the hook and the lock reads the hook's new set too. The
// two placements differ for as long as the stream waits on liveMu, which a test
// shows by swapping while a registration is parked on the lock
// (TestARekeyWhileRegistrationWaitsOnLiveMuIsRefused). Variables so they can be
// replaced; a test that does must restore them and must not run in parallel.
var (
	beforeRegisterLockHook = func(*streamContext) {}
	afterAttributeHook     = func(*streamContext) {}
)

// tryRegisterConn admits a stream into the live registry and into its user's
// address ledger in one critical section, or refuses it and says why: DenyNone
// is admitted. The address is resolved before the lock is taken: ClientIP takes
// a lock of its own, and liveMu sits on the connect and disconnect path of
// every stream.
//
// The steps run in a fixed order, and a refusal at any of them leaves the
// ledger, and the per-address table, exactly as it was found: the key
// re-check, then the ban re-check, then the per-address connection cap, then
// the address limit (the ledger's admit), then the per-address table entry,
// then the registration. Every refusal comes before the table is asked for an
// entry, so a refused address never holds one, and a step that refuses does so
// through refuse, which gives back what the steps before it took.
//
// The key re-check is first, and it loads the secret set under liveMu, never
// before it: that placement is the whole of its correctness. A swap stores its
// set before it takes liveMu to walk the live streams and close those whose key
// it took away. A stream that loads the set under the lock is either
// registered before the walk, and judged by it, or takes the lock after the
// walk and reads the set the swap stored. A set loaded before the lock could be
// one a swap replaced while this stream waited on liveMu -- the wait being that
// very walk -- and the stream would then register a key nothing will ever look
// at again. The common case costs one load and one pointer compare: the set
// the stream was attributed from is the set in force, and it accepts the key
// it matched. Nothing has been taken yet, so the refusal gives back nothing.
//
// The ban re-check comes next, before the cap and the limit, because it closes
// a race of its own: attribute checked the ban without liveMu, and a ban is
// recorded, and the streams it ends are found, under liveMu. A stream that
// passed attribute before a ban was recorded is either registered before the
// ban takes the lock, and closed by it, or meets the ban here. A key the set no
// longer accepts is refused as such even from a banned place: the key is the
// first thing that no longer holds. On the FakeTLS door the server's flight has
// gone out by now, so a refusal at either re-check is a close after the
// handshake, as an address-limit refusal is; they take a swap, or a ban,
// recorded in the moments between attribution and registration.
//
// The cap reads the ledger's count of the address's live connections, which
// the ledger keeps for every stream whatever else is configured, so it counts
// the streams that were open before the cap was set and it holds when the
// table has no room for the address. It reads the count BEFORE the admit, which
// increments it: reading after would refuse the cap-th connection instead of
// the one past it. An address that does not stand for one place is not capped.
//
// A limit with no address to count against fails closed. The only way a TCP
// listener yields no address is a PROXY header that declared a non-TCP
// source, and admitting such a connection uncounted would make that header
// the way around the limit.
func (p *Proxy) tryRegisterConn(ctx *streamContext) DenyReason {
	ip := ctx.ClientIP()
	key, hasKey := addressKeyOf(ip)
	keyed := hasKey && clientKeyed(ip)
	now := time.Now()

	beforeRegisterLockHook(ctx)

	p.liveMu.Lock()
	defer p.liveMu.Unlock()

	// counted is what the ledger holds for this stream so far, and entry what
	// the per-address table gave it. The stream itself is marked, and handed
	// its entry, only once every step has passed, so a refusal never leaves it
	// looking counted or governed.
	var (
		counted bool
		entry   *clientEntry
	)

	refuse := func(reason DenyReason) DenyReason {
		p.clients.release(entry)

		if counted {
			p.releaseAddressLocked(ctx.secretName, key, now)
		} else {
			// ledgerLocked creates a ledger on first use, so even an admit that
			// refused can have made one.
			p.dropLedgerIfIdleLocked(ctx.secretName, now)
		}

		return reason
	}

	// The key re-check. The Load MUST stay below the Lock: a set read before it
	// can be one a swap replaced while this stream waited on liveMu -- and that
	// swap's walk ran exactly then.
	cur := p.secrets.Load()
	if cur != ctx.attrSet && !cur.accepts(ctx.secretName, ctx.matchedSecretKey, time.Now()) {
		return refuse(DenyKeyRevoked)
	}

	if hasKey && p.bans.banned(ctx.secretName, key) {
		return refuse(DenyBanned)
	}

	if keyed && ctx.clientConns > 0 && p.addresses[ctx.secretName].live(key) >= ctx.clientConns {
		return refuse(DenyClientConns)
	}

	switch {
	case hasKey:
		if !p.ledgerLocked(ctx.secretName).admit(key, ctx.ipLimit, now) {
			return refuse(DenyIPLimit)
		}

		counted = true
	case ctx.ipLimit > 0:
		return refuse(DenyIPLimit)
	}

	if reason := registerStepHook(stepLedgerAdmitted, ctx); reason != DenyNone {
		return refuse(reason)
	}

	entry = p.acquireClientLocked(ctx.secretName, key, keyed)

	if reason := registerStepHook(stepEntryAcquired, ctx); reason != DenyNone {
		return refuse(reason)
	}

	conns := p.liveConns[ctx.secretName]
	if conns == nil {
		conns = make(map[*streamContext]struct{})
		p.liveConns[ctx.secretName] = conns
	}

	conns[ctx] = struct{}{}

	if counted {
		ctx.addrKey, ctx.addrCounted = key, true
	}

	ctx.addrKeyed = keyed

	if entry != nil {
		ctx.addrEntry.Store(entry)
	}

	// Registered: the set it was attributed from has been judged, and a stream
	// that lives for hours must not hold it. The key it matched is kept.
	ctx.attrSet = nil

	return DenyNone
}

// clientEntriesWanted is decision 3 of the per-address design: a secret's
// streams take entries in the per-address table only when the proxy keeps
// client addresses (track-client-ips, which a panel always sets) or the secret
// has a per-address control. Otherwise there is no entry, and the data path
// reads a nil pointer. This is the one place that decides it, for admission and
// for a reload's backfill alike; clientEntriesWantedBy asks it of a whole set.
func (p *Proxy) clientEntriesWanted(lim SecretLimits) bool {
	return p.trackClientIPs || lim.hasClientControl()
}

// clientEntriesWantedBy is clientEntriesWanted for every secret of a set at
// once, answered without looking a secret up: false exactly when no secret of
// the set wants entries -- the proxy keeps no addresses and no secret has a
// per-address control -- which is the common case, and then admission and a
// reload's backfill do no table work at all. Both ask it, and nothing else
// writes the shortcut out; a reason added to clientEntriesWanted belongs here
// too, and a test holds the two to the same answer.
func (p *Proxy) clientEntriesWantedBy(set *secretSet) bool {
	return p.trackClientIPs || set.anyClientControl()
}

// acquireClientLocked takes the per-address entry a stream of the named secret
// is governed by, or nil when there is no table or the secret needs none. The
// limits are read from the secret set as it is now, under liveMu: a reload
// swaps the set before it takes liveMu to re-rate and backfill, so an entry
// made here is either made from the new set or reached by that reload. A
// secret the set no longer has gets no entry; its stream is about to be
// closed. Caller holds liveMu.
func (p *Proxy) acquireClientLocked(name string, key addressKey, keyed bool) *clientEntry {
	if p.clients == nil {
		return nil
	}

	set := p.secrets.Load()
	if !p.clientEntriesWantedBy(set) {
		return nil
	}

	lim, ok := set.limitsOf(name)
	if !ok || !p.clientEntriesWanted(lim) {
		return nil
	}

	return p.clients.acquire(name, key, keyed, entryInitOf(lim))
}

// connectedIPs snapshots the distinct client addresses holding a live
// connection, per secret name. It returns nil when address tracking is off, so
// the field stays absent from /stats rather than present and empty.
func (p *Proxy) connectedIPs() map[string][]string {
	if !p.trackClientIPs {
		return nil
	}

	reports := p.addressReports()
	rv := make(map[string][]string, len(reports))

	for name, report := range reports {
		if len(report.ConnectedIPs) > 0 {
			rv[name] = report.ConnectedIPs
		}
	}

	return rv
}

// unregisterConn undoes tryRegisterConn: the stream leaves the registry, its
// address is released from the ledger and its per-address entry is given back,
// in the same critical section. The entry stays in the table, for the address
// to find again when it reconnects.
func (p *Proxy) unregisterConn(ctx *streamContext) {
	p.liveMu.Lock()
	defer p.liveMu.Unlock()

	// Swapped out, so that a stream can never give its entry back twice.
	p.clients.release(ctx.addrEntry.Swap(nil))

	if ctx.addrCounted {
		p.releaseAddressLocked(ctx.secretName, ctx.addrKey, time.Now())

		ctx.addrCounted = false
	}

	conns := p.liveConns[ctx.secretName]
	if conns == nil {
		return
	}

	delete(conns, ctx)

	if len(conns) == 0 {
		delete(p.liveConns, ctx.secretName)
	}
}
