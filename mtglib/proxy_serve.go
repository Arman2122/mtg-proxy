package mtglib

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
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

	tracker := newIdleTracker(p.idleTimeout)

	relay.Relay(
		ctx,
		ctx.logger.Named("relay"),
		connIdleTimeout{Conn: ctx.telegram(), tracker: tracker},
		newCountingConn(connIdleTimeout{Conn: ctx.client(), tracker: tracker}, p.stats, ctx.secretName),
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
func (p *Proxy) attribute(ctx *streamContext, set *secretSet, i int) bool {
	ctx.matchedSecretKey = set.secrets[i].Key[:]
	ctx.secretName = set.names[i]
	ctx.adTag = set.effectiveAdTag(i)
	ctx.logger = ctx.logger.BindStr("secret_name", ctx.secretName)

	allowed, reason := p.checkLimits(ctx.secretName, set.limits[i])
	if !allowed {
		ctx.logger.BindStr("deny_reason", reason.String()).Info("connection denied by per-user limit")
	}

	return allowed
}

// admit performs the throttle check and the accounting that must not happen
// before the secret is known.
func (p *Proxy) admit(ctx *streamContext) bool {
	if !p.stats.CanConnect(ctx.secretName) {
		ctx.logger.Info("connection throttled")
		p.eventStream.Send(ctx, NewEventThrottled(ctx.streamID, ctx.secretName))

		return false
	}

	p.stats.OnConnect(ctx.secretName)
	p.stats.UpdateLastSeen(ctx.secretName)

	// Only once the secret is known, for the same reason nothing is billed
	// before attribution: on the dd/plain door the name does not exist until
	// the frame is trial-decrypted, and an address recorded earlier would be
	// filed under the empty name for every obfuscated user at once.
	if p.trackClientIPs {
		if ip, ok := acceptedClientIP(ctx.client().RemoteAddr()); ok {
			p.stats.SetLastIP(ctx.secretName, ip.String())
		}
	}

	p.registerConn(ctx)

	return true
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

func (p *Proxy) registerConn(ctx *streamContext) {
	p.liveMu.Lock()
	defer p.liveMu.Unlock()

	conns := p.liveConns[ctx.secretName]
	if conns == nil {
		conns = make(map[*streamContext]struct{})
		p.liveConns[ctx.secretName] = conns
	}

	conns[ctx] = struct{}{}
}

// connectedIPs snapshots the distinct client addresses holding a live
// connection, per secret name. It returns nil when address tracking is off, so
// the field stays absent from /stats rather than present and empty.
//
// The lock discipline is closeStaleConns': collect under liveMu, resolve
// outside it. Nothing but the contexts themselves is touched inside the
// critical section -- liveMu is a plain Mutex on the connect and disconnect
// path of every stream, and ClientIP takes a second lock of its own, which is
// a lock edge worth not creating for a stats scrape.
//
// Addresses are deduplicated and sorted. Map iteration order is randomised per
// run, and an unsorted list would make two scrapes of an unchanged proxy
// differ -- the same reason the feature list is kept sorted.
func (p *Proxy) connectedIPs() map[string][]string {
	if !p.trackClientIPs {
		return nil
	}

	p.liveMu.Lock()

	snapshot := make(map[string][]*streamContext, len(p.liveConns))

	for name, conns := range p.liveConns {
		contexts := make([]*streamContext, 0, len(conns))
		for sc := range conns {
			contexts = append(contexts, sc)
		}

		snapshot[name] = contexts
	}
	p.liveMu.Unlock()

	rv := make(map[string][]string, len(snapshot))

	for name, contexts := range snapshot {
		seen := make(map[string]struct{}, len(contexts))
		addresses := make([]string, 0, len(contexts))

		for _, sc := range contexts {
			ip := sc.ClientIP()
			if ip == nil {
				continue
			}

			text := ip.String()
			if _, ok := seen[text]; ok {
				continue
			}

			seen[text] = struct{}{}

			addresses = append(addresses, text)
		}

		if len(addresses) == 0 {
			continue
		}

		sort.Strings(addresses)

		rv[name] = addresses
	}

	return rv
}

func (p *Proxy) unregisterConn(ctx *streamContext) {
	p.liveMu.Lock()
	defer p.liveMu.Unlock()

	conns := p.liveConns[ctx.secretName]
	if conns == nil {
		return
	}

	delete(conns, ctx)

	if len(conns) == 0 {
		delete(p.liveConns, ctx.secretName)
	}
}
