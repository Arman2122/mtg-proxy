package mtglib

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Arman2122/mtg-proxy/essentials"
	"github.com/Arman2122/mtg-proxy/mtglib/internal/dc"
	"github.com/Arman2122/mtg-proxy/mtglib/internal/doppel"
	"github.com/Arman2122/mtg-proxy/mtglib/internal/middleproxy"
	"github.com/Arman2122/mtg-proxy/mtglib/internal/relay"
	"github.com/Arman2122/mtg-proxy/mtglib/internal/tls"
	"github.com/Arman2122/mtg-proxy/mtglib/internal/tls/fake"
	"github.com/Arman2122/mtg-proxy/mtglib/obfuscation"
	"github.com/panjf2000/ants/v2"
)

// secretSet is an immutable snapshot of the secrets a proxy serves. The proxy
// keeps it behind an atomic pointer so a running handshake always reads a
// single consistent view, and ReloadSecrets can swap the whole set in without
// locking the hot path. secrets, names and hostnames stay index-aligned:
// secrets[i] belongs to names[i]; hostnames is the deduplicated, sorted set of
// secret hosts used for SNI matching.
type secretSet struct {
	secrets   []Secret
	names     []string
	hostnames []string
	// adTags[i] is the per-secret advertising tag override for secrets[i], or
	// nil when that secret has no override; globalAdTag applies to any secret
	// without an override, or nil when no advertising is configured.
	adTags      []*[AdTagLength]byte
	globalAdTag *[AdTagLength]byte
	// limits[i] holds the governance limits (quota, expiry, disabled) for
	// secrets[i]; the zero value means the secret is unrestricted.
	limits []SecretLimits

	// hosted holds the indices of ee secrets, in name order. It is the FakeTLS
	// HMAC candidate list: a hostless secret has no hostname a client could put
	// in SNI, and admitting its key on that path would let a client borrow
	// ANOTHER secret's hostname to authenticate with it.
	hosted []int

	// frontHost is the domain-fronting fallback: the first non-empty Host in
	// name order, or "" when no ee secret is configured. It replaces
	// secrets[0].Host, which under a management panel was whichever client name
	// sorted first -- operator-uncontrolled, and now possibly hostless.
	frontHost string
}

// effectiveAdTag returns the advertising tag that applies to secrets[i]: the
// per-secret override if present, otherwise the global tag, otherwise nil (the
// direct-DC path).
func (s *secretSet) effectiveAdTag(i int) *[AdTagLength]byte {
	if i < len(s.adTags) && s.adTags[i] != nil {
		return s.adTags[i]
	}

	return s.globalAdTag
}

// toConfig reconstructs a mutable SecretConfig from the immutable snapshot. It
// is the copy-on-write starting point for the management-API mutators, which
// apply a delta and swap the result back in.
func (s *secretSet) toConfig() SecretConfig {
	secrets := make(map[string]Secret, len(s.names))

	var perSecret map[string][AdTagLength]byte

	var limits map[string]SecretLimits

	for i, name := range s.names {
		secrets[name] = s.secrets[i]

		if s.adTags[i] != nil {
			if perSecret == nil {
				perSecret = make(map[string][AdTagLength]byte)
			}

			perSecret[name] = *s.adTags[i]
		}

		if i < len(s.limits) && !s.limits[i].IsZero() {
			if limits == nil {
				limits = make(map[string]SecretLimits)
			}

			limits[name] = s.limits[i]
		}
	}

	return SecretConfig{Secrets: secrets, SecretAdTags: perSecret, GlobalAdTag: s.globalAdTag, Limits: limits}
}

// buildSecretSet turns a name->secret map into an immutable, name-sorted
// snapshot. Sorting keeps names[i] and secrets[i] aligned and makes the
// matched index stable across processes for a given secret map. perSecret
// carries optional per-name advertising tags and global is the fallback tag;
// both may be nil. limitsMap carries optional per-name governance limits and
// may be nil.
func buildSecretSet(secretsMap map[string]Secret, perSecret map[string][AdTagLength]byte, global *[AdTagLength]byte, limitsMap map[string]SecretLimits) *secretSet {
	names := make([]string, 0, len(secretsMap))
	for name := range secretsMap {
		names = append(names, name)
	}

	sort.Strings(names)

	secretsList := make([]Secret, 0, len(secretsMap))
	adTags := make([]*[AdTagLength]byte, len(names))
	limits := make([]SecretLimits, len(names))

	for i, name := range names {
		secretsList = append(secretsList, secretsMap[name])

		if tag, ok := perSecret[name]; ok {
			t := tag
			adTags[i] = &t
		}

		if lim, ok := limitsMap[name]; ok {
			limits[i] = lim
		}
	}

	hostnameSet := make(map[string]struct{}, len(secretsList))
	hosted := make([]int, 0, len(secretsList))

	var frontHost string

	for i, s := range secretsList {
		if s.Hosted() {
			hosted = append(hosted, i)
		}

		if s.Host == "" {
			// The empty string must never become a matchable SNI: a hostless
			// secret would otherwise answer to a ClientHello carrying no
			// server_name at all.
			continue
		}

		hostnameSet[s.Host] = struct{}{}

		if frontHost == "" {
			frontHost = s.Host
		}
	}

	hostnames := make([]string, 0, len(hostnameSet))
	for h := range hostnameSet {
		hostnames = append(hostnames, h)
	}

	sort.Strings(hostnames)

	return &secretSet{
		secrets:     secretsList,
		names:       names,
		hostnames:   hostnames,
		adTags:      adTags,
		globalAdTag: global,
		limits:      limits,
		hosted:      hosted,
		frontHost:   frontHost,
	}
}

// Proxy is an MTPROTO proxy structure.
type Proxy struct {
	ctx             context.Context
	ctxCancel       context.CancelFunc
	streamWaitGroup sync.WaitGroup

	allowFallbackOnUnknownDC    bool
	tolerateTimeSkewness        time.Duration
	idleTimeout                 time.Duration
	handshakeTimeout            time.Duration
	domainFrontingPort          int
	domainFrontingHost          string
	domainFrontingProxyProtocol bool
	workerPool                  *ants.PoolWithFunc
	telegram                    *dc.Telegram
	configUpdater               *dc.PublicConfigUpdater
	doppelGanger                *doppel.Ganger

	middleProxy    *middleproxy.Manager
	ourIPv4        net.IP
	ourIPv6        net.IP
	advertisedPort int

	usageStateFile string
	emitTraffic    bool

	stats           *ProxyStats
	obfsStats       obfuscatedCounters
	obfsLimiter     *obfuscatedLimiter
	listeners       []ListenerJSON
	listenerModes   ModeSet
	secrets         atomic.Pointer[secretSet]
	reloader        func() (SecretConfig, error)
	reloadMu        sync.Mutex
	liveMu          sync.Mutex
	liveConns       map[string]map[*streamContext]struct{}
	network         Network
	antiReplayCache AntiReplayCache
	blocklist       IPBlocklist
	allowlist       IPBlocklist
	eventStream     EventStream
	logger          Logger
}

// DomainFrontingAddress returns a host:port pair for a fronting domain.
// If a fronting host (literal IP or hostname) is configured, it is used
// instead of the secret's hostname. When secrets use different hostnames,
// pass the matched secret's host to front the correct domain.
func (p *Proxy) DomainFrontingAddress() string {
	return p.domainFrontingAddressForHost(p.secrets.Load().frontHost)
}

// domainFrontingAddressForHost returns "" when there is no cover site at all;
// callers MUST treat that as "cannot front" rather than dialling it.
func (p *Proxy) domainFrontingAddressForHost(host string) string {
	if p.domainFrontingHost != "" {
		host = p.domainFrontingHost
	}

	if host == "" {
		return ""
	}

	return net.JoinHostPort(host, strconv.Itoa(p.domainFrontingPort))
}

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

	if err := ctx.clientConn.SetDeadline(time.Now().Add(p.handshakeTimeout)); err != nil {
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
		clientConn, err := p.doppelGanger.NewConn(ctx.clientConn)
		if err != nil {
			ctx.logger.InfoError("cannot wrap into doppelganger connection", err)
			return
		}
		defer clientConn.Stop()

		ctx.clientConn = clientConn

		if err := p.doObfuscatedHandshake(ctx); err != nil {
			ctx.logger.InfoError("obfuscated handshake is failed", err)
			return
		}
	}

	if err := ctx.clientConn.SetDeadline(time.Time{}); err != nil {
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
		connIdleTimeout{Conn: ctx.telegramConn, tracker: tracker},
		newCountingConn(connIdleTimeout{Conn: ctx.clientConn, tracker: tracker}, p.stats, ctx.secretName),
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

	for {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-p.ctx.Done():
				return nil
			default:
				return fmt.Errorf("cannot accept a new connection: %w", err)
			}
		}

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

// Shutdown 'gracefully' shutdowns all connections. Please remember that it
// does not close an underlying listener.
func (p *Proxy) Shutdown() {
	p.ctxCancel()
	p.streamWaitGroup.Wait()
	p.workerPool.Release()
	p.configUpdater.Wait()
	p.doppelGanger.Shutdown()

	p.allowlist.Shutdown()
	p.blocklist.Shutdown()

	if p.usageStateFile != "" {
		if err := p.stats.FlushUsage(p.usageStateFile); err != nil {
			p.logger.WarningError("cannot flush usage state on shutdown", err)
		}
	}
}

// ReloadSecrets re-reads the secret set through the configured reloader and
// swaps it in atomically, so a client add, removal, disable or re-key takes
// effect without restarting the process. Connections whose secret disappeared
// or was re-keyed are closed; every other live stream keeps running, and the
// /stats counters carry across the swap. It returns ErrReloaderNotConfigured
// when the proxy was built without a SecretsReloader, and an error (leaving the
// current set active) when the reloader fails or yields no valid secret.
func (p *Proxy) ReloadSecrets() error {
	if p.reloader == nil {
		return ErrReloaderNotConfigured
	}

	p.reloadMu.Lock()
	defer p.reloadMu.Unlock()

	cfg, err := p.reloader()
	if err != nil {
		return fmt.Errorf("cannot reload secrets: %w", err)
	}

	return p.swapSecretConfigLocked(cfg)
}

// swapSecretConfigLocked validates cfg, builds a fresh immutable snapshot,
// swaps it in atomically, pre-registers stats for every name, and closes stale
// connections. It is the single mutation point shared by ReloadSecrets and the
// management-API mutators; the caller MUST hold reloadMu.
func (p *Proxy) swapSecretConfigLocked(cfg SecretConfig) error {
	if len(cfg.Secrets) == 0 {
		return ErrSecretInvalid
	}

	for _, s := range cfg.Secrets {
		if !s.Valid() {
			return ErrSecretInvalid
		}
	}

	// bind-to is mandatory and permanently ee-only, so every process has a
	// FakeTLS listener. A swap that leaves it no cover site is REJECTED rather
	// than applied: closing every failed ClientHello instead of fronting it is
	// exactly the distinguisher the fronting path exists to avoid, and the
	// previous set staying active is the safe outcome.
	if !SecretsCanFront(cfg.Secrets, p.domainFrontingHost) {
		return ErrSecretInvalid
	}

	newSet := buildSecretSet(cfg.Secrets, cfg.SecretAdTags, cfg.GlobalAdTag, cfg.Limits)
	oldSet := p.secrets.Swap(newSet)

	for _, name := range newSet.names {
		p.stats.PreRegister(name)
	}

	p.closeStaleConns(oldSet, newSet)
	p.closeDeniedConns()

	return nil
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

// closeStaleConns closes every live stream whose secret was dropped from the
// new set or whose key changed since the old set (a re-key), and leaves the
// rest connected. It compares the KEY ALONE, deliberately: a Host change
// touches nothing on a live stream (the FakeTLS handshake is long finished and
// the fronting host is read only on the failure path of a NEW connection) and a
// Mode change touches nothing at all (the three modes share the key and derive
// identical ciphers), so widening the comparison would kill every live stream
// of every client on a hostname edit for no correctness gain. Streams are snapshotted under the lock and closed outside it,
// so each stream's own unregister (which also takes the lock) cannot deadlock.
func (p *Proxy) closeStaleConns(oldSet, newSet *secretSet) {
	newKeys := make(map[string][SecretKeyLength]byte, len(newSet.names))
	for i, name := range newSet.names {
		newKeys[name] = newSet.secrets[i].Key
	}

	oldKeys := make(map[string][SecretKeyLength]byte)
	if oldSet != nil {
		for i, name := range oldSet.names {
			oldKeys[name] = oldSet.secrets[i].Key
		}
	}

	var stale []*streamContext

	p.liveMu.Lock()
	for name, conns := range p.liveConns {
		if newKey, kept := newKeys[name]; kept {
			if oldKey, had := oldKeys[name]; had && oldKey == newKey {
				continue
			}
		}

		for sc := range conns {
			stale = append(stale, sc)
		}
	}
	p.liveMu.Unlock()

	for _, sc := range stale {
		sc.Close()
	}
}

// checkLimits reports whether a new connection for the named secret is allowed
// by its governance limits, combining the snapshot limit (disabled flag, expiry
// deadline, quota ceiling) with the live usage counter held in stats. The
// returned DenyReason is DenyNone when allowed.
func (p *Proxy) checkLimits(name string, lim SecretLimits) (bool, DenyReason) {
	if lim.Disabled {
		return false, DenyDisabled
	}

	if !lim.ExpiresAt.IsZero() && !time.Now().Before(lim.ExpiresAt) {
		return false, DenyExpired
	}

	if lim.QuotaBytes > 0 && p.stats.QuotaUsed(name, lim.QuotaReset) >= lim.QuotaBytes {
		return false, DenyQuota
	}

	return true, DenyNone
}

// closeDeniedConns closes every live stream whose secret is now denied because
// it was disabled or has expired, so such a change applied via a reload or the
// API takes effect immediately instead of only blocking new connections. A
// quota overrun does not close live streams — consistent with the throttle,
// existing connections are never killed mid-flight.
func (p *Proxy) closeDeniedConns() {
	set := p.secrets.Load()

	limitByName := make(map[string]SecretLimits, len(set.names))
	for i, name := range set.names {
		limitByName[name] = set.limits[i]
	}

	var denied []*streamContext

	p.liveMu.Lock()
	for name, conns := range p.liveConns {
		lim, ok := limitByName[name]
		if !ok {
			continue
		}

		if allowed, reason := p.checkLimits(name, lim); allowed || reason == DenyQuota {
			continue
		}

		for sc := range conns {
			denied = append(denied, sc)
		}
	}
	p.liveMu.Unlock()

	for _, sc := range denied {
		sc.Close()
	}
}

// rolloverAllQuotas applies a monthly quota rollover to every secret whose
// policy is monthly, keeping the persisted and displayed usage fresh even for
// secrets that no client is currently hitting.
func (p *Proxy) rolloverAllQuotas() {
	set := p.secrets.Load()
	now := time.Now()

	for i, name := range set.names {
		if set.limits[i].QuotaReset == QuotaResetMonthly {
			p.stats.rollover(name, set.limits[i].QuotaReset, now)
		}
	}
}

// startUsagePersistence periodically rolls quota periods over and flushes the
// usage counters to usageStateFile until ctx is cancelled.
func (p *Proxy) startUsagePersistence(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(usageFlushInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				p.rolloverAllQuotas()

				if err := p.stats.FlushUsage(p.usageStateFile); err != nil {
					p.logger.WarningError("cannot flush usage state", err)
				}
			}
		}
	}()
}

func (p *Proxy) doFakeTLSHandshake(ctx *streamContext) bool {
	rewind := newConnRewind(ctx.clientConn)

	// Read the active secret snapshot once so a concurrent ReloadSecrets swap
	// cannot desync the key list, hostnames and matched index mid-handshake.
	set := p.secrets.Load()

	// Only HOSTED secrets are HMAC candidates. ReadClientHelloMulti matches SNI
	// against the global hostname list and then HMACs against every key it is
	// given, so leaving a hostless key in this list would let a client borrow
	// another secret's hostname to authenticate with it.
	secretKeys := make([][]byte, 0, len(set.hosted))
	for _, i := range set.hosted {
		secretKeys = append(secretKeys, set.secrets[i].Key[:])
	}

	result, err := fake.ReadClientHelloMulti(
		rewind,
		secretKeys,
		set.hostnames,
		p.tolerateTimeSkewness,
	)
	if err != nil {
		p.logger.InfoError("cannot read client hello", err)

		frontHost := set.frontHost
		if result != nil && result.MatchedHost != "" {
			frontHost = result.MatchedHost
		}

		p.doDomainFrontingForHost(ctx, rewind, frontHost)

		return false
	}

	if p.antiReplayCache.SeenBefore(result.Hello.SessionID) {
		p.logger.Warning("replay attack has been detected!")
		p.eventStream.Send(p.ctx, NewEventReplayAttack(ctx.streamID))
		p.doDomainFrontingForHost(ctx, rewind, result.MatchedHost)

		return false
	}

	// MatchedIndex indexes the hosted candidate list; map it back into the full
	// secret list before anything reads names, limits or ad tags by it.
	idx := set.hosted[result.MatchedIndex]

	// Enforce per-user governance limits before we speak TLS back. A denied
	// user (disabled, expired, or over quota) is routed to the cover site just
	// like a wrong secret, so the outcome is indistinguishable to a prober.
	if !p.attribute(ctx, set, idx) {
		p.doDomainFrontingForHost(ctx, rewind, result.MatchedHost)

		return false
	}

	gangerNoise := p.doppelGanger.NoiseParams()
	noiseParams := fake.NoiseParams{Mean: gangerNoise.Mean, Jitter: gangerNoise.Jitter}

	if err := fake.SendServerHello(ctx.clientConn, set.secrets[idx].Key[:], result.Hello, noiseParams); err != nil {
		p.logger.InfoError("cannot send welcome packet", err)
		return false
	}

	ctx.clientConn = tls.New(ctx.clientConn, true, false)

	return true
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

	res, err := obfuscation.MatchHandshake(ctx.clientConn, keys, policy.Tags())

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

	if !p.attribute(ctx, set, res.Index) {
		return p.denyObfuscated(ctx, policy)
	}

	ctx.dc = res.DC
	ctx.connTag = res.Tag
	ctx.clientConn = res.Conn
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

	io.CopyN(io.Discard, ctx.clientConn, obfuscatedDrainBytes) //nolint: errcheck

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
	dc, tag, conn, err := obfs.ReadHandshake(ctx.clientConn, obfuscation.TagSetOf(obfuscation.TagPaddedIntermediate))
	if err != nil {
		return fmt.Errorf("cannot process client handshake: %w", err)
	}

	ctx.dc = dc
	ctx.connTag = tag
	ctx.clientConn = conn
	ctx.logger = ctx.logger.BindInt("dc", dc)

	return nil
}

// wrapTraffic wraps conn so per-read/write byte counts are emitted as
// EventTraffic, but only when a metrics observer is configured (emitTraffic).
// EventTraffic is consumed solely by the statsd/prometheus observers, so when
// none is enabled the wrapper is skipped entirely — avoiding a heap allocation
// (plus time.Now, a streamID hash and a channel send) on every relay read and
// write.
func (p *Proxy) wrapTraffic(conn essentials.Conn, ctx *streamContext) essentials.Conn {
	if !p.emitTraffic {
		return conn
	}

	return connTraffic{
		Conn:     conn,
		streamID: ctx.streamID,
		stream:   p.eventStream,
		ctx:      ctx,
	}
}

func (p *Proxy) doTelegramCall(ctx *streamContext) error {
	// When this stream carries an advertising tag, route it through a Telegram
	// middle proxy so a sponsored channel appears. On any failure we log and
	// fall through to the direct path so the client stays online (availability
	// is favored over the sponsored channel).
	if ctx.adTag != nil && p.middleProxy != nil {
		switch ctx.connTag {
		case obfuscation.TagAbridged:
			// The middle proxy re-frames into RPC_PROXY_REQ and abridged is a
			// different framing with a different RPC mode (RPC_F_COMPACT).
			// Rather than ship a second, barely exercised reframer whose failure
			// mode is a silently corrupted stream to Telegram, an abridged
			// client takes the direct path: it loses the sponsored channel, not
			// its connection.
			p.stats.OnAdTagSkipped(ctx.secretName)
			ctx.logger.BindStr("conn_tag", ctx.connTag.String()).
				Info("advertising is not supported for this transport; using direct connection")
		default:
			if err := p.doMiddleProxyCall(ctx); err != nil {
				ctx.logger.WarningError("cannot route through middle proxy, using direct connection", err)
			} else {
				return nil
			}
		}
	}

	dcid := ctx.dc

	addresses := p.telegram.GetAddresses(dcid)
	if len(addresses) == 0 && p.allowFallbackOnUnknownDC {
		ctx.logger = ctx.logger.BindInt("original_dc", dcid)
		ctx.logger.Warning("unknown DC, fallbacks")
		ctx.dc = dc.DefaultDC
		addresses = p.telegram.GetAddresses(dc.DefaultDC)
	}

	var (
		conn      essentials.Conn
		err       error
		foundAddr dc.Addr
	)

	for _, addr := range addresses {
		conn, err = p.network.Dial(addr.Network, addr.Address)
		if err == nil {
			foundAddr = addr
			break
		}
	}
	if err != nil {
		return fmt.Errorf("no addresses to call: %w", err)
	}
	if conn == nil {
		return fmt.Errorf("no available addresses for DC %d", ctx.dc)
	}

	// The client's own tag, not ours: the relay above is byte-transparent, so
	// announcing a different transport to Telegram corrupts every packet.
	tgConn, err := foundAddr.Obfuscator.SendHandshake(conn, ctx.dc, ctx.connTag)
	if err != nil {
		conn.Close() // nolint: errcheck
		return fmt.Errorf("cannot perform server handshake: %w", err)
	}

	ctx.telegramConn = p.wrapTraffic(tgConn, ctx)

	telegramHost, _, err := net.SplitHostPort(foundAddr.Address)
	if err != nil {
		conn.Close() //nolint: errcheck

		return fmt.Errorf("cannot parse telegram address %s: %w", foundAddr.Address, err)
	}

	p.eventStream.Send(
		ctx,
		NewEventConnectedToDC(ctx.streamID,
			net.ParseIP(telegramHost),
			ctx.dc),
	)

	return nil
}

// doMiddleProxyCall dials a Telegram middle proxy for the stream's DC and sets
// ctx.telegramConn to an RPC stream that carries the client's traffic together
// with the advertising tag. It returns an error (leaving ctx.telegramConn
// unset) if the middle proxy cannot be reached, so the caller can fall back to
// a direct connection.
func (p *Proxy) doMiddleProxyCall(ctx *streamContext) error {
	clientAddr, _ := ctx.clientConn.RemoteAddr().(*net.TCPAddr)

	stream, middleIP, err := p.middleProxy.DialProxyStream(p.network, middleproxy.DialParams{
		DC:             ctx.dc,
		ClientAddr:     clientAddr,
		PublicIPv4:     p.ourIPv4,
		PublicIPv6:     p.ourIPv6,
		AdvertisedPort: p.advertisedPort,
		AdTag:          *ctx.adTag,

		PaddedIntermediate: ctx.connTag == obfuscation.TagPaddedIntermediate,
	})
	if err != nil {
		return fmt.Errorf("cannot dial middle proxy: %w", err)
	}

	ctx.telegramConn = p.wrapTraffic(stream, ctx)

	p.eventStream.Send(ctx, NewEventConnectedToDC(ctx.streamID, middleIP, ctx.dc))

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
		frontConn = newConnProxyProtocol(ctx.clientConn, frontConn)
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

// NewProxy makes a new proxy instance.
func NewProxy(opts ProxyOpts) (*Proxy, error) {
	if err := opts.valid(); err != nil {
		return nil, fmt.Errorf("invalid settings: %w", err)
	}

	tg, err := dc.New(opts.getPreferIP())
	if err != nil {
		return nil, fmt.Errorf("cannot build telegram dc fetcher: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	logger := opts.getLogger("proxy")
	updatersLogger := logger.Named("telegram-updaters")

	initialSet := buildSecretSet(opts.getSecrets(), opts.SecretAdTags, opts.GlobalAdTag, opts.SecretLimits)

	stats := NewProxyStats()
	for _, name := range initialSet.names {
		stats.PreRegister(name)
	}

	if opts.UsageStateFile != "" {
		if err := stats.LoadUsage(opts.UsageStateFile); err != nil {
			logger.WarningError("cannot load usage state", err)
		}
	}

	if opts.ThrottleMaxConnections > 0 {
		stats.SetThrottle(int64(opts.ThrottleMaxConnections), opts.getThrottleCheckInterval())
		stats.startThrottleLoop(ctx, logger)
	}

	if opts.DomainFrontingIP != "" {
		logger.Warning("mtglib.ProxyOpts.DomainFrontingIP is deprecated and ignored; use DomainFrontingHost instead")
	}

	proxy := &Proxy{
		ctx:                      ctx,
		ctxCancel:                cancel,
		stats:                    stats,
		reloader:                 opts.SecretsReloader,
		liveConns:                make(map[string]map[*streamContext]struct{}),
		network:                  opts.Network,
		antiReplayCache:          opts.AntiReplayCache,
		blocklist:                opts.IPBlocklist,
		allowlist:                opts.IPAllowlist,
		eventStream:              opts.EventStream,
		logger:                   logger,
		domainFrontingPort:       opts.getDomainFrontingPort(),
		domainFrontingHost:       opts.DomainFrontingHost,
		tolerateTimeSkewness:     opts.getTolerateTimeSkewness(),
		idleTimeout:              opts.getIdleTimeout(),
		handshakeTimeout:         opts.getHandshakeTimeout(),
		allowFallbackOnUnknownDC: opts.AllowFallbackOnUnknownDC,
		telegram:                 tg,
		doppelGanger: doppel.NewGanger(
			ctx,
			opts.Network,
			logger.Named("doppelganger"),
			opts.DoppelGangerEach,
			int(opts.DoppelGangerPerRaid),
			opts.DoppelGangerURLs,
			opts.DoppelGangerDRS,
		),
		configUpdater: dc.NewPublicConfigUpdater(
			tg,
			updatersLogger.Named("public-config"),
			opts.Network.MakeHTTPClient(nil),
		),
		domainFrontingProxyProtocol: opts.DomainFrontingProxyProtocol,
		ourIPv4:                     opts.PublicIPv4,
		ourIPv6:                     opts.PublicIPv6,
		advertisedPort:              opts.AdvertisedPort,
		usageStateFile:              opts.UsageStateFile,
		emitTraffic:                 opts.EmitTraffic,
		listeners:                   opts.Listeners,
		listenerModes:               opts.ListenerModes,
	}

	// The limiter's bucket aging runs under the proxy's own context, so it stops
	// with Shutdown.
	proxy.obfsLimiter = newObfuscatedLimiter(ctx)

	// W1: a hostless secret with no door is stored, valid and unreachable. It is
	// deliberately a warning and not an error -- one odd client must never take
	// a whole inbound offline, and this is the recovery path for an "ee" prefix
	// typo that length-first parsing turns into a plain secret.
	listenerTags := opts.ListenerModes.Tags()

	for i, name := range initialSet.names {
		secret := initialSet.secrets[i]
		// Served means every transport a client of this form might pick is
		// honoured, so the test is tag-set containment, not overlap: a plain
		// listener covers a dd secret, but a dd-only listener does NOT cover a
		// plain one -- a plain client is free to choose abridged or
		// intermediate. C1 computes GET /secrets' "unserved" the same way.
		if !secret.Hosted() && !listenerTags.Covers(ModeSetOf(secret.Mode).Tags()) {
			logger.
				BindStr("secret_name", name).
				BindStr("mode", secret.Mode.String()).
				Warning("secret is not served by any listener; no configured listener honours this form")
		}
	}

	// The middle-proxy manager is always available so advertising can be
	// enabled at runtime via the API. It fetches Telegram's proxy secret and
	// middle-proxy list lazily (nothing happens until an ad-tagged stream is
	// dialed), so a proxy without advertising never touches the network. When
	// advertising is already configured, warm it so the first client is fast.
	proxy.middleProxy = middleproxy.NewManager(
		ctx,
		opts.Network.MakeHTTPClient(nil),
		updatersLogger.Named("middle-proxy"),
		opts.getPreferIP(),
	)

	if opts.GlobalAdTag != nil || len(opts.SecretAdTags) > 0 {
		proxy.middleProxy.Warm()
	}

	proxy.secrets.Store(initialSet)

	// Start the management API only now that the proxy exists, so the routes
	// can drive ReloadSecrets and the secrets/adtag mutators. /stats, /reload,
	// /secrets and /adtag share the api-bind-to listener; reload is a
	// no-op-with-error when no reloader was supplied.
	if opts.APIBindTo != "" {
		proxy.startAPIServer(ctx, opts.APIBindTo, opts.APIToken)
	}

	if opts.UsageStateFile != "" {
		proxy.startUsagePersistence(ctx)
	}

	proxy.doppelGanger.Run()

	if opts.AutoUpdate {
		proxy.configUpdater.Run(ctx, dc.PublicConfigUpdateURLv4, "tcp4")
		proxy.configUpdater.Run(ctx, dc.PublicConfigUpdateURLv6, "tcp6")
	}

	pool, err := ants.NewPoolWithFunc(opts.getConcurrency(),
		// A listener that yields a plain net.Conn is adapted rather than asserted:
		// ants recovers a worker panic and only logs it, so the old forced assert
		// leaked one file descriptor per connection with no error path.
		func(arg any) {
			switch v := arg.(type) {
			case essentials.Conn:
				proxy.ServeConn(v)
			case net.Conn:
				proxy.ServeConn(essentials.WrapNetConn(v))
			}
		},
		ants.WithLogger(opts.getLogger("ants")),
		ants.WithNonblocking(true))
	if err != nil {
		panic(err)
	}

	proxy.workerPool = pool

	return proxy, nil
}
