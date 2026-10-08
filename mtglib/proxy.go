package mtglib

import (
	"context"
	"fmt"
	"net"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Arman2122/mtg-proxy/essentials"
	"github.com/Arman2122/mtg-proxy/mtglib/internal/dc"
	"github.com/Arman2122/mtg-proxy/mtglib/internal/doppel"
	"github.com/Arman2122/mtg-proxy/mtglib/internal/middleproxy"
	"github.com/panjf2000/ants/v2"
)

// The proxy's lifecycle: its state, how it is built and how it stops.
// Serving, entry, the Telegram leg and the secret set each have a file.

// middleProxyDialer is the single call mtglib makes into the middle proxy.
// It is an interface so the advertised path can be driven in tests without an
// RPC-speaking fake; production always holds a *middleproxy.Manager.
type middleProxyDialer interface {
	DialProxyStream(dialer middleproxy.Dialer, params middleproxy.DialParams) (essentials.Conn, net.IP, error)
}

// Proxy is an MTPROTO proxy structure.
type Proxy struct {
	ctx             context.Context
	ctxCancel       context.CancelFunc
	streamWaitGroup sync.WaitGroup

	// apiWaitGroup is the management API server's shutdown, which Shutdown
	// waits for so the socket is released by the time it returns.
	apiWaitGroup sync.WaitGroup

	// fairWaitGroup is fair share's ticker (startFairShare), which Shutdown
	// waits for so that no tick runs once it has returned.
	fairWaitGroup sync.WaitGroup

	// afterFairPass, when set, runs after each pass of fair share's ticker.
	// Only tests set it, and it is read without a lock: a test sets it before
	// the ticker starts.
	afterFairPass func()

	allowFallbackOnUnknownDC    bool
	trackClientIPs              bool
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

	// Untyped nil when no middle proxy is wired: a typed-nil *middleproxy.Manager
	// stored here would pass the "!= nil" gate in doTelegramCall and panic.
	middleProxy    middleProxyDialer
	ourIPv4        net.IP
	ourIPv6        net.IP
	advertisedPort int

	usageStateFile string
	emitTraffic    bool

	stats         *ProxyStats
	obfsStats     obfuscatedCounters
	obfsLimiter   *obfuscatedLimiter
	fakeStats     fakeTLSCounters
	listeners     []ListenerJSON
	listenerModes ModeSet
	secrets       atomic.Pointer[secretSet]
	reloader      func() (SecretConfig, error)
	reloadMu      sync.Mutex
	liveMu        sync.Mutex
	liveConns     map[string]map[*streamContext]struct{}

	// hints is the FakeTLS door's address -> recently matched secret names
	// cache. nil is "hints off": NewProxy builds it only when HandshakeHints (or
	// TrackClientIPs, which it follows by default) asks for it, and a Proxy{}
	// literal in a test has none.
	hints *matchHints

	// scanBudget bounds the CPU the FakeTLS door spends scanning hellos that no
	// hint matched. nil is "budget off": NewProxy always builds one, and a
	// Proxy{} literal in a test has none.
	scanBudget *scanBudget

	// addresses is each user's counted-address ledger, guarded by liveMu so
	// that the address-limit check and the registration of a stream are one
	// critical section. Created on first use and dropped when it counts
	// nothing, so an idle user costs no memory here.
	addresses map[string]*addressLedger

	// clients is the per-address table: what each source address of a secret
	// has moved and is allowed, kept past its connections (client_table.go).
	// It has a lock of its own, taken after liveMu. nil is "off": NewProxy
	// always builds one, and a Proxy{} literal in a test has none. An empty
	// table costs nothing; a stream takes an entry only when its secret needs
	// one (clientEntriesWanted).
	clients *clientTable

	// bans are the places an operator has refused a secret to, until each
	// lapses (proxy_bans.go). Memory only. Its lock is inner to liveMu. The zero
	// value is an empty list, so a Proxy{} literal in a test bans nobody.
	bans banList

	// rotation is the clock retiring keys expire by: one per process, the
	// instance ProxyOpts.RotationClock carries or one NewProxy builds. nil reads
	// the wall clock, and a Proxy{} literal in a test has none.
	rotation *RotationClock

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

// Shutdown 'gracefully' shutdowns all connections. Please remember that it
// does not close an underlying listener.
func (p *Proxy) Shutdown() {
	p.ctxCancel()
	p.streamWaitGroup.Wait()
	// The management API shuts itself down on the cancellation above; waiting
	// for it here is what makes its port free again before this returns.
	p.apiWaitGroup.Wait()
	// So does fair share's ticker, and no tick runs once this has returned.
	p.fairWaitGroup.Wait()
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

// NewProxy makes a new proxy instance.
func NewProxy(opts ProxyOpts) (*Proxy, error) {
	if err := opts.valid(); err != nil {
		return nil, fmt.Errorf("invalid settings: %w", err)
	}

	tg, err := dc.New(opts.getPreferIP())
	if err != nil {
		return nil, fmt.Errorf("cannot build telegram dc fetcher: %w", err)
	}

	shaping, _ := doppel.ParseShaping(opts.DoppelGangerShaping) // valid() checked it

	ctx, cancel := context.WithCancel(context.Background())
	logger := opts.getLogger("proxy")
	updatersLogger := logger.Named("telegram-updaters")

	// The clock comes first: the initial build reads it, and so must be handed
	// the one the rest of the process reads, not the wall clock.
	clock := opts.RotationClock
	if clock == nil {
		clock = NewRotationClock(time.Now, func(by time.Duration) {
			logger.BindStr("behind_by", by.String()).
				Warning("the wall clock is behind the latest time seen; rotation overlaps are judged by the latest time")
		})
	}

	initialSet, initialDrops := buildSecretSetAt(
		opts.getSecrets(), opts.SecretAdTags, opts.GlobalAdTag, opts.SecretLimits, opts.RetiringSecrets, clock.Now())

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
		trackClientIPs:           opts.TrackClientIPs,
		telegram:                 tg,
		doppelGanger: doppel.NewGanger(
			ctx,
			opts.Network,
			logger.Named("doppelganger"),
			opts.DoppelGangerEach,
			int(opts.DoppelGangerPerRaid),
			opts.DoppelGangerURLs,
			opts.DoppelGangerDRS,
			shaping,
			opts.DoppelGangerScoutCovers,
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
		rotation:                    clock,
	}

	// Logged only now: the lines are the proxy's, and the proxy exists.
	proxy.logRetiringDrops(initialDrops)

	// The limiter's bucket aging runs under the proxy's own context, so it stops
	// with Shutdown.
	proxy.obfsLimiter = newObfuscatedLimiter(ctx)

	// So does the hint cache's rotation. Off unless asked for: it keeps client
	// addresses past their connection.
	if opts.handshakeHints() {
		proxy.hints = newMatchHints(ctx)
	}

	// The per-address table is always built: it is empty until a secret needs
	// per-address entries, and applyLimits below must find it for a secret
	// that already does. Its sweep runs from the maintenance loop.
	proxy.clients = newClientTable(addrClock{})

	// The scan budget is in real CPU, so it needs what a SHA-256 block costs
	// here: measured once per process, by whichever proxy is built first, and
	// logged then so an operator can see what the budget believes.
	nsPerBlock, measured := processCalibration.value()
	if measured {
		logger.BindStr("ns_per_block", strconv.FormatFloat(nsPerBlock, 'f', 1, 64)).
			Info("ee handshake budget calibrated")
	}

	proxy.scanBudget = newScanBudget(opts.handshakeBudget(nsPerBlock, runtime.GOMAXPROCS(0)), time.Now)

	go proxy.scanBudget.run(ctx)

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
	// Kept concrete here: Warm is a manager-only method, and the field is the
	// narrow dial interface.
	manager := middleproxy.NewManager(
		ctx,
		opts.Network.MakeHTTPClient(nil),
		updatersLogger.Named("middle-proxy"),
		opts.getPreferIP(),
	)
	proxy.middleProxy = manager

	if opts.GlobalAdTag != nil || len(opts.SecretAdTags) > 0 {
		manager.Warm()
	}

	proxy.secrets.Store(initialSet)
	proxy.applyLimits(initialSet)
	proxy.doppelGanger.SetCoverHosts(proxy.coverHosts(initialSet))

	// Start the management API only now that the proxy exists, so the routes
	// can drive ReloadSecrets and the secrets/adtag mutators. /stats, /reload,
	// /secrets and /adtag share the api-bind-to listener; reload is a
	// no-op-with-error when no reloader was supplied.
	//
	// A socket that cannot be bound is a warning, not a failure: the proxy's
	// job is the MTProto port, and an operator who lost the API to a taken
	// port must not lose every client with it.
	if ln, err := apiListener(ctx, opts); err != nil {
		logger.WarningError("cannot start management API listener", err)
	} else if ln != nil {
		proxy.startAPIServer(ctx, ln, opts.APIToken)
	}

	proxy.startMaintenance(ctx, denySweepInterval, usageFlushInterval)

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
