package cli

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/Arman2122/mtg-proxy/antireplay"
	"github.com/Arman2122/mtg-proxy/events"
	"github.com/Arman2122/mtg-proxy/internal/config"
	"github.com/Arman2122/mtg-proxy/internal/proxyprotocol"
	"github.com/Arman2122/mtg-proxy/internal/utils"
	"github.com/Arman2122/mtg-proxy/ipblocklist"
	"github.com/Arman2122/mtg-proxy/ipblocklist/files"
	"github.com/Arman2122/mtg-proxy/logger"
	"github.com/Arman2122/mtg-proxy/mtglib"
	"github.com/Arman2122/mtg-proxy/network/v2"
	"github.com/Arman2122/mtg-proxy/stats"
	"github.com/pires/go-proxyproto"
	"github.com/rs/zerolog"
	"github.com/yl2chen/cidranger"
)

func makeLogger(conf *config.Config) mtglib.Logger {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnixMs
	zerolog.TimestampFieldName = "timestamp"
	zerolog.LevelFieldName = "level"

	if conf.Debug.Get(false) {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	} else {
		zerolog.SetGlobalLevel(zerolog.WarnLevel)
	}

	baseLogger := zerolog.New(os.Stdout).With().Timestamp().Logger()

	return logger.NewZeroLogger(baseLogger)
}

func makeNetwork(conf *config.Config, version string) (mtglib.Network, error) {
	resolver, err := network.GetDNS(conf.GetDNS())
	if err != nil {
		return nil, fmt.Errorf("cannot create DNS resolver: %w", err)
	}

	// The socket option takes a machine word, so an oversized watermark is
	// refused here rather than wrapped on the 32-bit builds we ship.
	lowat, err := conf.Network.TCPNotSentLowat.GetUint(network.DefaultTCPNotSentLowat)
	if err != nil {
		return nil, fmt.Errorf("incorrect tcp-not-sent-lowat: %w", err)
	}

	base := network.New(
		resolver,
		"",
		conf.Network.Timeout.TCP.Get(0),
		conf.Network.Timeout.HTTP.Get(0),
		conf.Network.Timeout.Idle.Get(0),
		net.KeepAliveConfig{
			Enable:   !conf.Network.KeepAlive.Disabled.Get(false),
			Idle:     conf.Network.KeepAlive.Idle.Get(0),
			Interval: conf.Network.KeepAlive.Interval.Get(0),
			Count:    int(conf.Network.KeepAlive.Count.Get(0)),
		},
		int(lowat),
	)

	proxyDialers := make([]mtglib.Network, len(conf.Network.Proxies))
	for idx, v := range conf.Network.Proxies {
		value, err := network.NewProxyNetwork(base, v.Get(nil))
		if err != nil {
			return nil, fmt.Errorf("cannot use %v for proxy url: %w", v.Get(nil), err)
		}
		proxyDialers[idx] = value
	}

	switch len(proxyDialers) {
	case 0:
		return base, nil
	case 1:
		return proxyDialers[0], nil
	}

	value, err := network.Join(proxyDialers...)
	if err != nil {
		panic(err)
	}

	return value, nil
}

func makeAntiReplayCache(conf *config.Config) (mtglib.AntiReplayCache, error) {
	if !conf.Defense.AntiReplay.Enabled.Get(false) {
		return antireplay.NewNoop(), nil
	}

	// The filter is sized in machine words, so an oversized max-size is refused
	// here rather than wrapped on the 32-bit builds we ship.
	maxSize, err := conf.Defense.AntiReplay.MaxSize.GetUint(antireplay.DefaultStableBloomFilterMaxSize)
	if err != nil {
		return nil, fmt.Errorf("incorrect anti-replay max-size: %w", err)
	}

	return antireplay.NewStableBloomFilter(
		maxSize,
		conf.Defense.AntiReplay.ErrorRate.Get(antireplay.DefaultStableBloomFilterErrorRate),
	), nil
}

func makeIPBlocklist(conf config.ListConfig,
	logger mtglib.Logger,
	ntw mtglib.Network,
	updateCallback ipblocklist.FireholUpdateCallback,
) (mtglib.IPBlocklist, error) {
	if !conf.Enabled.Get(false) {
		return ipblocklist.NewNoop(), nil
	}

	remoteURLs := []string{}
	localFiles := []string{}

	for _, v := range conf.URLs {
		if v.IsRemote() {
			remoteURLs = append(remoteURLs, v.String())
		} else {
			localFiles = append(localFiles, v.String())
		}
	}

	blocklist, err := ipblocklist.NewFirehol(logger.Named("ipblockist"),
		ntw,
		conf.DownloadConcurrency.Get(1),
		remoteURLs,
		localFiles,
		updateCallback)
	if err != nil {
		return nil, fmt.Errorf("incorrect parameters for firehol: %w", err)
	}

	go blocklist.Run(conf.UpdateEach.Get(ipblocklist.DefaultFireholUpdateEach))

	return blocklist, nil
}

func makeIPAllowlist(conf config.ListConfig,
	logger mtglib.Logger,
	ntw mtglib.Network,
	updateCallback ipblocklist.FireholUpdateCallback,
) (mtglib.IPBlocklist, error) {
	var (
		allowlist mtglib.IPBlocklist
		err       error
	)

	if !conf.Enabled.Get(false) {
		allowlist, err = ipblocklist.NewFireholFromFiles(
			logger.Named("ipblocklist"),
			1,
			[]files.File{
				files.NewMem([]*net.IPNet{
					cidranger.AllIPv4,
					cidranger.AllIPv6,
				}),
			},
			updateCallback,
		)

		go allowlist.Run(conf.UpdateEach.Get(ipblocklist.DefaultFireholUpdateEach))
	} else {
		allowlist, err = makeIPBlocklist(
			conf,
			logger,
			ntw,
			updateCallback,
		)
	}

	if err != nil {
		return nil, fmt.Errorf("cannot build allowlist: %w", err)
	}

	return allowlist, nil
}

func makeEventStream(conf *config.Config, logger mtglib.Logger) (mtglib.EventStream, error) {
	factories := make([]events.ObserverFactory, 0, 2)

	if conf.Stats.StatsD.Enabled.Get(false) {
		statsdFactory, err := stats.NewStatsd(
			conf.Stats.StatsD.Address.Get(""),
			logger.Named("statsd"),
			conf.Stats.StatsD.MetricPrefix.Get(stats.DefaultStatsdMetricPrefix),
			conf.Stats.StatsD.TagFormat.Get(stats.DefaultStatsdTagFormat),
		)
		if err != nil {
			return nil, fmt.Errorf("cannot build statsd observer: %w", err)
		}

		factories = append(factories, statsdFactory.Make)
	}

	if conf.Stats.Prometheus.Enabled.Get(false) {
		prometheus := stats.NewPrometheus(
			conf.Stats.Prometheus.MetricPrefix.Get(stats.DefaultMetricPrefix),
			conf.Stats.Prometheus.HTTPPath.Get("/"),
		)

		listener, err := (&net.ListenConfig{}).Listen(
			context.Background(), "tcp", conf.Stats.Prometheus.BindTo.Get(""),
		)
		if err != nil {
			return nil, fmt.Errorf("cannot start a listener for prometheus: %w", err)
		}

		go prometheus.Serve(listener) //nolint: errcheck

		factories = append(factories, prometheus.Make)
	}

	if len(factories) > 0 {
		return events.NewEventStream(factories), nil
	}

	return events.NewNoopStream(), nil
}

func warnSNIMismatch(conf *config.Config, ntw mtglib.Network, log mtglib.Logger) {
	host := conf.Secret.Host
	if host == "" {
		return
	}

	res := runSNICheck(context.Background(), net.DefaultResolver, conf, ntw, host)

	if res.ResolveErr != nil {
		log.BindStr("hostname", host).
			WarningError("SNI-DNS check: cannot resolve secret hostname", res.ResolveErr)
		return
	}

	if !res.PublicIPKnown() {
		log.Warning("SNI-DNS check: cannot detect public IP address; set public-ipv4/public-ipv6 in config or run 'mtg doctor'")
		return
	}

	v4Match := res.OurIPv4 == nil || res.IPv4Match
	v6Match := res.OurIPv6 == nil || res.IPv6Match

	if v4Match && v6Match {
		return
	}

	resolved := make([]string, 0, len(res.Resolved))
	for _, ip := range res.Resolved {
		resolved = append(resolved, ip.String())
	}

	our := ""
	if res.OurIPv4 != nil {
		our = res.OurIPv4.String()
	}

	if res.OurIPv6 != nil {
		if our != "" {
			our += "/"
		}

		our += res.OurIPv6.String()
	}

	entry := log.BindStr("hostname", host).
		BindStr("resolved", strings.Join(resolved, ", ")).
		BindStr("public_ip", our)

	if res.OurIPv4 != nil {
		entry = entry.BindStr("ipv4_match", fmt.Sprintf("%t", v4Match))
	}

	if res.OurIPv6 != nil {
		entry = entry.BindStr("ipv6_match", fmt.Sprintf("%t", v6Match))
	}

	entry.Warning("SNI-DNS mismatch: secret hostname does not resolve to this server's public IP. " +
		"DPI may detect and block the proxy. See 'mtg doctor' for details")
}

// warnIgnoredOfficialEnvs flags environment variables of the official
// telegrammessenger/proxy image that mtg-proxy intentionally does not
// implement, so migrating users are not left guessing why they had no effect.
// SECRET and TAG (and the MTG_-prefixed variants) are honored — see
// config.ApplyEnvironment.
func warnIgnoredOfficialEnvs(log mtglib.Logger) {
	if _, ok := os.LookupEnv("WORKERS"); ok {
		log.Warning("WORKERS environment variable is ignored: mtg-proxy is a single Go process that already uses all CPU cores")
	}

	if _, ok := os.LookupEnv("SECRET_COUNT"); ok {
		log.Warning("SECRET_COUNT environment variable is ignored: define named secrets in the [secrets] config section or via the management API")
	}
}

func warnDeprecatedDomainFronting(conf *config.Config, log mtglib.Logger) {
	if conf.DomainFrontingIP.Value != nil {
		log.Warning(`config option "domain-fronting-ip" is deprecated and ignored; use "host" in [domain-fronting] instead`)
	}

	if conf.DomainFronting.IP.Value != nil {
		log.Warning(`config option "ip" in [domain-fronting] is deprecated and ignored; use "host" instead`)
	}
}

// makeSecretsReloader builds the callback Proxy.ReloadSecrets uses to re-read
// the secret set on a POST /reload. It re-parses the same config file passed to
// `mtg run`, so an operator editing [secrets] and calling reload swaps the set
// without a restart. It returns nil when there is no config file (simple-run),
// leaving reload unsupported.
func makeSecretsReloader(configPath string) func() (mtglib.SecretConfig, error) {
	if configPath == "" {
		return nil
	}

	return func() (mtglib.SecretConfig, error) {
		conf, err := utils.ReadConfig(configPath)
		if err != nil {
			return mtglib.SecretConfig{}, err
		}

		return mtglib.SecretConfig{
			Secrets:      conf.GetSecrets(),
			SecretAdTags: conf.GetSecretAdTags(),
			GlobalAdTag:  conf.GetAdTag(),
			Limits:       conf.GetSecretLimits(),
		}, nil
	}
}

// servedListener is one accepting socket: raw is what shutdown closes, serve is
// what the proxy accepts from (raw itself, or a PROXY-protocol adapter around
// it) and policy is stamped onto every connection accepted from it.
//
// The policy has to travel with the socket because MultiListener fans several
// sockets into one Accept and the PROXY-protocol adapter rewrites LocalAddr, so
// listener identity cannot be recovered downstream.
type servedListener struct {
	raw    net.Listener
	serve  net.Listener
	policy mtglib.ListenerPolicy
}

// maybeProxyProtocol wraps a listener into the PROXY-protocol adapter when the
// socket expects a header.
func maybeProxyProtocol(listener net.Listener, enabled bool) net.Listener {
	if !enabled {
		return listener
	}

	return &proxyprotocol.ListenerAdapter{
		Listener: proxyproto.Listener{
			Listener: listener,
		},
	}
}

// buildListeners builds every socket the proxy serves, first entry being the
// bind-to group.
//
// The bind-to group keeps today's shape exactly: one MultiListener, one
// proxy-protocol wrapper, one FakeTLS-only policy. A failure there is still
// fatal. Each [[listener]] then gets its own socket, its own PROXY-protocol
// decision and its own policy, and a bind failure there is logged and skipped:
// the loopback port a panel allocated may have been taken since, and losing the
// WEB backend must never take the public port down with it.
func buildListeners(conf *config.Config, log mtglib.Logger) ([]servedListener, error) {
	return buildListenersWith(conf, log, func(addr string) (net.Listener, error) {
		return utils.NewListener(addr, 0)
	})
}

// listenFunc binds one address. It is a parameter so a test can hand in
// sockets it already holds, and for no other reason: production always binds
// through utils.NewListener, and a test that wants a bind to fail for real can
// still fall through to it.
type listenFunc func(addr string) (net.Listener, error)

func buildListenersWith(conf *config.Config, log mtglib.Logger, listen listenFunc) ([]servedListener, error) {
	bindAddrs := conf.GetBindAddrs()
	baseListeners := make([]net.Listener, 0, len(bindAddrs))

	for _, addr := range bindAddrs {
		l, err := listen(addr)
		if err != nil {
			for _, prev := range baseListeners {
				prev.Close() //nolint: errcheck
			}

			return nil, fmt.Errorf("cannot start proxy on %s: %w", addr, err)
		}

		baseListeners = append(baseListeners, l)
	}

	var base net.Listener

	if len(baseListeners) == 1 {
		base = baseListeners[0]
	} else {
		base = utils.NewMultiListener(baseListeners...)
	}

	served := make([]servedListener, 0, 1+len(conf.GetListeners()))
	served = append(served, servedListener{
		raw: base,
		// The global proxy-protocol-listener applies to bind-to ONLY: each
		// [[listener]] carries its own key, otherwise the panel's single global
		// toggle would make a loopback carrier that never sends a PROXY header
		// be refused wholesale.
		serve: maybeProxyProtocol(base, conf.ProxyProtocolListener.Get(false)),
		// bind-to is permanently FakeTLS-only. There is deliberately no way to
		// spell "dd on the public port" by editing an existing key.
		policy: mtglib.DefaultListenerPolicy,
	})

	for _, lc := range conf.GetListeners() {
		addr := lc.BindTo.Get("")

		// Config.Validate already rejected a bad accept list, so this cannot
		// fire from `mtg run`. Skipping rather than ignoring the error keeps a
		// caller that never validated from binding a socket whose zero-value
		// policy honours nothing at all.
		policy, err := lc.Policy()
		if err != nil {
			log.WarningError("cannot use extra listener on "+addr, err)

			continue
		}

		l, err := listen(addr)
		if err != nil {
			log.WarningError("cannot start extra listener on "+addr, err)

			continue
		}

		served = append(served, servedListener{
			raw:    l,
			serve:  maybeProxyProtocol(l, policy.ProxyProtocol),
			policy: policy,
		})
	}

	return served, nil
}

// listenerReport describes every configured socket for the capability report on
// GET /stats. It is nil when only bind-to is configured, so the report keeps its
// current shape for every deployment that has no [[listener]].
func listenerReport(conf *config.Config) []mtglib.ListenerJSON {
	listeners := conf.GetListeners()
	if len(listeners) == 0 {
		return nil
	}

	bindAddrs := conf.GetBindAddrs()
	report := make([]mtglib.ListenerJSON, 0, len(bindAddrs)+len(listeners))

	for _, addr := range bindAddrs {
		report = append(report, mtglib.ListenerJSON{
			Bind:   addr,
			Accept: mtglib.ModeSetOf(mtglib.SecretModeFakeTLS).Strings(),
			Public: true,
		})
	}

	for _, lc := range listeners {
		modes := make([]mtglib.SecretMode, 0, len(lc.Accept))
		for _, entry := range lc.Accept {
			modes = append(modes, entry.Get())
		}

		report = append(report, mtglib.ListenerJSON{
			Bind:   lc.BindTo.Get(""),
			Accept: mtglib.ModeSetOf(modes...).Strings(),
			Public: lc.Public.Get(false),
		})
	}

	return report
}

func runProxy(conf *config.Config, version, configPath string) error { //nolint: funlen, cyclop
	logger := makeLogger(conf)

	logger.BindJSON("configuration", conf.String()).Debug("configuration")

	warnIgnoredOfficialEnvs(logger)
	warnDeprecatedDomainFronting(conf, logger)

	eventStream, err := makeEventStream(conf, logger)
	if err != nil {
		return fmt.Errorf("cannot build event stream: %w", err)
	}

	ntw, err := makeNetwork(conf, version)
	if err != nil {
		return fmt.Errorf("cannot build network: %w", err)
	}

	warnSNIMismatch(conf, ntw, logger)

	blocklist, err := makeIPBlocklist(
		conf.Defense.Blocklist,
		logger.Named("blocklist"),
		ntw,
		func(ctx context.Context, size int) {
			eventStream.Send(ctx, mtglib.NewEventIPListSize(size, true))
		},
	)
	if err != nil {
		return fmt.Errorf("cannot build ip blocklist: %w", err)
	}

	allowlist, err := makeIPAllowlist(
		conf.Defense.Allowlist,
		logger.Named("allowlist"),
		ntw,
		func(ctx context.Context, size int) {
			eventStream.Send(ctx, mtglib.NewEventIPListSize(size, false))
		},
	)
	if err != nil {
		return fmt.Errorf("cannot build ip allowlist: %w", err)
	}

	antiReplayCache, err := makeAntiReplayCache(conf)
	if err != nil {
		return fmt.Errorf("cannot build anti-replay cache: %w", err)
	}

	doppelGangerURLs := make([]string, len(conf.Defense.Doppelganger.URLs))
	for i, v := range conf.Defense.Doppelganger.URLs {
		doppelGangerURLs[i] = v.String()
	}

	opts := mtglib.ProxyOpts{
		Logger:          logger,
		Network:         ntw,
		AntiReplayCache: antiReplayCache,
		IPBlocklist:     blocklist,
		IPAllowlist:     allowlist,
		EventStream:     eventStream,

		Secrets:                     conf.GetSecrets(),
		Concurrency:                 conf.GetConcurrency(mtglib.DefaultConcurrency),
		DomainFrontingPort:          conf.GetDomainFrontingPort(mtglib.DefaultDomainFrontingPort),
		DomainFrontingHost:          conf.GetDomainFrontingHost(),
		DomainFrontingProxyProtocol: conf.GetDomainFrontingProxyProtocol(false),
		PreferIP:                    conf.PreferIP.Get(mtglib.DefaultPreferIP),
		AutoUpdate:                  conf.AutoUpdate.Get(false),

		AllowFallbackOnUnknownDC: conf.AllowFallbackOnUnknownDC.Get(false),
		TrackClientIPs:           conf.TrackClientIPs.Get(false),
		TolerateTimeSkewness:     conf.TolerateTimeSkewness.Value,
		IdleTimeout:              conf.Network.Timeout.Idle.Get(mtglib.DefaultIdleTimeout),
		HandshakeTimeout:         conf.Network.Timeout.Handshake.Get(mtglib.DefaultHandshakeTimeout),

		DoppelGangerURLs:    doppelGangerURLs,
		DoppelGangerPerRaid: conf.Defense.Doppelganger.Repeats.Get(mtglib.DoppelGangerPerRaid),
		DoppelGangerEach:    conf.Defense.Doppelganger.UpdateEach.Get(mtglib.DoppelGangerEach),
		DoppelGangerDRS:     conf.Defense.Doppelganger.DRS.Get(false),

		APIBindTo:       conf.APIBindTo.Get(""),
		APIToken:        conf.GetAPIToken(),
		SecretsReloader: makeSecretsReloader(configPath),

		GlobalAdTag:    conf.GetAdTag(),
		SecretAdTags:   conf.GetSecretAdTags(),
		SecretLimits:   conf.GetSecretLimits(),
		UsageStateFile: conf.UsageStateFile,
		EmitTraffic:    conf.Stats.StatsD.Enabled.Get(false) || conf.Stats.Prometheus.Enabled.Get(false),
		PublicIPv4:     conf.PublicIPv4.Get(nil),
		PublicIPv6:     conf.PublicIPv6.Get(nil),
		// AdvertisedPort must keep naming the PUBLIC port for RPC_PROXY_REQ,
		// never a [[listener]] one, so it stays the first bind-to port.
		AdvertisedPort: int(conf.GetFirstBindPort()),
		Listeners:      listenerReport(conf),
		ListenerModes:  conf.GetListenerModes(),

		ThrottleMaxConnections: conf.Throttle.MaxConnections.Get(0),
		ThrottleCheckInterval:  conf.Throttle.CheckInterval.Get(5 * time.Second),
	}

	proxy, err := mtglib.NewProxy(opts)
	if err != nil {
		return fmt.Errorf("cannot create a proxy: %w", err)
	}

	served, err := buildListeners(conf, logger)
	if err != nil {
		return err
	}

	ctx := utils.RootContext()

	for _, sl := range served {
		go proxy.ServeWithPolicy(sl.serve, sl.policy) //nolint: errcheck
	}

	<-ctx.Done()

	for _, sl := range served {
		sl.raw.Close() //nolint: errcheck
	}

	proxy.Shutdown()

	return nil
}
