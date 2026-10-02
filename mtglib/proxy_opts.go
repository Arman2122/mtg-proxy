package mtglib

import (
	"fmt"
	"net"
	"time"

	"github.com/Arman2122/mtg-proxy/mtglib/internal/doppel"
	"github.com/Arman2122/mtg-proxy/mtglib/obfuscation"
)

// UnknownSecretAction is how an obfuscated2 listener disposes of a connection
// it refused. The ZERO VALUE is close, which is the right answer on loopback.
type UnknownSecretAction uint8

const (
	// UnknownSecretClose closes a refused connection immediately.
	UnknownSecretClose UnknownSecretAction = iota

	// UnknownSecretDrain reads and discards from a refused connection, bounded
	// in both bytes and time, before closing. On a public listener a socket that
	// neither answers nor hangs up is less distinctive than a prompt reset.
	UnknownSecretDrain
)

// ListenerPolicy is what one listening socket HONOURS. The mode a connection
// actually uses is always derived (entry path + decrypted tag); this only says
// which derivations are served. The ZERO VALUE is FakeTLS-only, so an existing
// Serve(listener) call and a bare ServeConn are byte-for-byte unchanged.
type ListenerPolicy struct {
	// Modes is the set of secret forms this socket serves.
	Modes ModeSet

	// Public is the operator's acknowledgement that a non-loopback obfuscated2
	// port is fingerprintable as an MTProto proxy. It also arms HandshakesPerIP.
	Public bool

	// ProxyProtocol says a PROXY header is expected on this listener. It is
	// consumed by the CLI when it builds the socket, not by the proxy.
	ProxyProtocol bool

	// OnUnknownSecret is the disposal of a refused connection.
	OnUnknownSecret UnknownSecretAction

	// HandshakesPerIP is the per-IP failed-handshake budget per second (burst
	// 2x). 0 disables it, and it is armed only when Public is set.
	HandshakesPerIP uint
}

// DefaultListenerPolicy is what an unstamped connection gets: FakeTLS only.
// Failing closed here is what keeps a wiring mistake from turning a public port
// into an obfuscated2 oracle.
var DefaultListenerPolicy = ListenerPolicy{Modes: ModeSetOf(SecretModeFakeTLS)}

// Obfuscated reports whether this socket serves the pre-FakeTLS entry.
func (p ListenerPolicy) Obfuscated() bool {
	return p.Modes.Has(SecretModeDD) || p.Modes.Has(SecretModePlain)
}

// Tags is the set of obfuscated2 connection-type tags this socket honours.
func (p ListenerPolicy) Tags() obfuscation.TagSet {
	return p.Modes.Tags()
}

// ListenerJSON is one entry of the listener capability report on GET /stats.
type ListenerJSON struct {
	Bind   string   `json:"bind"`
	Accept []string `json:"accept"`
	Public bool     `json:"public"`
}

// SecretsCanFront reports whether a secret set leaves the always-present FakeTLS
// listener a cover site to fall back to: at least one ee secret, or an explicit
// domain-fronting host. Without one, every failed ClientHello on the public port
// would have nowhere to go, and closing instead of fronting is exactly the
// distinguisher the fronting path exists to avoid.
func SecretsCanFront(secrets map[string]Secret, domainFrontingHost string) bool {
	if domainFrontingHost != "" {
		return true
	}

	for _, secret := range secrets {
		if secret.Hosted() && secret.Host != "" {
			return true
		}
	}

	return false
}

// SecretConfig is the full set of runtime-swappable secret state produced by a
// SecretsReloader: the named secrets plus the optional advertising tags. It is
// what POST /reload re-reads from the config file and what the management API
// mutators build before an atomic swap.
type SecretConfig struct {
	// Secrets is the name->secret map. It must be non-empty and every secret
	// must be valid.
	Secrets map[string]Secret

	// SecretAdTags carries optional per-secret advertising tag overrides keyed
	// by secret name. A name absent here falls back to GlobalAdTag.
	SecretAdTags map[string][AdTagLength]byte

	// GlobalAdTag is the advertising tag applied to any secret without an
	// override. nil means no advertising (the direct-DC path).
	GlobalAdTag *[AdTagLength]byte

	// Limits carries optional per-secret governance limits (data quota, expiry,
	// disabled flag) keyed by secret name. A name absent here has no limits. It
	// is swapped in atomically together with the secrets, so a reload or API
	// mutation can change limits without a restart.
	Limits map[string]SecretLimits
}

// ProxyOpts is a structure with settings to mtg proxy.
//
// This is not required per se, but this is to shorten function signature and
// give an ability to conveniently provide default values.
type ProxyOpts struct {
	// Secret defines a secret which should be used by a proxy.
	//
	// Deprecated: Use Secrets instead for multi-secret support.
	// Kept for backward compatibility.
	Secret Secret

	// Secrets defines a map of named secrets which should be used by a proxy.
	// If set, Secret is ignored. During FakeTLS handshake, each secret is
	// tried until one validates.
	Secrets map[string]Secret

	// Network defines a network instance which should be used for all network
	// communications made by proxies.
	//
	// This is a mandatory setting.
	Network Network

	// AntiReplayCache defines an instance of antireplay cache.
	//
	// This is a mandatory setting.
	AntiReplayCache AntiReplayCache

	// IPBlocklist defines an instance of IP blocklist.
	//
	// This is a mandatory setting.
	IPBlocklist IPBlocklist

	// IPAllowlist defines a whitelist of IPs to allow to use proxy.
	//
	// This is an optional setting, ignored by default (no restrictions).
	IPAllowlist IPBlocklist

	// EventStream defines an instance of event stream.
	//
	// This ia a mandatory setting.
	EventStream EventStream

	// Logger defines an instance of the logger.
	//
	// This is a mandatory setting.
	Logger Logger

	// BufferSize is a size of the copy buffer in bytes.
	//
	// Please remember that we multiply this number in 2, because when we relay
	// between proxies, we have to create 2 intermediate buffers: to and from.
	//
	// This is an optional setting.
	//
	// Deprecated: this setting is no longer makes any effect.
	BufferSize uint

	// Concurrency is a size of the worker pool for connection management.
	//
	// If we have more connections than this number, they are going to be
	// rejected.
	//
	// This is an optional setting.
	Concurrency uint

	// IdleTimeout is a timeout for relay when we have to break a stream.
	//
	// This is a timeout for any activity. So, if we have any message which will
	// pass to either direction, a timer is reset. If we have no any reads or
	// writes for this timeout, a connection will be aborted.
	//
	// This is an optional setting.
	IdleTimeout time.Duration

	// HandshakeTimeout is a timeout during which all handshake ceremonies must
	// be completed, otherwise this process will be aborted
	//
	// This is an optional setting.
	HandshakeTimeout time.Duration

	// TolerateTimeSkewness is a time boundary that defines a time range where
	// faketls timestamp is acceptable.
	//
	// This means that if if you got a timestamp X, now is Y, then if |X-Y| <
	// TolerateTimeSkewness, then you accept a packet.
	//
	// This is an optional setting.
	TolerateTimeSkewness time.Duration

	// PreferIP defines an IP connectivity preference. Valid values are:
	// 'prefer-ipv4', 'prefer-ipv6', 'only-ipv4', 'only-ipv6'.
	//
	// This is an optional setting.
	PreferIP string

	// AutoUpdate defines if it is required to auto update proxy list from
	// Telegram instead of relying on a hardcoded list.
	//
	// This is an optional setting.
	AutoUpdate bool

	// DomainFrontingPort is a port we use to connect to a fronting domain.
	//
	// This is required because secret does not specify a port. It specifies a
	// hostname only.
	//
	// This is an optional setting.
	DomainFrontingPort uint

	// DomainFrontingHost is the address to use when connecting to the
	// fronting domain instead of resolving the hostname from the secret via
	// DNS. It can be a literal IP or a hostname; hostnames are resolved at
	// dial time via the native dialer (which honours dual-stack and Happy
	// Eyeballs).
	//
	// This is useful when DNS resolution of the secret's hostname is blocked
	// or loops back to this server. The hostname from the secret is still
	// used for SNI in the TLS handshake.
	//
	// This is an optional setting.
	DomainFrontingHost string

	// DomainFrontingIP previously held the dial target for the fronting
	// domain. The setting is no longer honoured: setting it logs a warning
	// at proxy startup and the value is dropped.
	//
	// Deprecated: use DomainFrontingHost. Setting this field has no effect.
	DomainFrontingIP string

	// DomainFrontingProxyProtocol is used if communication between upstream
	// endpoint and mtg supports proxy protocol. This is useful in case
	// if mtg is also placed behind load balancer, and this will make
	// fronting webserver to know about real IP addresses
	//
	// This is an optional setting.
	DomainFrontingProxyProtocol bool

	// TrackClientIPs makes GET /stats report per-user client addresses:
	// connected_ips, the distinct addresses holding a live connection right
	// now, and last_ip, the address of the most recent admitted connection.
	//
	// It defaults to FALSE, and that default is deliberate. This is a
	// circumvention proxy: the people using it are frequently the reason it
	// exists, and an operator's answer to "who connected from where" is also
	// the answer anyone who takes the server gets. connected_ips costs no new
	// retention -- those addresses are already held for the duration of the
	// connection, and vanish with it -- but last_ip outlives the connection it
	// came from, so a deployment that never asks for it never accumulates it.
	//
	// Nothing here is written to disk. The usage state file holds quota
	// counters only, so an address survives a restart in no form at all.
	//
	// This is an optional setting.
	TrackClientIPs bool

	// AllowFallbackOnUnknownDC defines how proxy behaves if unknown DC was
	// requested. If this setting is set to false, then such connection will be
	// rejected. Otherwise, proxy will chose any DC.
	//
	// Telegram is designed in a way that any DC can serve any request, the
	// problem is a latency.
	//
	// This is an optional setting.
	AllowFallbackOnUnknownDC bool

	// UseTestDCs defines if we have to connect to production or to staging DCs of
	// Telegram.
	//
	// This is required if you use mtglib as an integration library for your
	// Telegram-related projects.
	//
	// This is an optional setting.
	//
	// OBSOLETE and DEPRECATED. Ignored.
	UseTestDCs bool

	// DCOverrides defines a set of IP addresses that should be used
	// with a higher priority to those that are calculated somehow by mtg.
	//
	// OBSOLETE and DEPRECATED. Ignored.
	DCOverrides map[int][]string

	// DoppelGangerURLs is a list of URLs that should be crawled by
	// mtg to calculate parameters for statistical distribution of a
	// traffic for fronting domains. If nothing is given, then predefined
	// statistics is going to be used.
	DoppelGangerURLs []string

	// DoppelGangerPerRaid defines how many time each URL from
	// DoppelGangerURLs list should be crawled per raid. We recommend to
	// have this number ~10.
	DoppelGangerPerRaid uint

	// DoppelGangerEach defines a time period between each raid. We recommend
	// to use hours here.
	DoppelGangerEach time.Duration

	// DoppelGangerDRS defines if TLS Dynamic Record Sizing is active.
	DoppelGangerDRS bool

	// DoppelGangerShaping is how the doppelganger spaces its records in time:
	// "record" (or empty, the default) waits a drawn delay before every
	// record; "burst" waits once when a connection wakes from idle and then
	// sends records back to back.
	DoppelGangerShaping string

	// DoppelGangerScoutCovers measures the cover sites the ee secrets name --
	// their certificate flight's size, for the fake handshake's noise record
	// -- when DoppelGangerURLs is empty. Their record timing is not taken:
	// pacing keeps the built-in model. It makes outbound HTTPS requests to
	// those sites, so a library caller has to ask; the mtg-proxy binary does
	// unless [defense.doppelganger] scout-covers = false.
	DoppelGangerScoutCovers bool

	// APIBindTo is the address to bind the stats HTTP API server to.
	// If empty, the stats API server is not started.
	//
	// This is an optional setting.
	APIBindTo string

	// APIListener is a socket already bound for the management API. When it
	// is set, APIBindTo is ignored and the proxy serves the API on this socket
	// instead, taking ownership of it: it is closed when the proxy shuts down.
	//
	// It exists for an embedder or a test that needs the port to be its own
	// before the proxy starts, rather than one the proxy picks and reports.
	//
	// This is an optional setting.
	APIListener net.Listener

	// ThrottleMaxConnections is the total connection limit. When total
	// connections exceed this value, per-user caps are computed using
	// a fair-share algorithm and new connections from over-cap users
	// are rejected. 0 disables throttling.
	//
	// This is an optional setting.
	ThrottleMaxConnections uint

	// ThrottleCheckInterval is how often the throttle recomputes per-user
	// caps. Defaults to 5 seconds.
	//
	// This is an optional setting.
	ThrottleCheckInterval time.Duration

	// SecretsReloader re-reads the desired secret configuration from its source
	// (for the CLI, the config file passed to `mtg run`). When set, a POST to
	// /reload on the stats API triggers Proxy.ReloadSecrets, which calls this
	// and swaps the secret set (and advertising tags) in without a restart.
	// When nil, /reload reports the capability is unavailable and the proxy
	// behaves exactly as before.
	//
	// This is an optional setting.
	SecretsReloader func() (SecretConfig, error)

	// GlobalAdTag is the advertising tag (ad_tag from @MTProxybot) applied to
	// every secret without a per-secret override. When set, matching clients
	// are routed through Telegram middle proxies so a sponsored channel is
	// shown. nil disables advertising globally.
	//
	// This is an optional setting.
	GlobalAdTag *[AdTagLength]byte

	// SecretAdTags carries per-secret advertising tag overrides keyed by secret
	// name. A secret listed here uses its own tag instead of GlobalAdTag.
	//
	// This is an optional setting.
	SecretAdTags map[string][AdTagLength]byte

	// SecretLimits carries per-secret governance limits (data quota, expiry,
	// disabled flag) keyed by secret name. A secret absent here is unlimited,
	// never expires and is enabled.
	//
	// This is an optional setting.
	SecretLimits map[string]SecretLimits

	// UsageStateFile is the path of a JSON file where per-secret quota usage is
	// persisted so it survives restarts. When empty, quota accounting is
	// in-memory only and resets when the process restarts.
	//
	// This is an optional setting.
	UsageStateFile string

	// EmitTraffic controls whether per-read/write EventTraffic events are
	// produced for relayed connections. These events are consumed only by the
	// statsd/prometheus observers, so leave it false when no metrics sink is
	// configured: doing so skips a heap allocation (plus time.Now, a streamID
	// hash and a channel send) on every relay read and write. The CLI sets it
	// automatically when statsd or prometheus is enabled.
	//
	// This is an optional setting.
	EmitTraffic bool

	// PublicIPv4 and PublicIPv6 advertise this proxy's externally reachable
	// addresses. They are used as the proxy's own address in the middle-proxy
	// RPC handshake and RPC_PROXY_REQ; required to be correct behind NAT.
	//
	// These are optional settings.
	PublicIPv4 net.IP
	PublicIPv6 net.IP

	// AdvertisedPort is the port reported as the proxy's own port in
	// RPC_PROXY_REQ. Usually the first bind port.
	//
	// This is an optional setting.
	AdvertisedPort int

	// Listeners describes every socket this proxy was configured to serve, for
	// the capability report on GET /stats. It is display only: the policy that
	// actually governs a connection travels on the connection itself.
	//
	// This is an optional setting.
	Listeners []ListenerJSON

	// ListenerModes is the union of every configured listener's accept set. It
	// is what tells NewProxy that a dd or plain secret has no door, so the
	// operator gets a warning instead of a client that silently cannot connect.
	//
	// This is an optional setting.
	ListenerModes ModeSet

	// APIToken, when non-empty, requires every management-API request to carry
	// an "Authorization: Bearer <token>" header. Empty keeps the API
	// unauthenticated (relying on the localhost-bind convention).
	//
	// This is an optional setting.
	APIToken string
}

func (p ProxyOpts) valid() error {
	switch {
	case p.Network == nil:
		return ErrNetworkIsNotDefined
	case p.AntiReplayCache == nil:
		return ErrAntiReplayCacheIsNotDefined
	case p.IPBlocklist == nil:
		return ErrIPBlocklistIsNotDefined
	case p.IPAllowlist == nil:
		return ErrIPAllowlistIsNotDefined
	case p.EventStream == nil:
		return ErrEventStreamIsNotDefined
	case p.Logger == nil:
		return ErrLoggerIsNotDefined
	}

	if _, err := doppel.ParseShaping(p.DoppelGangerShaping); err != nil {
		return fmt.Errorf("invalid doppelganger shaping: %w", err)
	}

	secrets := p.getSecrets()
	if len(secrets) == 0 {
		return ErrSecretInvalid
	}

	for _, s := range secrets {
		if !s.Valid() {
			return ErrSecretInvalid
		}
	}

	return nil
}

// getSecrets returns the effective secrets map. If Secrets is populated, it is
// returned directly. Otherwise the single Secret is wrapped in a map.
func (p ProxyOpts) getSecrets() map[string]Secret {
	if len(p.Secrets) > 0 {
		return p.Secrets
	}

	if p.Secret.Valid() {
		return map[string]Secret{"default": p.Secret}
	}

	return nil
}

func (p ProxyOpts) getConcurrency() int {
	if p.Concurrency == 0 {
		return DefaultConcurrency
	}

	return int(p.Concurrency)
}

func (p ProxyOpts) getDomainFrontingPort() int {
	if p.DomainFrontingPort == 0 {
		return DefaultDomainFrontingPort
	}

	return int(p.DomainFrontingPort)
}

func (p ProxyOpts) getTolerateTimeSkewness() time.Duration {
	if p.TolerateTimeSkewness == 0 {
		return DefaultTolerateTimeSkewness
	}

	return p.TolerateTimeSkewness
}

func (p ProxyOpts) getPreferIP() string {
	if p.PreferIP == "" {
		return DefaultPreferIP
	}

	return p.PreferIP
}

func (p ProxyOpts) getHandshakeTimeout() time.Duration {
	if p.HandshakeTimeout == 0 {
		return DefaultHandshakeTimeout
	}

	return p.HandshakeTimeout
}

func (p ProxyOpts) getIdleTimeout() time.Duration {
	if p.IdleTimeout == 0 {
		return DefaultIdleTimeout
	}

	return p.IdleTimeout
}

func (p ProxyOpts) getThrottleCheckInterval() time.Duration {
	if p.ThrottleCheckInterval == 0 {
		return 5 * time.Second //nolint: mnd
	}

	return p.ThrottleCheckInterval
}

func (p ProxyOpts) getLogger(name string) Logger {
	return p.Logger.Named(name)
}
