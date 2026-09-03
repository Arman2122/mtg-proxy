package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"time"

	"github.com/Arman2122/mtg-proxy/mtglib"
)

type Optional struct {
	Enabled TypeBool `json:"enabled"`
}

// ConfigSecretLimit is the typed form of a single [secret-limits.<name>] table:
// an optional data quota (with reset policy), an expiry deadline and a disabled
// flag. All fields are optional; the zero value leaves the secret unrestricted.
type ConfigSecretLimit struct {
	Quota      TypeBytes      `json:"quota"`
	QuotaReset TypeQuotaReset `json:"quotaReset"`
	Expires    TypeExpiry     `json:"expires"`
	Disabled   TypeBool       `json:"disabled"`
}

// ConfigListener is one [[listener]] block: an extra socket serving the
// pre-FakeTLS secret forms. It is purely additive -- the top-level bind-to is
// never replaced and always stays FakeTLS-only, because a socket that answers
// obfuscated2 is fingerprintable as an MTProto proxy and that has to be an
// explicit stanza rather than a one-token edit of an existing key.
type ConfigListener struct {
	BindTo          TypeHostPort            `json:"bindTo"`
	Accept          []TypeSecretMode        `json:"accept"`
	Public          TypeBool                `json:"public"`
	ProxyProtocol   TypeBool                `json:"proxyProtocol"`
	OnUnknownSecret TypeUnknownSecretAction `json:"onUnknownSecret"`
	HandshakesPerIP TypeConcurrency         `json:"handshakesPerIp"`
}

// defaultHandshakesPerIP is the per-IP obfuscated2 failure budget used when a
// [[listener]] names none. It is armed only on a public listener.
const defaultHandshakesPerIP = 30

// Policy converts one configured listener into the runtime policy the proxy
// stamps onto every connection accepted from its socket. It is also where V2 is
// enforced, so Validate and run_proxy cannot disagree about what a listener
// honours.
func (l ConfigListener) Policy() (mtglib.ListenerPolicy, error) {
	modes := make([]mtglib.SecretMode, 0, len(l.Accept))

	for _, entry := range l.Accept {
		modes = append(modes, entry.Get())
	}

	set := mtglib.ModeSetOf(modes...)

	if set.Empty() || set.Has(mtglib.SecretModeFakeTLS) {
		return mtglib.ListenerPolicy{}, fmt.Errorf(
			"listener %s: accept must be a non-empty subset of [\"dd\",\"plain\"]; "+
				"the top-level bind-to serves FakeTLS and a [[listener]] never does. "+
				"Run two listeners if you need both", l.BindTo.Get(""))
	}

	action := mtglib.UnknownSecretClose
	if l.OnUnknownSecret.Get(TypeUnknownSecretActionClose) == TypeUnknownSecretActionDrain {
		action = mtglib.UnknownSecretDrain
	}

	return mtglib.ListenerPolicy{
		Modes:           set,
		Public:          l.Public.Get(false),
		ProxyProtocol:   l.ProxyProtocol.Get(false),
		OnUnknownSecret: action,
		HandshakesPerIP: l.HandshakesPerIP.Get(defaultHandshakesPerIP),
	}, nil
}

type ListConfig struct {
	Optional

	DownloadConcurrency TypeConcurrency    `json:"downloadConcurrency"`
	URLs                []TypeBlocklistURI `json:"urls"`
	UpdateEach          TypeDuration       `json:"updateEach"`
}

type Config struct {
	Debug                       TypeBool                     `json:"debug"`
	AllowFallbackOnUnknownDC    TypeBool                     `json:"allowFallbackOnUnknownDc"`
	Secret                      mtglib.Secret                `json:"secret"`
	Secrets                     map[string]mtglib.Secret     `json:"secrets"`
	AdTag                       TypeAdTag                    `json:"adTag"`
	SecretAdTags                map[string]TypeAdTag         `json:"secretAdTags"`
	SecretLimits                map[string]ConfigSecretLimit `json:"secretLimits"`
	UsageStateFile              string                       `json:"usageStateFile"`
	APIToken                    string                       `json:"apiToken"`
	BindTo                      []TypeHostPort               `json:"bindTo"`
	Listeners                   []ConfigListener             `json:"listeners"`
	ProxyProtocolListener       TypeBool                     `json:"proxyProtocolListener"`
	PreferIP                    TypePreferIP                 `json:"preferIp"`
	AutoUpdate                  TypeBool                     `json:"autoUpdate"`
	DomainFrontingPort          TypePort                     `json:"domainFrontingPort"`
	DomainFrontingIP            TypeIP                       `json:"domainFrontingIp"`
	DomainFrontingProxyProtocol TypeBool                     `json:"domainFrontingProxyProtocol"`
	TolerateTimeSkewness        TypeDuration                 `json:"tolerateTimeSkewness"`
	Concurrency                 TypeConcurrency              `json:"concurrency"`
	PublicIPv4                  TypeIP                       `json:"publicIpv4"`
	PublicIPv6                  TypeIP                       `json:"publicIpv6"`
	DomainFronting              struct {
		Host          TypeHost `json:"host"`
		IP            TypeIP   `json:"ip"`
		Port          TypePort `json:"port"`
		ProxyProtocol TypeBool `json:"proxyProtocol"`
	} `json:"domainFronting"`
	Defense struct {
		AntiReplay struct {
			Optional

			MaxSize   TypeBytes     `json:"maxSize"`
			ErrorRate TypeErrorRate `json:"errorRate"`
		} `json:"antiReplay"`
		Blocklist    ListConfig `json:"blocklist"`
		Allowlist    ListConfig `json:"allowlist"`
		Doppelganger struct {
			URLs       []TypeHttpsURL  `json:"urls"`
			Repeats    TypeConcurrency `json:"repeats_per_raid"`
			UpdateEach TypeDuration    `json:"raid_each"`
			DRS        TypeBool        `json:"drs"`
		} `json:"doppelganger"`
	} `json:"defense"`
	Network struct {
		Timeout struct {
			TCP       TypeDuration `json:"tcp"`
			HTTP      TypeDuration `json:"http"`
			Idle      TypeDuration `json:"idle"`
			Handshake TypeDuration `json:"handshake"`
		} `json:"timeout"`
		KeepAlive struct {
			Disabled TypeBool        `json:"disabled"`
			Idle     TypeDuration    `json:"idle"`
			Interval TypeDuration    `json:"interval"`
			Count    TypeConcurrency `json:"count"`
		} `json:"keepAlive"`
		DOHIP           TypeIP         `json:"dohIp"`
		DNS             TypeDNSURI     `json:"dns"`
		Proxies         []TypeProxyURL `json:"proxies"`
		TCPNotSentLowat TypeBytes      `json:"tcpNotSentLowat"`
	} `json:"network"`
	APIBindTo TypeHostPort `json:"apiBindTo"`
	Throttle  struct {
		MaxConnections TypeConcurrency `json:"maxConnections"`
		CheckInterval  TypeDuration    `json:"checkInterval"`
	} `json:"throttle"`
	Stats struct {
		StatsD struct {
			Optional

			Address      TypeHostPort        `json:"address"`
			MetricPrefix TypeMetricPrefix    `json:"metricPrefix"`
			TagFormat    TypeStatsdTagFormat `json:"tagFormat"`
		} `json:"statsd"`
		Prometheus struct {
			Optional

			BindTo       TypeHostPort     `json:"bindTo"`
			HTTPPath     TypeHTTPPath     `json:"httpPath"`
			MetricPrefix TypeMetricPrefix `json:"metricPrefix"`
		} `json:"prometheus"`
	} `json:"stats"`
}

func (c *Config) GetConcurrency(defaultValue uint) uint {
	if concurrency := c.Concurrency.Get(0); concurrency != 0 {
		return concurrency
	}
	return c.Concurrency.Get(defaultValue)
}

func (c *Config) GetDNS() *url.URL {
	var dohURL *url.URL

	if dohIP := c.Network.DOHIP.Get(nil); dohIP != nil {
		dohURL, _ = url.Parse("https://" + dohIP.String())
	}

	return c.Network.DNS.Get(dohURL)
}

func (c *Config) GetDomainFrontingPort(defaultValue uint) uint {
	if port := c.DomainFronting.Port.Get(0); port != 0 {
		return port
	}
	return c.DomainFrontingPort.Get(defaultValue)
}

func (c *Config) GetDomainFrontingHost() string {
	return c.DomainFronting.Host.Get("")
}

func (c *Config) GetDomainFrontingProxyProtocol(defaultValue bool) bool {
	return c.DomainFronting.ProxyProtocol.Get(false) || c.DomainFrontingProxyProtocol.Get(defaultValue)
}

func (c *Config) Validate() error {
	if len(c.Secrets) == 0 {
		if !c.Secret.Valid() {
			return fmt.Errorf("invalid secret %s", c.Secret.String())
		}
	} else {
		for name, s := range c.Secrets {
			if !s.Valid() {
				return fmt.Errorf("invalid secret %q: %s", name, s.String())
			}
		}
	}

	if len(c.BindTo) == 0 {
		return fmt.Errorf("incorrect bind-to parameter: no addresses specified")
	}

	seen := make(map[string]struct{}, len(c.BindTo))

	for _, addr := range c.BindTo {
		v := addr.Get("")
		if v == "" {
			return fmt.Errorf("incorrect bind-to parameter: empty address")
		}

		if _, ok := seen[v]; ok {
			return fmt.Errorf("duplicate bind-to address: %s", v)
		}

		seen[v] = struct{}{}
	}

	if err := c.validateListeners(seen); err != nil {
		return err
	}

	// V4: bind-to is mandatory and permanently ee-only, so every process has a
	// FakeTLS listener. Without a hostname to fall back to it could not front a
	// failed ClientHello, and closing instead is exactly the distinguisher the
	// fronting path exists to avoid.
	if !mtglib.SecretsCanFront(c.GetSecrets(), c.GetDomainFrontingHost()) {
		return fmt.Errorf("no secret carries a fronting hostname and domain-fronting.host is unset; " +
			"the FakeTLS listener would have no cover site. " +
			"Set domain-fronting.host, or keep at least one ee secret")
	}

	if err := c.validateAdTags(); err != nil {
		return err
	}

	if err := c.validateSecretLimits(); err != nil {
		return err
	}

	return nil
}

// validateListeners enforces V1-V3 for the [[listener]] blocks. It is handed
// the map already holding every top-level bind-to address, so one lookup catches
// a collision inside either group and across the two: an address serves exactly
// one accept policy, and two sockets on it would race for the same port.
func (c *Config) validateListeners(seen map[string]struct{}) error {
	for _, l := range c.Listeners {
		addr := l.BindTo.Get("")
		if addr == "" {
			return fmt.Errorf("incorrect listener bind-to parameter: empty address")
		}

		if _, ok := seen[addr]; ok {
			return fmt.Errorf("two listeners bind %s; one address serves one accept policy", addr)
		}

		seen[addr] = struct{}{}

		policy, err := l.Policy()
		if err != nil {
			return err
		}

		if ip := net.ParseIP(l.BindTo.Host); (ip == nil || !ip.IsLoopback()) && !l.Public.Get(false) {
			return fmt.Errorf(
				"listener %s accepts %v on a public address. "+
					"A non-FakeTLS listener answers obfuscated2 and is fingerprintable as an MTProto proxy. "+
					"Set public = true on this [[listener]] to confirm, or bind it to 127.0.0.1",
				addr, policy.Modes.Strings())
		}
	}

	return nil
}

// validateAdTags ensures every [secret-ad-tags] entry names a secret that
// actually exists. Tag byte-length is already enforced at parse time by
// TypeAdTag.Set, so here we only guard against typos in the secret name.
func (c *Config) validateAdTags() error {
	if len(c.SecretAdTags) == 0 {
		return nil
	}

	known := make(map[string]struct{}, len(c.Secrets)+1)
	if len(c.Secrets) > 0 {
		for name := range c.Secrets {
			known[name] = struct{}{}
		}
	} else {
		known["default"] = struct{}{}
	}

	for name := range c.SecretAdTags {
		if _, ok := known[name]; !ok {
			return fmt.Errorf("secret-ad-tags refers to unknown secret %q", name)
		}
	}

	return nil
}

// validateSecretLimits ensures every [secret-limits] entry names a secret that
// actually exists. Field values are already validated at parse time by their
// Type* setters, so here we only guard against typos in the secret name.
func (c *Config) validateSecretLimits() error {
	if len(c.SecretLimits) == 0 {
		return nil
	}

	known := make(map[string]struct{}, len(c.Secrets)+1)
	if len(c.Secrets) > 0 {
		for name := range c.Secrets {
			known[name] = struct{}{}
		}
	} else {
		known["default"] = struct{}{}
	}

	for name := range c.SecretLimits {
		if _, ok := known[name]; !ok {
			return fmt.Errorf("secret-limits refers to unknown secret %q", name)
		}
	}

	return nil
}

// GetSecrets returns all secrets as a map. If the new [secrets] section is used,
// returns that map. Otherwise, wraps the single Secret as {"default": Secret}.
func (c *Config) GetSecrets() map[string]mtglib.Secret {
	if len(c.Secrets) > 0 {
		return c.Secrets
	}

	return map[string]mtglib.Secret{"default": c.Secret}
}

// GetAdTag returns the global advertising tag, or nil when none is configured.
func (c *Config) GetAdTag() *[mtglib.AdTagLength]byte {
	return c.AdTag.Get()
}

// GetSecretAdTags returns the per-secret advertising tag overrides keyed by
// secret name, or nil when none are configured.
func (c *Config) GetSecretAdTags() map[string][mtglib.AdTagLength]byte {
	if len(c.SecretAdTags) == 0 {
		return nil
	}

	out := make(map[string][mtglib.AdTagLength]byte, len(c.SecretAdTags))

	for name, tag := range c.SecretAdTags {
		if t := tag.Get(); t != nil {
			out[name] = *t
		}
	}

	return out
}

// GetSecretLimits converts the [secret-limits] tables into the engine-level
// map keyed by secret name, or nil when none impose any restriction.
func (c *Config) GetSecretLimits() map[string]mtglib.SecretLimits {
	if len(c.SecretLimits) == 0 {
		return nil
	}

	out := make(map[string]mtglib.SecretLimits, len(c.SecretLimits))

	for name, l := range c.SecretLimits {
		lim := mtglib.SecretLimits{
			QuotaBytes: int64(l.Quota.Get(0)),
			ExpiresAt:  l.Expires.Get(time.Time{}),
			Disabled:   l.Disabled.Get(false),
		}

		if l.QuotaReset.Get("none") == mtglib.QuotaResetMonthly.String() {
			lim.QuotaReset = mtglib.QuotaResetMonthly
		}

		if lim.IsZero() {
			continue
		}

		out[name] = lim
	}

	if len(out) == 0 {
		return nil
	}

	return out
}

// GetAPIToken returns the bearer token guarding the management API, or an empty
// string when the API should stay unauthenticated (localhost-bind convention).
func (c *Config) GetAPIToken() string {
	return c.APIToken
}

// GetBindAddrs returns all bind addresses as strings.
func (c *Config) GetBindAddrs() []string {
	addrs := make([]string, len(c.BindTo))

	for i, hp := range c.BindTo {
		addrs[i] = hp.Get("")
	}

	return addrs
}

// GetListeners returns every configured [[listener]], or nil.
func (c *Config) GetListeners() []ConfigListener {
	if len(c.Listeners) == 0 {
		return nil
	}

	return c.Listeners
}

// GetListenerModes returns the union of every [[listener]]'s accept set, for
// the /stats capability report and the unserved-secret warning.
func (c *Config) GetListenerModes() mtglib.ModeSet {
	var set mtglib.ModeSet

	for _, l := range c.Listeners {
		for _, entry := range l.Accept {
			set |= mtglib.ModeSetOf(entry.Get())
		}
	}

	return set
}

// GetFirstBindPort returns the port of the first bind address.
func (c *Config) GetFirstBindPort() uint {
	if len(c.BindTo) == 0 {
		return 0
	}

	return c.BindTo[0].Port
}

func (c *Config) String() string {
	buf := &bytes.Buffer{}
	encoder := json.NewEncoder(buf)

	encoder.SetEscapeHTML(false)

	if err := encoder.Encode(c); err != nil {
		panic(err)
	}

	return buf.String()
}
