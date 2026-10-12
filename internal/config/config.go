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
// an optional data quota (with reset policy), a speed limit, an expiry
// deadline, a disabled flag, an address limit, a per-address connection cap, a
// per-address speed ceiling and the switch that divides the speed limits among
// the secret's addresses. All fields are optional; the zero value leaves the
// secret unrestricted.
type ConfigSecretLimit struct {
	Quota      TypeBytes      `json:"quota"`
	QuotaReset TypeQuotaReset `json:"quotaReset"`
	Expires    TypeExpiry     `json:"expires"`
	Disabled   TypeBool       `json:"disabled"`
	Speed      TypeSpeed      `json:"speed"`
	SpeedUp    TypeSpeed      `json:"speedUp"`
	SpeedDown  TypeSpeed      `json:"speedDown"`
	IPLimit    TypeIPLimit    `json:"ipLimit"`

	// The per-address controls carry omitzero, so a table that does not use
	// them -- every one a panel writes -- renders in Config.String() exactly
	// as it did before they existed.
	ClientConns TypeClientConns `json:"clientConns,omitzero"`
	ClientSpeed TypeClientSpeed `json:"clientSpeed,omitzero"`
	ClientFair  TypeBool        `json:"clientFair,omitzero"`
}

// ConfigRetiringSecret is one [[retiring-secret]] block, its three fields as
// the file spelled them: Name, Secret (the old value, hex or base64url, any
// mode) and Until (an RFC 3339 instant; a TOML offset date-time arrives here
// in RFC 3339 with nanoseconds). None is parsed while decoding, so a bad value
// never fails the file and no decoder error, which carries no entry index and
// might echo the value, is ever raised; GetRetiringSecrets parses and judges
// them. Secret is a credential: Config.String() redacts it.
type ConfigRetiringSecret struct {
	Name   string `json:"name"`
	Secret string `json:"secret"`
	Until  string `json:"until"`

	// wrongType marks, one bit per field, the fields whose TOML value had the
	// wrong type: their text above is fmt.Sprint of that value. Parse sets it
	// after the JSON step, which an unexported field does not cross, and for
	// the same reason Config.String() never shows it.
	wrongType uint8
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
				"Run two listeners if you need both", l.BindTo.Get(""),
		)
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
	Debug                    TypeBool                     `json:"debug"`
	AllowFallbackOnUnknownDC TypeBool                     `json:"allowFallbackOnUnknownDc"`
	Secret                   mtglib.Secret                `json:"secret"`
	Secrets                  map[string]mtglib.Secret     `json:"secrets"`
	AdTag                    TypeAdTag                    `json:"adTag"`
	SecretAdTags             map[string]TypeAdTag         `json:"secretAdTags"`
	SecretLimits             map[string]ConfigSecretLimit `json:"secretLimits"`

	// RetiringSecrets are the [[retiring-secret]] blocks, raw: a secret's
	// previous key and when it stops being accepted. GetRetiringSecrets judges
	// them; Validate never does, because a problem in one drops that entry and
	// never refuses the file. omitempty keeps Config.String() byte-identical
	// for every file without the table, the panel's included.
	RetiringSecrets []ConfigRetiringSecret `json:"retiringSecrets,omitempty"`

	// UnknownKeys are the dotted paths of every key the file carried that this
	// binary does not know, sorted. The parser is deliberately lenient -- a
	// file written for a newer binary must still load on an older one -- so a
	// typo, or a key in the wrong table, is not an error. It is not silent
	// either: whoever loads the file logs these. Not part of the config's own
	// rendering.
	UnknownKeys                 []string         `json:"-"`
	UsageStateFile              string           `json:"usageStateFile"`
	APIToken                    string           `json:"apiToken"`
	BindTo                      []TypeHostPort   `json:"bindTo"`
	Listeners                   []ConfigListener `json:"listeners"`
	Web                         ConfigWeb        `json:"web"`
	ProxyProtocolListener       TypeBool         `json:"proxyProtocolListener"`
	PreferIP                    TypePreferIP     `json:"preferIp"`
	AutoUpdate                  TypeBool         `json:"autoUpdate"`
	TrackClientIPs              TypeBool         `json:"trackClientIps"`
	DomainFrontingPort          TypePort         `json:"domainFrontingPort"`
	DomainFrontingIP            TypeIP           `json:"domainFrontingIp"`
	DomainFrontingProxyProtocol TypeBool         `json:"domainFrontingProxyProtocol"`
	TolerateTimeSkewness        TypeDuration     `json:"tolerateTimeSkewness"`
	Concurrency                 TypeConcurrency  `json:"concurrency"`
	PublicIPv4                  TypeIP           `json:"publicIpv4"`
	PublicIPv6                  TypeIP           `json:"publicIpv6"`
	DomainFronting              struct {
		Host          TypeHost `json:"host"`
		IP            TypeIP   `json:"ip"`
		Port          TypePort `json:"port"`
		ProxyProtocol TypeBool `json:"proxyProtocol"`
	} `json:"domainFronting"`
	Defense struct {
		AntiReplay struct {
			// Enabled is nil when the config does not say: replay protection
			// is then on. Only an explicit false turns it off.
			Enabled *TypeBool `json:"enabled"`

			MaxSize   TypeBytes     `json:"maxSize"`
			ErrorRate TypeErrorRate `json:"errorRate"`
		} `json:"antiReplay"`
		Blocklist    ListConfig `json:"blocklist"`
		Allowlist    ListConfig `json:"allowlist"`
		Doppelganger struct {
			URLs       []TypeHttpsURL    `json:"urls"`
			Repeats    TypeConcurrency   `json:"repeats_per_raid"`
			UpdateEach TypeDuration      `json:"raid_each"`
			DRS        TypeBool          `json:"drs"`
			Shaping    TypeDoppelShaping `json:"shaping"`
			// ScoutCovers is nil when the config does not say: the cover
			// sites are then measured. Only an explicit false turns it off.
			ScoutCovers *TypeBool `json:"scout_covers"`
		} `json:"doppelganger"`

		// HandshakeBudget is [defense.handshake-budget]. Its fields are the
		// zero value when the config does not say, which every getter below
		// reads as "the default"; omitzero keeps a config that does not use
		// the table rendering exactly as it did before the table existed.
		HandshakeBudget struct {
			Mode TypeHandshakeBudgetMode `json:"mode"`

			// PerIPMillis is nil when the config does not say (50); an
			// explicit 0 is a non-nil pointer to 0 and turns the per-address
			// bucket off.
			PerIPMillis *TypeHandshakeBudgetPerIP `json:"perIpMs,omitempty"`

			CPUPercent TypeHandshakeBudgetCPU `json:"cpuPercent"`

			// Hints is nil when the config does not say: the cache then
			// follows track-client-ips. Only an explicit value overrides it,
			// in either direction.
			Hints *TypeBool `json:"hints,omitempty"`
		} `json:"handshakeBudget,omitzero"`
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
				addr, policy.Modes.Strings(),
			)
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

// UnknownKeyWarnings renders one warning per unknown key, in the words the
// log and the doctor both use.
func (c *Config) UnknownKeyWarnings() []string {
	out := make([]string, 0, len(c.UnknownKeys))

	for _, key := range c.UnknownKeys {
		out = append(out, fmt.Sprintf(
			"unknown config key %q is ignored: a typo, or a key written under the wrong table?", key))
	}

	return out
}

// validateSecretLimits ensures every [secret-limits] entry names a secret that
// actually exists, and that a table turning client-fair on has a speed for it
// to divide. Field values are already validated at parse time by their Type*
// setters; what is left is the secret name, and the one rule that spans two
// keys of a table.
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

	for name, l := range c.SecretLimits {
		if _, ok := known[name]; !ok {
			return fmt.Errorf("secret-limits refers to unknown secret %q", name)
		}

		// client-speed is not a speed fair share divides: it holds one
		// address, and fair share divides what the secret as a whole may move.
		if l.ClientFair.Get(false) && l.Speed.Get(0) == 0 && l.SpeedUp.Get(0) == 0 && l.SpeedDown.Get(0) == 0 {
			return fmt.Errorf(
				"secret-limits.%s: client-fair divides the secret's speed among its addresses "+
					"and needs speed, speed-up or speed-down beside it", name)
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
			QuotaBytes:                l.Quota.Get(0),
			ExpiresAt:                 l.Expires.Get(time.Time{}),
			Disabled:                  l.Disabled.Get(false),
			SpeedBytesPerSecond:       l.Speed.Get(0),
			SpeedUpBytesPerSecond:     l.SpeedUp.Get(0),
			SpeedDownBytesPerSecond:   l.SpeedDown.Get(0),
			IPLimit:                   l.IPLimit.Get(0),
			ClientConns:               l.ClientConns.Get(0),
			ClientSpeedBytesPerSecond: l.ClientSpeed.Get(0),
			ClientFair:                l.ClientFair.Get(false),
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

// GetHandshakeBudgetMode returns [defense.handshake-budget] mode, or "" when the
// config does not say, which mtglib reads as enforce.
func (c *Config) GetHandshakeBudgetMode() string {
	return c.Defense.HandshakeBudget.Mode.Get("")
}

// GetHandshakeBudgetPerIPMillis returns [defense.handshake-budget] per-ip-ms, or
// nil when the config does not say, which mtglib reads as 50. An explicit 0 is
// returned as a pointer to 0: it turns the per-address bucket off.
func (c *Config) GetHandshakeBudgetPerIPMillis() *uint {
	perIP := c.Defense.HandshakeBudget.PerIPMillis
	if perIP == nil {
		return nil
	}

	value := perIP.Value

	return &value
}

// GetHandshakeBudgetCPUPercent returns [defense.handshake-budget] cpu-percent, or
// 0 when the config does not say, which mtglib reads as 25. The file cannot say
// 0: it is refused when parsed.
func (c *Config) GetHandshakeBudgetCPUPercent() uint {
	return c.Defense.HandshakeBudget.CPUPercent.Get(0)
}

// GetHandshakeHints returns [defense.handshake-budget] hints, or nil when the
// config does not say, which mtglib reads as "follow track-client-ips". An
// explicit false is returned as a pointer to false, and is what keeps the hint
// cache off under track-client-ips = true.
func (c *Config) GetHandshakeHints() *bool {
	hints := c.Defense.HandshakeBudget.Hints
	if hints == nil {
		return nil
	}

	// Get(false), never Get(true): TypeBool.Get is an OR, so a true default
	// would turn an explicit false into true.
	value := hints.Get(false)

	return &value
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

// redactedValue replaces every credential in the rendering below. It is a fixed
// string rather than an empty one so a reader can tell "not configured" from
// "not shown".
const redactedValue = "[redacted]"

// String renders the configuration for a log line, with the credentials taken
// out.
//
// Its one caller is a Debug log, and it used to serialise the struct verbatim:
// switching debug on wrote every client's secret and the management API token
// into the operator's log file, where they outlive the process and are read by
// whatever ships the logs. Names are kept, because knowing which secrets are
// configured is the entire value of that line, and values are not.
func (c *Config) String() string {
	fields := map[string]any{}

	// The intermediate holds the real values and never leaves this function.
	//nolint:gosec // G117: every credential is replaced below, before returning
	raw, err := json.Marshal(c)
	if err != nil {
		panic(err)
	}

	if err := json.Unmarshal(raw, &fields); err != nil {
		panic(err)
	}

	redactConfigCredentials(fields)
	redactMistypedRetiringFields(fields, c.RetiringSecrets)

	buf := &bytes.Buffer{}
	encoder := json.NewEncoder(buf)

	encoder.SetEscapeHTML(false)

	if err := encoder.Encode(fields); err != nil {
		panic(err)
	}

	return buf.String()
}

// redactConfigCredentials blanks the values that authenticate somebody, in
// place. The keys are the JSON names of Config's own fields; a field added to
// Config that carries a credential has to be added here too, which is what
// TestConfigStringRedactsEveryCredential is for.
func redactConfigCredentials(fields map[string]any) {
	// The ad tag is a credential too: it is what @MTProxybot issued to this
	// operator, and whoever holds it can present another proxy's traffic as
	// this one's.
	for _, key := range []string{"secret", "apiToken", "adTag"} {
		if _, found := fields[key]; found {
			fields[key] = redactedValue
		}
	}

	// The named secrets and per-user ad tags keep their names: which clients
	// exist is the reason to log the configuration at all, and the key is not
	// the credential.
	for _, table := range []string{"secrets", "secretAdTags"} {
		named, ok := fields[table].(map[string]any)
		if !ok {
			continue
		}

		for name := range named {
			named[name] = redactedValue
		}
	}

	// A retiring entry keeps its name and until -- which rotations are
	// configured, and until when, is the point of the line -- and loses its
	// value, the old link's credential (D21).
	for _, entry := range retiringEntryFields(fields) {
		if _, found := entry["secret"]; found {
			entry["secret"] = redactedValue
		}
	}
}

// redactMistypedRetiringFields blanks a retiring entry's name or until when
// its TOML value had the wrong type. Such a field holds fmt.Sprint of an
// array or an inline table, which can carry a value pasted in the wrong
// place; a string name or until is shown as written.
func redactMistypedRetiringFields(fields map[string]any, entries []ConfigRetiringSecret) {
	for i, entry := range retiringEntryFields(fields) {
		if i >= len(entries) {
			return
		}

		if entries[i].wrongType&retiringNameWrongType != 0 {
			entry["name"] = redactedValue
		}

		if entries[i].wrongType&retiringUntilWrongType != 0 {
			entry["until"] = redactedValue
		}
	}
}

// retiringEntryFields is the rendering's retiringSecrets list, one map per
// entry, in file order; nil when the table is absent.
func retiringEntryFields(fields map[string]any) []map[string]any {
	list, ok := fields["retiringSecrets"].([]any)
	if !ok {
		return nil
	}

	out := make([]map[string]any, 0, len(list))

	for _, item := range list {
		entry, ok := item.(map[string]any)
		if !ok {
			entry = map[string]any{}
		}

		out = append(out, entry)
	}

	return out
}
