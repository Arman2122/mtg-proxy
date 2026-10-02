package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/pelletier/go-toml/v2"
)

type tomlConfig struct {
	Debug                    bool              `toml:"debug" json:"debug,omitempty"`
	AllowFallbackOnUnknownDC bool              `toml:"allow-fallback-on-unknown-dc" json:"allowFallbackOnUnknownDc,omitempty"`
	Secret                   string            `toml:"secret" json:"secret,omitempty"`
	Secrets                  map[string]string `toml:"secrets" json:"secrets,omitempty"`
	AdTag                    string            `toml:"ad-tag" json:"adTag,omitempty"`
	SecretAdTags             map[string]string `toml:"secret-ad-tags" json:"secretAdTags,omitempty"`
	SecretLimits             map[string]struct {
		Quota      string `toml:"quota" json:"quota,omitempty"`
		QuotaReset string `toml:"quota-reset" json:"quotaReset,omitempty"`
		Speed      string `toml:"speed" json:"speed,omitempty"`
		SpeedUp    string `toml:"speed-up" json:"speedUp,omitempty"`
		SpeedDown  string `toml:"speed-down" json:"speedDown,omitempty"`
		Expires    string `toml:"expires" json:"expires,omitempty"`
		Disabled   bool   `toml:"disabled" json:"disabled,omitempty"`
		IPLimit    int    `toml:"ip-limit" json:"ipLimit,omitempty"`
	} `toml:"secret-limits" json:"secretLimits,omitempty"`
	UsageStateFile string `toml:"usage-state-file" json:"usageStateFile,omitempty"`
	APIToken       string `toml:"api-token" json:"apiToken,omitempty"`
	BindTo         any    `toml:"bind-to" json:"bindTo"`
	Listeners      []struct {
		BindTo          string   `toml:"bind-to"           json:"bindTo"`
		Accept          []string `toml:"accept"            json:"accept,omitempty"`
		Public          bool     `toml:"public"            json:"public,omitempty"`
		ProxyProtocol   bool     `toml:"proxy-protocol"    json:"proxyProtocol,omitempty"`
		OnUnknownSecret string   `toml:"on-unknown-secret" json:"onUnknownSecret,omitempty"`
		HandshakesPerIP uint     `toml:"handshakes-per-ip" json:"handshakesPerIp,omitempty"`
	} `toml:"listener" json:"listeners,omitempty"`
	Web struct {
		Enabled           bool   `toml:"enabled"             json:"enabled,omitempty"`
		Host              string `toml:"host"                json:"host,omitempty"`
		BindTo            string `toml:"bind-to"             json:"bindTo,omitempty"`
		Backend           string `toml:"backend"             json:"backend,omitempty"`
		TokenKey          string `toml:"token-key"           json:"tokenKey,omitempty"`
		CoverDir          string `toml:"cover-dir"           json:"coverDir,omitempty"`
		CoverUpstream     string `toml:"cover-upstream"      json:"coverUpstream,omitempty"`
		ClientIP          string `toml:"client-ip"           json:"clientIp,omitempty"`
		MaxSessions       uint   `toml:"max-sessions"        json:"maxSessions,omitempty"`
		MaxStreams        uint   `toml:"max-streams"         json:"maxStreams,omitempty"`
		MaxFramePayload   string `toml:"max-frame-payload"   json:"maxFramePayload,omitempty"`
		CarrierBatchBytes string `toml:"carrier-batch-bytes" json:"carrierBatchBytes,omitempty"`
		StatsBindTo       string `toml:"stats-bind-to"      json:"statsBindTo,omitempty"`
	} `toml:"web" json:"web"`
	ProxyProtocolListener       bool   `toml:"proxy-protocol-listener" json:"proxyProtocolListener"`
	PreferIP                    string `toml:"prefer-ip" json:"preferIp,omitempty"`
	AutoUpdate                  bool   `toml:"auto-update" json:"autoUpdate,omitempty"`
	TrackClientIPs              bool   `toml:"track-client-ips" json:"trackClientIps,omitempty"`
	DomainFrontingPort          uint   `toml:"domain-fronting-port" json:"domainFrontingPort,omitempty"`
	DomainFrontingIP            string `toml:"domain-fronting-ip" json:"domainFrontingIp,omitempty"`
	DomainFrontingProxyProtocol bool   `toml:"domain-fronting-proxy-protocol" json:"domainFrontingProxyProtocol,omitempty"`
	TolerateTimeSkewness        string `toml:"tolerate-time-skewness" json:"tolerateTimeSkewness,omitempty"`
	Concurrency                 uint   `toml:"concurrency" json:"concurrency,omitempty"`
	PublicIPv4                  string `toml:"public-ipv4" json:"publicIpv4,omitempty"`
	PublicIPv6                  string `toml:"public-ipv6" json:"publicIpv6,omitempty"`
	DomainFronting              struct {
		Host          string `toml:"host" json:"host,omitempty"`
		IP            string `toml:"ip" json:"ip,omitempty"`
		Port          uint   `toml:"port" json:"port,omitempty"`
		ProxyProtocol bool   `toml:"proxy-protocol" json:"proxyProtocol,omitempty"`
	} `toml:"domain-fronting" json:"domainFronting"`
	Defense struct {
		AntiReplay struct {
			// A pointer, so an explicit "enabled = false" survives into the
			// typed config instead of reading as "not set": unset means on.
			Enabled   *bool   `toml:"enabled" json:"enabled,omitempty"`
			MaxSize   string  `toml:"max-size" json:"maxSize,omitempty"`
			ErrorRate float64 `toml:"error-rate" json:"errorRate,omitempty"`
		} `toml:"anti-replay" json:"antiReplay"`
		Blocklist struct {
			Enabled             bool     `toml:"enabled" json:"enabled,omitempty"`
			DownloadConcurrency uint     `toml:"download-concurrency" json:"downloadConcurrency,omitempty"`
			URLs                []string `toml:"urls" json:"urls,omitempty"`
			UpdateEach          string   `toml:"update-each" json:"updateEach,omitempty"`
		} `toml:"blocklist" json:"blocklist"`
		Allowlist struct {
			Enabled             bool     `toml:"enabled" json:"enabled,omitempty"`
			DownloadConcurrency uint     `toml:"download-concurrency" json:"downloadConcurrency,omitempty"`
			URLs                []string `toml:"urls" json:"urls,omitempty"`
			UpdateEach          string   `toml:"update-each" json:"updateEach,omitempty"`
		} `toml:"allowlist" json:"allowlist"`
		Doppelganger struct {
			URLs       []string `toml:"urls" json:"urls,omitempty"`
			Repeats    uint     `toml:"repeats-per-raid" json:"repeats_per_raid,omitempty"`
			UpdateEach string   `toml:"raid-each" json:"raid_each,omitempty"`
			DRS        bool     `toml:"drs" json:"drs,omitempty"`
			Shaping    string   `toml:"shaping" json:"shaping,omitempty"`
		} `toml:"doppelganger" json:"doppelganger"`
	} `toml:"defense" json:"defense"`
	Network struct {
		Timeout struct {
			TCP       string `toml:"tcp" json:"tcp,omitempty"`
			HTTP      string `toml:"http" json:"http,omitempty"`
			Idle      string `toml:"idle" json:"idle,omitempty"`
			Handshake string `toml:"handshake" json:"handshake,omitempty"`
		} `toml:"timeout" json:"timeout"`
		KeepAlive struct {
			Disabled bool   `toml:"disabled" json:"disabled,omitempty"`
			Idle     string `toml:"idle" json:"idle,omitempty"`
			Interval string `toml:"interval" json:"interval,omitempty"`
			Count    uint   `toml:"count" json:"count,omitempty"`
		} `toml:"keep-alive" json:"keepAlive"`
		DOHIP           string   `toml:"doh-ip" json:"dohIp,omitempty"`
		DNS             string   `toml:"dns" json:"dns,omitempty"`
		Proxies         []string `toml:"proxies" json:"proxies,omitempty"`
		TCPNotSentLowat string   `toml:"tcp-not-sent-lowat" json:"tcpNotSentLowat,omitempty"`
	} `toml:"network" json:"network"`
	APIBindTo string `toml:"api-bind-to" json:"apiBindTo,omitempty"`
	Throttle  struct {
		MaxConnections uint   `toml:"max-connections" json:"maxConnections,omitempty"`
		CheckInterval  string `toml:"check-interval" json:"checkInterval,omitempty"`
	} `toml:"throttle" json:"throttle"`
	Stats struct {
		StatsD struct {
			Enabled      bool   `toml:"enabled" json:"enabled,omitempty"`
			Address      string `toml:"address" json:"address,omitempty"`
			MetricPrefix string `toml:"metric-prefix" json:"metricPrefix,omitempty"`
			TagFormat    string `toml:"tag-format" json:"tagFormat,omitempty"`
		} `toml:"statsd" json:"statsd"`
		Prometheus struct {
			Enabled      bool   `toml:"enabled" json:"enabled,omitempty"`
			BindTo       string `toml:"bind-to" json:"bindTo,omitempty"`
			HTTPPath     string `toml:"http-path" json:"httpPath,omitempty"`
			MetricPrefix string `toml:"metric-prefix" json:"metricPrefix,omitempty"`
		} `toml:"prometheus" json:"prometheus"`
	} `toml:"stats" json:"stats"`
}

func Parse(rawData []byte) (*Config, error) {
	tomlConf := &tomlConfig{}
	jsonBuf := &bytes.Buffer{}
	conf := &Config{}

	jsonEncoder := json.NewEncoder(jsonBuf)
	jsonEncoder.SetEscapeHTML(false)
	jsonEncoder.SetIndent("", "")

	if err := toml.Unmarshal(rawData, tomlConf); err != nil {
		return nil, fmt.Errorf("cannot parse toml config: %w", err)
	}

	switch v := tomlConf.BindTo.(type) {
	case string:
		if v != "" {
			tomlConf.BindTo = []string{v}
		}
	case []any:
		strs := make([]string, len(v))

		for i, s := range v {
			str, ok := s.(string)
			if !ok {
				return nil, fmt.Errorf("bind-to array elements must be strings")
			}

			strs[i] = str
		}

		tomlConf.BindTo = strs
	}

	// G117: the buffer is decoded back into conf three lines down and never
	// leaves this function. This is the TOML-to-struct pipeline, not output.
	//nolint:gosec // an in-memory round trip
	if err := jsonEncoder.Encode(tomlConf); err != nil {
		panic(err)
	}

	if err := json.NewDecoder(jsonBuf).Decode(conf); err != nil {
		return nil, fmt.Errorf("cannot parse a config: %w", err)
	}

	if len(conf.BindTo) == 0 {
		return nil, fmt.Errorf("bind-to is required")
	}

	conf.UnknownKeys = unknownKeys(rawData)

	return conf, nil
}

// unknownKeys is the list of keys a strict decode of the same document would
// have refused. The lenient decode above is the one that counts; this second
// pass exists only to name what it dropped. Any failure of this pass other
// than unknown keys is ignored, because the document already parsed.
func unknownKeys(rawData []byte) []string {
	decoder := toml.NewDecoder(bytes.NewReader(rawData))
	decoder.DisallowUnknownFields()

	var (
		probe  tomlConfig
		strict *toml.StrictMissingError
	)

	if err := decoder.Decode(&probe); !errors.As(err, &strict) {
		return nil
	}

	keys := make([]string, 0, len(strict.Errors))

	for _, decodeErr := range strict.Errors {
		keys = append(keys, strings.Join(decodeErr.Key(), "."))
	}

	sort.Strings(keys)

	return slices.Compact(keys)
}
