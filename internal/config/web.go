package config

import (
	"fmt"
	"net"
	"strings"

	"github.com/Arman2122/mtg-proxy/internal/webrelay"
	"github.com/Arman2122/mtg-proxy/mtglib"
)

// ClientIPSource says how the relay learns the browser's address.
//
// It is a required decision rather than a default, because both wrong answers
// are silent. Trusting a header nobody sets makes every WEB user look like
// 127.0.0.1 -- the blocklist stops matching, the per-IP limits stop counting and
// every log names the loopback. Trusting one anybody can set hands those same
// controls to the client.
type ClientIPSource uint8

// The two ways a relay behind a front proxy can learn who is connecting.
const (
	// ClientIPProxyProtocol reads a PROXY header the front proxy writes. The
	// default, because it cannot be forged by the browser: it arrives before
	// the request, on a socket only the front proxy connects to.
	ClientIPProxyProtocol ClientIPSource = iota

	// ClientIPForwardedFor reads the right-most X-Forwarded-For entry, and only
	// from a loopback peer. Right-most because that is the entry the nearest
	// trusted hop appended; anything further left was written by whoever was
	// speaking before it.
	ClientIPForwardedFor
)

// TypeClientIPSource parses the client-ip setting.
type TypeClientIPSource struct {
	Value ClientIPSource
	set   bool
}

func (t *TypeClientIPSource) Set(value string) error {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "proxy-protocol", "proxy_protocol", "proxyprotocol":
		t.Value = ClientIPProxyProtocol
	case "x-forwarded-for", "forwarded-for", "xff":
		t.Value = ClientIPForwardedFor
	default:
		return fmt.Errorf("unknown client-ip source %q (expected \"proxy-protocol\" or \"x-forwarded-for\")", value)
	}

	t.set = true

	return nil
}

func (t TypeClientIPSource) Get(defaultValue ClientIPSource) ClientIPSource {
	if !t.set {
		return defaultValue
	}

	return t.Value
}

func (t *TypeClientIPSource) UnmarshalText(data []byte) error {
	return t.Set(string(data))
}

func (t TypeClientIPSource) MarshalText() ([]byte, error) {
	return []byte(t.String()), nil
}

func (t TypeClientIPSource) String() string {
	if t.Value == ClientIPForwardedFor {
		return "x-forwarded-for"
	}

	return "proxy-protocol"
}

// ConfigWeb is the [web] table: everything the WEB relay needs and the proxy
// ignores.
//
// It lives in the same file as the proxy's own settings on purpose. The relay is
// a second process of the same binary serving the same secrets, and the one
// thing it must agree with the proxy about -- whether the backend listener
// expects a PROXY header -- is already written in that listener's own stanza.
// Two places to say it is two places to disagree, and the disagreement is
// invisible: an unexpected header is consumed as the first bytes of the client's
// obfuscated handshake.
//
// An old binary ignores this table entirely, because parsing does not reject
// unknown keys. That is what lets a panel write it before every deployment has
// upgraded.
type ConfigWeb struct {
	Optional

	Host          TypeHost           `json:"host"`
	BindTo        TypeHostPort       `json:"bindTo"`
	Backend       TypeHostPort       `json:"backend"`
	TokenKey      string             `json:"tokenKey"`
	CoverDir      string             `json:"coverDir"`
	CoverUpstream string             `json:"coverUpstream"`
	ClientIP      TypeClientIPSource `json:"clientIp"`
	MaxSessions   TypeConcurrency    `json:"maxSessions"`
	MaxStreams    TypeConcurrency    `json:"maxStreams"`
	MaxPayload    TypeBytes          `json:"maxFramePayload"`
	BatchBytes    TypeBytes          `json:"carrierBatchBytes"`

	// StatsBindTo is the loopback address the relay serves its own counters on.
	// Empty (the default) means no stats server at all.
	//
	// Deliberately a second socket rather than a path on BindTo: that one is
	// published to the internet by the front proxy, and the relay's recognition
	// rule says everything without a credential it minted gets the cover site.
	// An endpoint there would be a fingerprint whether or not it was gated.
	StatsBindTo TypeHostPort `json:"statsBindTo"`
}

// WebBackendListener finds the [[listener]] stanza the [web] backend address
// names. The relay takes its PROXY-protocol decision from that stanza rather
// than from a setting of its own, so the two processes cannot disagree about
// what the socket between them speaks.
func (c *Config) WebBackendListener() (ConfigListener, bool) {
	backend := c.Web.Backend.Get("")
	if backend == "" {
		return ConfigListener{}, false
	}

	for _, listener := range c.Listeners {
		if sameAddress(listener.BindTo.Get(""), backend) {
			return listener, true
		}
	}

	return ConfigListener{}, false
}

// sameAddress compares two host:port strings by value rather than by spelling,
// so "127.0.0.1:2398" and "127.000.000.001:2398" are the same socket.
func sameAddress(left, right string) bool {
	leftHost, leftPort, err := net.SplitHostPort(left)
	if err != nil {
		return false
	}

	rightHost, rightPort, err := net.SplitHostPort(right)
	if err != nil {
		return false
	}

	if leftPort != rightPort {
		return false
	}

	leftIP, rightIP := net.ParseIP(leftHost), net.ParseIP(rightHost)
	if leftIP == nil || rightIP == nil {
		return leftHost == rightHost
	}

	return leftIP.Equal(rightIP)
}

// ValidateWeb checks the [web] table against the rest of the configuration.
//
// It is separate from Validate because the proxy must keep starting with a
// [web] table it does not understand or cannot satisfy: an operator editing the
// relay's settings has no business taking the MTProto port down.
func (c *Config) ValidateWeb() error {
	web := c.Web

	if !web.Enabled.Get(false) {
		return fmt.Errorf("[web] is not enabled in this configuration")
	}

	if _, err := webCanonicalHost(web.Host.Get("")); err != nil {
		return err
	}

	if web.BindTo.Get("") == "" {
		return fmt.Errorf("[web] bind-to is required")
	}

	if web.Backend.Get("") == "" {
		return fmt.Errorf("[web] backend is required")
	}

	if web.TokenKey == "" {
		return fmt.Errorf("[web] token-key is required; create one with 'mtg-proxy generate-web-key <path>'")
	}

	if (web.CoverDir == "") == (web.CoverUpstream == "") {
		return fmt.Errorf("[web] needs exactly one of cover-dir or cover-upstream: " +
			"the hostname must serve a plausible website to everyone who is not a Telegram client")
	}

	// Refused, not warned about. This socket answers, with no credential at
	// all, how many sessions the relay is carrying and how many bytes it has
	// moved -- the traffic analysis this whole transport exists to deny. An
	// operator who typed a public address has published that, and a line in a
	// log is not where they would find out.
	if err := webrelay.ValidateStatsBind(web.StatsBindTo.Get("")); err != nil {
		return err
	}

	listener, found := c.WebBackendListener()
	if !found {
		return fmt.Errorf("[web] backend %s names no [[listener]]; "+
			"the relay dials one of this proxy's own loopback sockets", web.Backend.Get(""))
	}

	policy, err := listener.Policy()
	if err != nil {
		return fmt.Errorf("[web] backend listener: %w", err)
	}

	// A WEB client's secret is dd, so the backend listener has to accept dd.
	// Refusing here rather than at the first connection turns a silent
	// per-stream failure into a startup message.
	if !policy.Modes.Has(mtglib.SecretModeDD) {
		return fmt.Errorf("[web] backend %s does not accept dd secrets, which is the only form a WEB client can hold",
			web.Backend.Get(""))
	}

	return nil
}

// webCanonicalHost is a small local check so config does not import webrelay,
// which would be a cycle in waiting: the relay reads config. The authoritative
// canonicalisation lives with the capability derivation, and this only catches
// the shapes an operator types.
func webCanonicalHost(host string) (string, error) {
	if host == "" {
		return "", fmt.Errorf("[web] host is required: it is the name a client derives its capability over")
	}

	if strings.ContainsAny(host, ":/?#@ ") {
		return "", fmt.Errorf("[web] host %q must be a bare hostname, not a URL", host)
	}

	if !strings.Contains(host, ".") {
		return "", fmt.Errorf("[web] host %q must be a fully qualified name with a public certificate", host)
	}

	if net.ParseIP(host) != nil {
		return "", fmt.Errorf("[web] host %q is an IP address; a WEB client refuses one", host)
	}

	return strings.ToLower(host), nil
}
