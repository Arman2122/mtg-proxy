package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/Arman2122/mtg-proxy/internal/webrelay"
	"github.com/Arman2122/mtg-proxy/mtglib"
)

// Door is one way in: FakeTLS, obfuscated2 with a dd or a plain secret, or WEB.
type Door string

const (
	DoorEE    Door = "ee"
	DoorDD    Door = "dd"
	DoorPlain Door = "plain"
	DoorWeb   Door = "web"
)

// AllDoors is every door, in report order.
var AllDoors = []Door{DoorEE, DoorDD, DoorPlain, DoorWeb}

// The ee door's shapings. Shaping is process-wide, so each is its own stack.
const (
	shapingRecord = "record"
	shapingBurst  = "burst"
)

// A run's ports: the standing stack takes base to base+12, a fresh one
// base+freshOffset to base+portSpan.
const (
	freshOffset = 20
	portSpan    = 32
)

// The hosts mtgbench names. The cover host is what ee clients put in SNI; its
// fronting goes to mtgbench's own cover listener, never to the internet.
const (
	coverHost = "cover.bench.example"
	webHost   = "web.bench.example"
)

// User is one secret: a name and a key derived from it, so two runs of the
// same setup use the same keys.
type User struct {
	Name string
	Key  [16]byte
}

func NewUser(name string) User {
	sum := sha256.Sum256([]byte("mtgbench:" + name))

	var u User

	u.Name = name
	copy(u.Key[:], sum[:])

	return u
}

// Secret is u as an ee secret naming the cover host. The same key serves dd,
// plain and WEB.
func (u User) Secret() mtglib.Secret {
	return mtglib.Secret{Mode: mtglib.SecretModeFakeTLS, Key: u.Key, Host: coverHost}
}

// Capability is u's WEB capability, as the bridge link carries it.
func (u User) Capability() (string, error) {
	capability, err := webrelay.Derive(webrelay.WebSecret(u.Secret()), webHost)
	if err != nil {
		return "", fmt.Errorf("cannot derive %s's WEB capability: %w", u.Name, err)
	}

	return capability.String(), nil
}

// Caps are one user's speed limits in config spellings ("10MB"); empty is none.
type Caps struct{ Speed, Up, Down string }

// Setup is everything one run of the binary is configured with.
type Setup struct {
	Dir      string
	Users    []User
	Doors    []Door
	Shaping  string // "record" or "burst"
	Caps     map[string]Caps
	BasePort int

	// APIToken is the management API's bearer for the run: random, from
	// NewAPIToken, so nobody else on the box can guess it.
	APIToken string
}

// Ports, from BasePort.
func (s Setup) EEAddr() string         { return s.addr(0) }
func (s Setup) APIAddr() string        { return s.addr(1) }
func (s Setup) ObfuscatedAddr() string { return s.addr(2) }
func (s Setup) WebBackendAddr() string { return s.addr(3) }
func (s Setup) RelayAddr() string      { return s.addr(4) }
func (s Setup) RelayStatsAddr() string { return s.addr(5) }
func (s Setup) SOCKSAddr() string      { return s.addr(10) }
func (s Setup) CoverAddr() string      { return s.addr(11) }
func (s Setup) DirectAddr() string     { return s.addr(12) }

func (s Setup) addr(offset int) string {
	return "127.0.0.1:" + strconv.Itoa(s.BasePort+offset)
}

// Ports lists every port a run listens on, for the check that they are free.
func (s Setup) Ports() []string {
	return []string{
		s.EEAddr(), s.APIAddr(), s.ObfuscatedAddr(), s.WebBackendAddr(), s.RelayAddr(),
		s.RelayStatsAddr(), s.SOCKSAddr(), s.CoverAddr(), s.DirectAddr(),
	}
}

// NewAPIToken is a fresh random bearer for a run's management API.
func NewAPIToken() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("cannot make an API token: %w", err)
	}

	return hex.EncodeToString(b), nil
}

var errNoToken = errors.New("the setup has no API token")

// WriteConfig writes the run's config.toml, the relay's token key and a cover
// site into s.Dir, and returns the config's path.
//
// Every outbound dial the binary makes on its own stays on this machine:
// Telegram goes through mtgbench's SOCKS5, fronting goes to its cover listener,
// the doppelganger does not scout, the public address is given, and the public
// config is not fetched.
func WriteConfig(s Setup) (string, error) {
	if s.APIToken == "" {
		return "", errNoToken
	}

	_, coverPort, err := net.SplitHostPort(s.CoverAddr())
	if err != nil {
		return "", fmt.Errorf("cannot read the cover port: %w", err)
	}

	keyPath := filepath.Join(s.Dir, "web.key")
	coverDir := filepath.Join(s.Dir, "site")

	if err := writeTokenKey(keyPath); err != nil {
		return "", err
	}

	if err := os.MkdirAll(coverDir, 0o750); err != nil {
		return "", fmt.Errorf("cannot make the cover site: %w", err)
	}

	if err := os.WriteFile(filepath.Join(coverDir, "index.html"), []byte("<!doctype html><title>bench</title>\n"), 0o644); err != nil { //nolint: gosec // a public test page
		return "", fmt.Errorf("cannot write the cover site: %w", err)
	}

	var b strings.Builder

	fmt.Fprintf(&b, "bind-to = %q\n", s.EEAddr())
	fmt.Fprintf(&b, "api-bind-to = %q\n", s.APIAddr())
	fmt.Fprintf(&b, "api-token = %q\n", s.APIToken)
	b.WriteString("public-ipv4 = \"127.0.0.1\"\n")
	b.WriteString("public-ipv6 = \"::1\"\n")
	b.WriteString("concurrency = 16384\n")
	b.WriteString("track-client-ips = true\n\n")

	fmt.Fprintf(&b, "[[listener]]\nbind-to = %q\naccept = [\"dd\", \"plain\"]\n\n", s.ObfuscatedAddr())
	fmt.Fprintf(&b, "[[listener]]\nbind-to = %q\naccept = [\"dd\"]\nproxy-protocol = true\n\n", s.WebBackendAddr())

	b.WriteString("[web]\nenabled = true\n")
	fmt.Fprintf(&b, "host = %q\nbind-to = %q\nbackend = %q\n", webHost, s.RelayAddr(), s.WebBackendAddr())
	fmt.Fprintf(&b, "token-key = %q\ncover-dir = %q\n", filepath.ToSlash(keyPath), filepath.ToSlash(coverDir))
	fmt.Fprintf(&b, "client-ip = \"x-forwarded-for\"\nstats-bind-to = %q\n\n", s.RelayStatsAddr())

	fmt.Fprintf(&b, "[domain-fronting]\nhost = \"127.0.0.1\"\nport = %s\n\n", coverPort)

	b.WriteString("[defense.doppelganger]\nscout-covers = false\n")
	fmt.Fprintf(&b, "shaping = %q\n\n", s.Shaping)

	fmt.Fprintf(&b, "[network]\nproxies = [\"socks5://%s\"]\n\n", s.SOCKSAddr())
	// Long enough for the idle scenario to hold its connections.
	b.WriteString("[network.timeout]\nhandshake = \"10s\"\nidle = \"10m\"\n\n")

	b.WriteString("[secrets]\n")

	for _, u := range s.Users {
		fmt.Fprintf(&b, "%q = %q\n", u.Name, u.Secret().Hex())
	}

	for _, u := range s.Users {
		caps, ok := s.Caps[u.Name]
		if !ok {
			continue
		}

		fmt.Fprintf(&b, "\n[secret-limits.%q]\n", u.Name)

		for _, kv := range [][2]string{{"speed", caps.Speed}, {"speed-up", caps.Up}, {"speed-down", caps.Down}} {
			if kv[1] != "" {
				fmt.Fprintf(&b, "%s = %q\n", kv[0], kv[1])
			}
		}
	}

	path := filepath.Join(s.Dir, "config.toml")
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		return "", fmt.Errorf("cannot write the config: %w", err)
	}

	return path, nil
}

func writeTokenKey(path string) error {
	key := make([]byte, webrelay.TokenKeySize)
	if _, err := rand.Read(key); err != nil {
		return fmt.Errorf("cannot make the relay's token key: %w", err)
	}

	if err := os.WriteFile(path, key, 0o600); err != nil {
		return fmt.Errorf("cannot write the relay's token key: %w", err)
	}

	return nil
}
