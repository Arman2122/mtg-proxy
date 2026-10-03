package main

import (
	"net"
	"os"
	"regexp"
	"strconv"
	"testing"

	"github.com/Arman2122/mtg-proxy/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func benchSetup(t *testing.T) Setup {
	t.Helper()

	return Setup{
		Dir:      t.TempDir(),
		Users:    []User{NewUser("alice"), NewUser("bob")},
		Doors:    AllDoors,
		Shaping:  "burst",
		Caps:     map[string]Caps{"bob": {Speed: "10MB", Up: "1MB", Down: "2MB"}},
		BasePort: 47000,
		APIToken: "test-token",
	}
}

// What mtgbench writes is a config the real binary accepts in full: the proxy's
// validation and the relay's both.
func TestGeneratedConfigValidates(t *testing.T) {
	t.Parallel()

	path, err := WriteConfig(benchSetup(t))
	require.NoError(t, err)

	raw, err := os.ReadFile(path)
	require.NoError(t, err)

	conf, err := config.Parse(raw)
	require.NoError(t, err)
	require.NoError(t, conf.Validate())
	require.NoError(t, conf.ValidateWeb())

	limits := conf.GetSecretLimits()
	assert.Equal(t, int64(10<<20), limits["bob"].SpeedBytesPerSecond)
	assert.Equal(t, int64(1<<20), limits["bob"].SpeedUpBytesPerSecond)
	assert.Equal(t, int64(2<<20), limits["bob"].SpeedDownBytesPerSecond)
}

// Nothing in the generated config may reach the internet: every outbound dial
// the binary makes on its own is either through mtgbench's SOCKS5 or to its
// local cover listener.
func TestGeneratedConfigStaysOnLoopback(t *testing.T) {
	t.Parallel()

	path, err := WriteConfig(benchSetup(t))
	require.NoError(t, err)

	raw, err := os.ReadFile(path)
	require.NoError(t, err)

	conf, err := config.Parse(raw)
	require.NoError(t, err)

	text := string(raw)
	assert.Contains(t, text, `proxies = ["socks5://127.0.0.1:47010"]`)
	assert.Contains(t, text, "scout-covers = false")
	assert.Contains(t, text, `public-ipv4 = "127.0.0.1"`)
	assert.Equal(t, "127.0.0.1", conf.DomainFronting.Host.Get(""), "fronting goes to mtgbench's cover listener")
	assert.Equal(t, uint(47011), conf.DomainFronting.Port.Get(0), "on the cover listener's own port")
	assert.Contains(t, text, `public-ipv6 = "::1"`, "the binary never asks the internet for its address")
	assert.NotContains(t, text, "auto-update = true")

	// Every address the binary listens on is loopback, inside the run's ports.
	for _, m := range regexp.MustCompile(`(?m)^(?:bind-to|api-bind-to|backend|stats-bind-to) = "([^"]+)"$`).FindAllStringSubmatch(text, -1) {
		host, port, err := net.SplitHostPort(m[1])
		require.NoError(t, err)
		assert.True(t, net.ParseIP(host).IsLoopback(), m[0])

		n, err := strconv.Atoi(port)
		require.NoError(t, err)
		assert.True(t, n >= 47000 && n <= 47012, m[0])
	}
}

// Without a token the management API would be open to anyone on the box.
func TestGeneratedConfigNeedsAToken(t *testing.T) {
	t.Parallel()

	s := benchSetup(t)
	s.APIToken = ""

	_, err := WriteConfig(s)
	require.ErrorIs(t, err, errNoToken)
}
