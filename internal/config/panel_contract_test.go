package config_test

import (
	"testing"

	"github.com/Arman2122/mtg-proxy/internal/config"
	"github.com/Arman2122/mtg-proxy/mtglib"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The Penhoon Panel (github.com/Arman2122/p-ui) generates this file and runs
// mtg-proxy against it, one process per inbound, plus the WEB relay as a second
// process reading the same file. That coupling lives in the other repo, so
// nothing there or here notices if the two drift -- this pins the shape the
// panel actually emits, key spelling and section order included.
//
// Section order is load-bearing twice over: TOML puts every key after a header
// inside that table, so [secrets] must stay last, and the panel's own
// renderConfig test asserts the same thing from its side.
func TestPanelEmittedConfigIsAccepted(t *testing.T) {
	t.Parallel()

	const rendered = `bind-to = "0.0.0.0:8443"
api-bind-to = "127.0.0.1:41337"
api-token = "tok"
track-client-ips = true

[throttle]
max-connections = 5000

[[listener]]
bind-to = "127.0.0.1:2398"
accept = ["dd", "plain"]
proxy-protocol = true

[web]
enabled = true
host = "web.example.com"
bind-to = "127.0.0.1:8099"
backend = "127.0.0.1:2398"
token-key = "/etc/p-ui/mtproto/7.web.key"
cover-dir = "/srv/site"
stats-bind-to = "127.0.0.1:8100"

[secret-ad-tags]
"alice" = "0123456789abcdef0123456789abcdef"

[secret-limits."alice"]
quota = "1073741824B"
expires = "2026-12-31T23:59:59Z"
speed-up = "125000"
speed-down = "250000"
ip-limit = 3

[secrets]
"alice" = "ee367a189aee18fa31c190054efd4a8e9573746f726167652e676f6f676c65617069732e636f6d"
`

	conf, err := config.Parse([]byte(rendered))
	require.NoError(t, err, "the proxy must parse the panel's rendered config")

	// A loopback listener carries no public = true: requiring one would make
	// every panel-managed WEB backend fail validation at cold start.
	require.NoError(t, conf.Validate())
	assert.Empty(t, conf.UnknownKeys, "every key the panel writes is one this binary reads")

	listeners := conf.GetListeners()
	require.Len(t, listeners, 1)

	policy, err := listeners[0].Policy()
	require.NoError(t, err)
	require.True(t, policy.Obfuscated())
	require.Equal(t, []string{"dd", "plain"}, policy.Modes.Strings())
	assert.True(t, listeners[0].ProxyProtocol.Get(false),
		"the relay hands the browser's address to the proxy over PROXY v2, and the listener must expect it")

	// The same file starts the relay: its checks are the ones `web-relay --check`
	// runs, and none of them touch the disk, so the panel can validate before
	// it writes anything.
	require.NoError(t, conf.ValidateWeb())

	backend, found := conf.WebBackendListener()
	require.True(t, found, "[web] backend must name the panel's loopback listener")
	assert.True(t, backend.ProxyProtocol.Get(false))

	// The limits, spelled as the panel spells them: a byte count with a B, an
	// RFC3339 expiry, per-direction speeds as bare bytes per second, and the
	// address limit as a bare integer.
	limits := conf.GetSecretLimits()
	require.Len(t, limits, 1)

	alice := limits["alice"]
	assert.Equal(t, int64(1<<30), alice.QuotaBytes)
	assert.Equal(t, 2026, alice.ExpiresAt.Year())
	assert.Equal(t, int64(125_000), alice.SpeedUpBytesPerSecond)
	assert.Equal(t, int64(250_000), alice.SpeedDownBytesPerSecond)
	assert.Zero(t, alice.SpeedBytesPerSecond, "the panel never writes the combined cap")
	assert.Equal(t, 3, alice.IPLimit)
	assert.Equal(t, mtglib.QuotaResetNone, alice.QuotaReset)
}
