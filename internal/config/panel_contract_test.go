package config_test

import (
	"testing"

	"github.com/Arman2122/mtg-proxy/internal/config"
	"github.com/stretchr/testify/require"
)

// The Penhoon Panel (github.com/Arman2122/p-ui) generates this file and runs
// mtg-proxy against it, one process per inbound. That coupling lives in the
// other repo, so nothing there or here notices if the two drift -- this pins the
// shape the panel actually emits, key spelling and section order included.
//
// Section order is load-bearing twice over: TOML puts every key after a header
// inside that table, so [secrets] must stay last, and the panel's own
// renderConfig test asserts the same thing from its side.
func TestPanelEmittedConfigIsAccepted(t *testing.T) {
	t.Parallel()

	const rendered = `bind-to = "0.0.0.0:8443"
api-bind-to = "127.0.0.1:41337"
api-token = "tok"

[throttle]
max-connections = 5000

[[listener]]
bind-to = "127.0.0.1:2398"
accept = ["dd", "plain"]

[secrets]
alice = "ee367a189aee18fa31c190054efd4a8e9573746f726167652e676f6f676c65617069732e636f6d"
`

	conf, err := config.Parse([]byte(rendered))
	require.NoError(t, err, "the proxy must parse the panel's rendered config")

	// A loopback listener carries no public = true: requiring one would make
	// every panel-managed WEB backend fail validation at cold start.
	require.NoError(t, conf.Validate())

	listeners := conf.GetListeners()
	require.Len(t, listeners, 1)

	policy, err := listeners[0].Policy()
	require.NoError(t, err)
	require.True(t, policy.Obfuscated())
	require.Equal(t, []string{"dd", "plain"}, policy.Modes.Strings())
}
