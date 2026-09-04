package mtglib

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

// secretInfoFor pulls one user out of the /secrets snapshot.
func secretInfoFor(t *testing.T, p *Proxy, name string) SecretInfo {
	t.Helper()

	for _, info := range p.SnapshotSecrets() {
		if info.Name == name {
			return info
		}
	}

	t.Fatalf("no secret named %q in the snapshot", name)

	return SecretInfo{}
}

// GET /stats and GET /secrets must not disagree about the same user.
//
// They are built by different code that reads the same counters: /stats
// overlays inline in handleStats, /secrets goes through SnapshotSecrets and
// fillLimitInfo. Nothing forced them to agree, and the failure mode is a panel
// showing one number on a list page and a different one on the detail page for
// the same person at the same moment.
func TestStatsAndSecretsAgreeAboutAUser(t *testing.T) {
	t.Parallel()

	secret, err := GenerateSecretMode(SecretModeDD, "")
	require.NoError(t, err)

	entry := govEntryCases()[1]
	h := entry.harness(t, map[string]Secret{"alice": secret}, nil)
	h.proxy.trackClientIPs = true

	client, done := dialProxyFrom(t, h, entry.policy,
		&net.TCPAddr{IP: net.IPv4(198, 51, 100, 12), Port: 44444})

	upstream := connectThrough(t, entry, h, client, "alice", secret.Key)
	defer endStream(client, upstream, done)

	stats := statsFor(t, h.proxy).Users["alice"]
	info := secretInfoFor(t, h.proxy, "alice")

	require.Equal(t, stats.Connections, info.Connections,
		"the connection count must be the same number in both places")
	require.Equal(t, stats.ConnectedIPs, info.ConnectedIPs,
		"the live addresses must be the same list in both places")
	require.Equal(t, stats.LastIP, info.LastIP)
	require.Equal(t, stats.QuotaUsed, info.QuotaUsed)

	require.NotNil(t, stats.LastSeen)
	require.NotNil(t, info.LastSeen)
	require.True(t, stats.LastSeen.Equal(*info.LastSeen),
		"last_seen must be the same instant in both places")

	// The values are not merely equal to each other: they describe the stream
	// this test actually opened. Two endpoints agreeing on zero would satisfy
	// every assertion above.
	require.EqualValues(t, 1, info.Connections)
	require.Equal(t, []string{"198.51.100.12"}, info.ConnectedIPs)
	require.Equal(t, "198.51.100.12", info.LastIP)
}

// The address gate applies to /secrets exactly as it does to /stats, and the
// ungated runtime fields still answer.
//
// A panel that could learn an address from the detail endpoint while the stats
// endpoint withheld it would make track-client-ips decorative.
func TestSecretsHonoursTheAddressGate(t *testing.T) {
	t.Parallel()

	secret, err := GenerateSecretMode(SecretModeDD, "")
	require.NoError(t, err)

	entry := govEntryCases()[1]
	h := entry.harness(t, map[string]Secret{"alice": secret}, nil)

	require.False(t, h.proxy.trackClientIPs)

	client, done := dialProxyFrom(t, h, entry.policy,
		&net.TCPAddr{IP: net.IPv4(198, 51, 100, 12), Port: 44444})

	upstream := connectThrough(t, entry, h, client, "alice", secret.Key)
	defer endStream(client, upstream, done)

	info := secretInfoFor(t, h.proxy, "alice")

	require.Empty(t, info.ConnectedIPs, "no address may leak through the detail endpoint")
	require.Empty(t, info.LastIP)

	// Not gated, and still true: how many connections a user has says nothing
	// about where they are, and withholding it would break every panel that
	// shows an online marker.
	require.EqualValues(t, 1, info.Connections, "the connection count is not an address")
	require.NotNil(t, info.LastSeen, "nor is a timestamp")
}

// A user nobody has ever connected to reports zero rather than absent, and
// reading it does not bring a counter bucket into being.
func TestSecretsReportsAnUntouchedUser(t *testing.T) {
	t.Parallel()

	secret, err := GenerateSecretMode(SecretModeDD, "")
	require.NoError(t, err)

	entry := govEntryCases()[1]
	h := entry.harness(t, map[string]Secret{"alice": secret}, nil)
	h.proxy.trackClientIPs = true

	info := secretInfoFor(t, h.proxy, "alice")

	require.Zero(t, info.Connections)
	require.Nil(t, info.LastSeen, "never seen is null, not the zero time")
	require.Empty(t, info.ConnectedIPs)
	require.Empty(t, info.LastIP)
}
