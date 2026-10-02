package mtglib

import (
	"testing"

	"github.com/Arman2122/mtg-proxy/mtglib/internal/doppel"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The doppelganger knows which cover sites the ee secrets name, and the
// address fronting would dial for each, from the start and across secret
// changes. Scouting is off here (DoppelGangerScoutCovers false), so nothing
// is fetched; only the list is under test.
func TestCoverHostsFollowTheSecrets(t *testing.T) {
	t.Parallel()

	alice := GenerateSecret("a.example")
	bob := GenerateSecret("b.example")
	plain, err := GenerateSecretMode(SecretModeDD, "")
	require.NoError(t, err)

	opts, _ := servingOpts(t)
	opts.Secrets = map[string]Secret{"alice": alice, "bob": bob, "dave": plain}

	proxy, err := NewProxy(opts)
	require.NoError(t, err)
	t.Cleanup(proxy.Shutdown)

	assert.Equal(t, []doppel.CoverHost{
		{Host: "a.example", Addr: "a.example:443"},
		{Host: "b.example", Addr: "b.example:443"},
	}, proxy.doppelGanger.CoverHosts(), "each ee secret's cover site once, in name order; a dd secret has none")

	proxy.reloadMu.Lock()
	err = proxy.swapSecretConfigLocked(SecretConfig{Secrets: map[string]Secret{
		"alice": alice,
		"carol": GenerateSecret("c.example"),
	}})
	proxy.reloadMu.Unlock()
	require.NoError(t, err)

	assert.Equal(t, []doppel.CoverHost{
		{Host: "a.example", Addr: "a.example:443"},
		{Host: "c.example", Addr: "c.example:443"},
	}, proxy.doppelGanger.CoverHosts(), "a secret change brings its cover sites along")

	opts.DomainFrontingHost = "192.0.2.9"

	fronted, err := NewProxy(opts)
	require.NoError(t, err)
	t.Cleanup(fronted.Shutdown)

	for _, h := range fronted.doppelGanger.CoverHosts() {
		assert.Equal(t, "192.0.2.9:443", h.Addr,
			"with a fronting host configured, %s is measured where fronting would dial", h.Host)
	}
}
