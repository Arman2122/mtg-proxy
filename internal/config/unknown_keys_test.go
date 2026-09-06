package config_test

import (
	"fmt"
	"testing"

	"github.com/Arman2122/mtg-proxy/internal/config"
	"github.com/Arman2122/mtg-proxy/mtglib"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A key the binary does not know still loads -- that leniency is what lets a
// newer file run on an older binary -- but it is named, with its full path,
// so a typo or a key under the wrong table is not silent.
func TestUnknownKeysAreNamed(t *testing.T) {
	t.Parallel()

	alice := mtglib.GenerateSecret("alice.example.com").Hex()

	raw := fmt.Sprintf(`
bind-to = "10.0.0.1:443"
track-client-ip = true

[[listener]]
bind-to = "127.0.0.1:2398"
accept = ["dd"]
concurrency = 8192

[secret-limits.alice]
quota_reset = "monthly"
quota = "10GB"

[secrets]
alice = "%s"
`, alice)

	conf, err := config.Parse([]byte(raw))
	require.NoError(t, err, "unknown keys must not refuse the file")
	require.NoError(t, conf.Validate())

	assert.Equal(t, []string{
		"listener.concurrency",
		"secret-limits.alice.quota_reset",
		"track-client-ip",
	}, conf.UnknownKeys)

	warnings := conf.UnknownKeyWarnings()
	require.Len(t, warnings, 3)
	assert.Contains(t, warnings[1], `"secret-limits.alice.quota_reset"`)
	assert.Contains(t, warnings[1], "ignored")

	// The known neighbour of the typo still took effect.
	assert.Equal(t, int64(10<<30), conf.GetSecretLimits()["alice"].QuotaBytes)
	assert.Equal(t, mtglib.QuotaResetNone, conf.GetSecretLimits()["alice"].QuotaReset,
		"the misspelled key did nothing, which is exactly why it is named")

	// It never leaks into the config's own rendering.
	assert.NotContains(t, conf.String(), "UnknownKeys")
	assert.NotContains(t, conf.String(), "quota_reset")
}

func TestACleanFileHasNoUnknownKeys(t *testing.T) {
	t.Parallel()

	alice := mtglib.GenerateSecret("alice.example.com").Hex()

	conf, err := config.Parse([]byte(fmt.Sprintf(`
bind-to = "10.0.0.1:443"
track-client-ips = true

[secret-limits.alice]
quota-reset = "monthly"
quota = "10GB"
ip-limit = 2

[secrets]
alice = "%s"
`, alice)))
	require.NoError(t, err)

	assert.Empty(t, conf.UnknownKeys)
	assert.Empty(t, conf.UnknownKeyWarnings())
}
