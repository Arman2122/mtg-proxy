package config_test

import (
	"encoding/json"
	"fmt"
	"sort"
	"testing"

	"github.com/Arman2122/mtg-proxy/internal/config"
	"github.com/Arman2122/mtg-proxy/mtglib"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// clientLimitsConfig is a config whose [secret-limits.alice] table carries the
// given lines.
func clientLimitsConfig(t *testing.T, lines string) string {
	t.Helper()

	return fmt.Sprintf(`
bind-to = "10.0.0.1:443"

[secret-limits.alice]
%s

[secrets]
alice = "%s"
`, lines, mtglib.GenerateSecret("alice.example.com").Hex())
}

// client-conns is a key of [secret-limits.<name>] this binary reads: it reaches
// the engine through the same conversion as the other per-secret limits, it is
// a limit on its own, zero is none, and it is refused by name when it is not a
// non-negative integer.
func TestSecretLimitClientConns(t *testing.T) {
	t.Parallel()

	t.Run("reaches the engine and is no unknown key", func(t *testing.T) {
		t.Parallel()

		conf, err := config.Parse([]byte(clientLimitsConfig(t, "ip-limit = 2\nclient-conns = 6")))
		require.NoError(t, err)
		require.NoError(t, conf.Validate())

		assert.Empty(t, conf.UnknownKeys, "run --check accepts it")

		alice := conf.GetSecretLimits()["alice"]
		assert.Equal(t, 6, alice.ClientConns)
		assert.Equal(t, 2, alice.IPLimit, "and it is not the address limit")
	})

	t.Run("alone it is still a limit", func(t *testing.T) {
		t.Parallel()

		conf, err := config.Parse([]byte(clientLimitsConfig(t, "client-conns = 1")))
		require.NoError(t, err)

		limits := conf.GetSecretLimits()
		require.Contains(t, limits, "alice")
		assert.Equal(t, 1, limits["alice"].ClientConns)
	})

	t.Run("zero is no limit", func(t *testing.T) {
		t.Parallel()

		conf, err := config.Parse([]byte(clientLimitsConfig(t, "client-conns = 0")))
		require.NoError(t, err)
		assert.Nil(t, conf.GetSecretLimits())
	})

	t.Run("negative is refused at parse time, by its own name", func(t *testing.T) {
		t.Parallel()

		_, err := config.Parse([]byte(clientLimitsConfig(t, "client-conns = -1")))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "client-conns")
		assert.NotContains(t, err.Error(), "ip-limit")
	})

	t.Run("a string is refused", func(t *testing.T) {
		t.Parallel()

		_, err := config.Parse([]byte(clientLimitsConfig(t, `client-conns = "4"`)))
		require.Error(t, err)
	})
}

// Config.String() is what a debug log prints. A [secret-limits] table that
// does not use client-conns renders exactly the keys it rendered before the key
// existed -- the panel's file included, which never writes it -- and one that
// uses it shows it.
func TestClientConnsLeavesConfigStringAloneUntilUsed(t *testing.T) {
	t.Parallel()

	limitKeys := func(t *testing.T, conf *config.Config) []string {
		t.Helper()

		var fields map[string]any

		require.NoError(t, json.Unmarshal([]byte(conf.String()), &fields))

		limits, ok := fields["secretLimits"].(map[string]any)
		require.True(t, ok)

		alice, ok := limits["alice"].(map[string]any)
		require.True(t, ok)

		keys := make([]string, 0, len(alice))
		for key := range alice {
			keys = append(keys, key)
		}

		sort.Strings(keys)

		return keys
	}

	unused, err := config.Parse([]byte(clientLimitsConfig(t, "ip-limit = 2")))
	require.NoError(t, err)

	assert.Equal(t,
		[]string{"disabled", "expires", "ipLimit", "quota", "quotaReset", "speed", "speedDown", "speedUp"},
		limitKeys(t, unused), "a table that never mentions the key renders no key for it")

	used, err := config.Parse([]byte(clientLimitsConfig(t, "client-conns = 6")))
	require.NoError(t, err)

	assert.Contains(t, limitKeys(t, used), "clientConns", "a table that uses it shows it")
	assert.Contains(t, used.String(), `"clientConns":6`)
}
