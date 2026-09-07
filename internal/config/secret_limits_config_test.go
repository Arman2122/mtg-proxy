package config_test

import (
	"fmt"
	"testing"

	"github.com/Arman2122/mtg-proxy/internal/config"
	"github.com/Arman2122/mtg-proxy/mtglib"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSecretLimitsParse(t *testing.T) {
	t.Parallel()

	alice := mtglib.GenerateSecret("alice.example.com").Hex()
	bob := mtglib.GenerateSecret("bob.example.com").Hex()

	raw := fmt.Sprintf(`
bind-to = "10.0.0.1:443"
usage-state-file = "/var/lib/mtg/usage.json"

[secret-limits.alice]
quota = "10GB"
quota-reset = "monthly"
expires = "2030-01-01"
disabled = true

[secret-limits.bob]
quota = "500MB"

[secrets]
alice = "%s"
bob = "%s"
`, alice, bob)

	conf, err := config.Parse([]byte(raw))
	require.NoError(t, err)
	require.NoError(t, conf.Validate())

	assert.Equal(t, "/var/lib/mtg/usage.json", conf.UsageStateFile)

	limits := conf.GetSecretLimits()
	require.Len(t, limits, 2)

	a := limits["alice"]
	assert.Equal(t, int64(10*1024*1024*1024), a.QuotaBytes)
	assert.Equal(t, mtglib.QuotaResetMonthly, a.QuotaReset)
	assert.True(t, a.Disabled)
	assert.Equal(t, 2030, a.ExpiresAt.Year())

	b := limits["bob"]
	assert.Equal(t, int64(500*1024*1024), b.QuotaBytes)
	assert.Equal(t, mtglib.QuotaResetNone, b.QuotaReset)
	assert.False(t, b.Disabled)
	assert.True(t, b.ExpiresAt.IsZero())
}

func TestSecretLimitsUnknownSecretRejected(t *testing.T) {
	t.Parallel()

	alice := mtglib.GenerateSecret("alice.example.com").Hex()

	raw := fmt.Sprintf(`
bind-to = "10.0.0.1:443"

[secret-limits.ghost]
quota = "1GB"

[secrets]
alice = "%s"
`, alice)

	conf, err := config.Parse([]byte(raw))
	require.NoError(t, err)
	assert.ErrorContains(t, conf.Validate(), "unknown secret")
}

func TestSecretLimitsAbsentIsNil(t *testing.T) {
	t.Parallel()

	alice := mtglib.GenerateSecret("alice.example.com").Hex()

	raw := fmt.Sprintf(`
bind-to = "10.0.0.1:443"

[secrets]
alice = "%s"
`, alice)

	conf, err := config.Parse([]byte(raw))
	require.NoError(t, err)
	require.NoError(t, conf.Validate())

	assert.Nil(t, conf.GetSecretLimits())
	assert.Empty(t, conf.UsageStateFile)
}

// speed-up and speed-down are each their own cap, spelled like speed, and a
// value below the floor is refused on either.
func TestSecretLimitsSpeedDirections(t *testing.T) {
	t.Parallel()

	alice := mtglib.GenerateSecret("alice.example.com").Hex()

	raw := fmt.Sprintf(`
bind-to = "10.0.0.1:443"

[secret-limits.alice]
speed-up = "1mbit"
speed-down = "2MB/s"

[secrets]
alice = "%s"
`, alice)

	conf, err := config.Parse([]byte(raw))
	require.NoError(t, err)
	require.NoError(t, conf.Validate())

	a := conf.GetSecretLimits()["alice"]
	assert.Equal(t, int64(125_000), a.SpeedUpBytesPerSecond)
	assert.Equal(t, int64(2<<20), a.SpeedDownBytesPerSecond)
	assert.Zero(t, a.SpeedBytesPerSecond, "the combined cap is a separate key")

	_, err = config.Parse([]byte(fmt.Sprintf(`
bind-to = "10.0.0.1:443"

[secret-limits.alice]
speed-down = "32kbit"

[secrets]
alice = "%s"
`, alice)))
	require.ErrorContains(t, err, "64kbit")
}
