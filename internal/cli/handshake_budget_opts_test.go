package cli

import (
	"testing"

	"github.com/Arman2122/mtg-proxy/internal/config"
	"github.com/Arman2122/mtg-proxy/mtglib"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func handshakeBudgetOptsFrom(t *testing.T, toml string) mtglib.ProxyOpts {
	t.Helper()

	conf, err := config.Parse([]byte(toml))
	require.NoError(t, err)

	var opts mtglib.ProxyOpts

	applyHandshakeBudget(&opts, conf)

	return opts
}

// A config that never mentions the table hands mtglib its zero values, which
// are the defaults: enforce, 50 ms per address, 25% of the cores, and hints that
// follow track-client-ips.
func TestHandshakeBudgetOptsStayZeroWithoutConfiguration(t *testing.T) {
	t.Parallel()

	opts := handshakeBudgetOptsFrom(t, antiReplayMinimal)

	assert.Empty(t, opts.HandshakeBudgetMode)
	assert.Nil(t, opts.HandshakeBudgetPerIPMillis)
	assert.Zero(t, opts.HandshakeBudgetCPUPercent)
	assert.Nil(t, opts.HandshakeHints)

	tracked := handshakeBudgetOptsFrom(t, antiReplayMinimal+"track-client-ips = true\n")

	assert.Nil(t, tracked.HandshakeHints, "the file does not decide for track-client-ips: mtglib follows it")
}

// An explicit false and an explicit 0 are values, not absences: they reach
// ProxyOpts as non-nil pointers, which is what makes hints = false beat
// track-client-ips = true and per-ip-ms = 0 turn the address bucket off.
func TestHandshakeBudgetOptsCarryExplicitFalseAndZero(t *testing.T) {
	t.Parallel()

	opts := handshakeBudgetOptsFrom(t, antiReplayMinimal+`track-client-ips = true

[defense.handshake-budget]
hints = false
per-ip-ms = 0
`)

	require.NotNil(t, opts.HandshakeHints)
	assert.False(t, *opts.HandshakeHints)

	require.NotNil(t, opts.HandshakeBudgetPerIPMillis)
	assert.Zero(t, *opts.HandshakeBudgetPerIPMillis)

	assert.Empty(t, opts.HandshakeBudgetMode)
	assert.Zero(t, opts.HandshakeBudgetCPUPercent)
}

func TestHandshakeBudgetOptsCarryEveryKey(t *testing.T) {
	t.Parallel()

	opts := handshakeBudgetOptsFrom(t, antiReplayMinimal+`
[defense.handshake-budget]
mode = "observe"
per-ip-ms = 200
cpu-percent = 60
hints = true
`)

	assert.Equal(t, "observe", opts.HandshakeBudgetMode)

	require.NotNil(t, opts.HandshakeBudgetPerIPMillis)
	assert.EqualValues(t, 200, *opts.HandshakeBudgetPerIPMillis)

	assert.EqualValues(t, 60, opts.HandshakeBudgetCPUPercent)

	require.NotNil(t, opts.HandshakeHints)
	assert.True(t, *opts.HandshakeHints)
}
