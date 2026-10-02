package cli

import (
	"testing"

	"github.com/Arman2122/mtg-proxy/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const antiReplayMinimal = `secret = "7oe1GqLy6TBc38CV3jx7q09nb29nbGUuY29t"
bind-to = "0.0.0.0:3128"
`

func antiReplayFrom(t *testing.T, toml string) func([]byte) bool {
	t.Helper()

	conf, err := config.Parse([]byte(toml))
	require.NoError(t, err)

	cache, err := makeAntiReplayCache(conf)
	require.NoError(t, err)

	return cache.SeenBefore
}

// A config that never mentions [defense.anti-replay] -- the Penhoon panel
// writes none -- still refuses a replayed handshake: a censor replaying a
// real client's hello within the clock-skew window must not get a proxy's
// answer.
func TestAntiReplayIsOnWithoutConfiguration(t *testing.T) {
	t.Parallel()

	seenBefore := antiReplayFrom(t, antiReplayMinimal)
	hello := []byte("a client random, as a replay would resend it")

	assert.False(t, seenBefore(hello), "the first sight of a handshake is not a replay")
	assert.True(t, seenBefore(hello), "the second is, and must be caught without any configuration")
}

// Turning it off still works, explicitly.
func TestAntiReplayCanStillBeTurnedOff(t *testing.T) {
	t.Parallel()

	seenBefore := antiReplayFrom(t, antiReplayMinimal+"\n[defense.anti-replay]\nenabled = false\n")
	hello := []byte("a client random, as a replay would resend it")

	assert.False(t, seenBefore(hello))
	assert.False(t, seenBefore(hello), "enabled = false must leave replay protection off")
}

func TestAntiReplayCanBeTurnedOnExplicitly(t *testing.T) {
	t.Parallel()

	seenBefore := antiReplayFrom(t, antiReplayMinimal+"\n[defense.anti-replay]\nenabled = true\n")
	hello := []byte("a client random, as a replay would resend it")

	assert.False(t, seenBefore(hello))
	assert.True(t, seenBefore(hello))
}
