package cli

import (
	"testing"

	"github.com/Arman2122/mtg-proxy/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func scoutCoversFrom(t *testing.T, toml string) bool {
	t.Helper()

	conf, err := config.Parse([]byte(toml))
	require.NoError(t, err)

	return scoutCovers(conf)
}

// Without configuration the proxy measures the cover sites its ee secrets
// name, so each fake handshake is sized like the site the client asked for.
func TestCoverScoutingIsOnWithoutConfiguration(t *testing.T) {
	t.Parallel()

	assert.True(t, scoutCoversFrom(t, antiReplayMinimal))
}

// An operator who wants no outbound fetches turns it off; handshakes then use
// the generic size, as before.
func TestCoverScoutingCanBeTurnedOff(t *testing.T) {
	t.Parallel()

	assert.False(t, scoutCoversFrom(t, antiReplayMinimal+"\n[defense.doppelganger]\nscout-covers = false\n"))
	assert.True(t, scoutCoversFrom(t, antiReplayMinimal+"\n[defense.doppelganger]\nscout-covers = true\n"))
}
