package config_test

import (
	"fmt"
	"testing"

	"github.com/Arman2122/mtg-proxy/internal/config"
	"github.com/Arman2122/mtg-proxy/mtglib"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The speed limit reaches the engine through the same conversion as the other
// per-secret limits, and is parsed by the same function the API uses, so a
// spelling the file accepts is one the API accepts.
func TestSecretLimitSpeed(t *testing.T) {
	t.Parallel()

	alice := mtglib.GenerateSecret("alice.example.com").Hex()

	withSpeed := func(speed string) string {
		return fmt.Sprintf(`
bind-to = "10.0.0.1:443"

[secret-limits.alice]
speed = %q

[secrets]
alice = "%s"
`, speed, alice)
	}

	t.Run("reaches the engine in bytes per second", func(t *testing.T) {
		t.Parallel()

		conf, err := config.Parse([]byte(withSpeed("5mbit")))
		require.NoError(t, err)
		require.NoError(t, conf.Validate())

		assert.Equal(t, int64(625_000), conf.GetSecretLimits()["alice"].SpeedBytesPerSecond)
	})

	t.Run("alone it is still a limit", func(t *testing.T) {
		t.Parallel()

		// No quota, no expiry, not disabled: a speed by itself must not be
		// dropped as an empty entry.
		conf, err := config.Parse([]byte(withSpeed("1MB/s")))
		require.NoError(t, err)

		limits := conf.GetSecretLimits()
		require.Contains(t, limits, "alice")
		assert.False(t, limits["alice"].IsZero())
	})

	t.Run("is refused below the floor, at parse time", func(t *testing.T) {
		t.Parallel()

		_, err := config.Parse([]byte(withSpeed("32kbit")))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "64kbit")
	})

	t.Run("is refused when it is not a speed", func(t *testing.T) {
		t.Parallel()

		_, err := config.Parse([]byte(withSpeed("fast")))
		require.Error(t, err)
	})

	t.Run("survives the config's own rendering", func(t *testing.T) {
		t.Parallel()

		conf, err := config.Parse([]byte(withSpeed("500kbit")))
		require.NoError(t, err)

		// String() is the debug rendering; the value must come back out in a
		// form Set accepts, and must not be mistaken for a credential.
		assert.Contains(t, conf.String(), `"speed":"62500B/s"`)
	})
}
