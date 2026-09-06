package config_test

import (
	"fmt"
	"testing"

	"github.com/Arman2122/mtg-proxy/internal/config"
	"github.com/Arman2122/mtg-proxy/mtglib"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The address limit reaches the engine through the same conversion as the
// other per-secret limits.
func TestSecretLimitIPLimit(t *testing.T) {
	t.Parallel()

	alice := mtglib.GenerateSecret("alice.example.com").Hex()

	withLimit := func(limit string) string {
		return fmt.Sprintf(`
bind-to = "10.0.0.1:443"

[secret-limits.alice]
ip-limit = %s

[secrets]
alice = "%s"
`, limit, alice)
	}

	t.Run("reaches the engine", func(t *testing.T) {
		t.Parallel()

		conf, err := config.Parse([]byte(withLimit("2")))
		require.NoError(t, err)
		require.NoError(t, conf.Validate())

		assert.Equal(t, 2, conf.GetSecretLimits()["alice"].IPLimit)
	})

	t.Run("alone it is still a limit", func(t *testing.T) {
		t.Parallel()

		conf, err := config.Parse([]byte(withLimit("1")))
		require.NoError(t, err)

		limits := conf.GetSecretLimits()
		require.Contains(t, limits, "alice")
		assert.False(t, limits["alice"].IsZero())
	})

	t.Run("zero is no limit", func(t *testing.T) {
		t.Parallel()

		conf, err := config.Parse([]byte(withLimit("0")))
		require.NoError(t, err)
		assert.Nil(t, conf.GetSecretLimits())
	})

	t.Run("negative is refused at parse time", func(t *testing.T) {
		t.Parallel()

		_, err := config.Parse([]byte(withLimit("-1")))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "ip-limit")
	})

	t.Run("a string is refused", func(t *testing.T) {
		t.Parallel()

		_, err := config.Parse([]byte(withLimit(`"2"`)))
		require.Error(t, err)
	})

	t.Run("renders in the config's own dump", func(t *testing.T) {
		t.Parallel()

		conf, err := config.Parse([]byte(withLimit("2")))
		require.NoError(t, err)
		assert.Contains(t, conf.String(), `"ipLimit":2`)
	})
}
