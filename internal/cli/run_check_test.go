package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// writeConfig puts raw in a file `run` can be pointed at.
func writeConfig(t *testing.T, raw string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "config.toml")
	require.NoError(t, os.WriteFile(path, []byte(raw), 0o600))

	return path
}

func TestRunCheck(t *testing.T) {
	t.Parallel()

	t.Run("accepts the file run would start on", func(t *testing.T) {
		t.Parallel()

		r := &Run{ConfigPath: writeConfig(t, doctorConfig("")), Check: true}
		require.NoError(t, r.Run(nil, "test"))
	})

	t.Run("refuses a key this binary does not read", func(t *testing.T) {
		t.Parallel()

		r := &Run{ConfigPath: writeConfig(t, doctorConfig("track-client-ip = true\n")), Check: true}
		err := r.Run(nil, "test")
		require.ErrorIs(t, err, errUnknownKeys)
		require.ErrorContains(t, err, "track-client-ip")
	})

	t.Run("accepts the per-address connection cap", func(t *testing.T) {
		t.Parallel()

		r := &Run{ConfigPath: writeConfig(t, doctorConfig("\n[secret-limits.default]\nclient-conns = 4\n")), Check: true}
		require.NoError(t, r.Run(nil, "test"))
	})

	t.Run("accepts the per-address speed ceiling", func(t *testing.T) {
		t.Parallel()

		r := &Run{ConfigPath: writeConfig(t, doctorConfig("\n[secret-limits.default]\nclient-speed = \"8mbit\"\n")), Check: true}
		require.NoError(t, r.Run(nil, "test"))
	})

	t.Run("accepts fair share beside a speed", func(t *testing.T) {
		t.Parallel()

		r := &Run{
			ConfigPath: writeConfig(t, doctorConfig("\n[secret-limits.default]\nspeed = \"8mbit\"\nclient-fair = true\n")),
			Check:      true,
		}
		require.NoError(t, r.Run(nil, "test"))
	})

	t.Run("refuses fair share with no speed to divide", func(t *testing.T) {
		t.Parallel()

		r := &Run{ConfigPath: writeConfig(t, doctorConfig("\n[secret-limits.default]\nclient-fair = true\n")), Check: true}
		require.ErrorContains(t, r.Run(nil, "test"), "client-fair")
	})

	t.Run("refuses what run refuses", func(t *testing.T) {
		t.Parallel()

		r := &Run{ConfigPath: writeConfig(t, `secret = "not-a-secret"`+"\n"+`bind-to = "127.0.0.1:3128"`+"\n"), Check: true}
		require.ErrorContains(t, r.Run(nil, "test"), "cannot init config")
	})
}
