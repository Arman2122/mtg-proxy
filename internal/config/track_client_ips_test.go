package config_test

import (
	"testing"

	"github.com/Arman2122/mtg-proxy/internal/config"
	"github.com/stretchr/testify/require"
)

// A config key in this package is carried by two structs -- the TOML-facing
// mirror in parse.go and the public Config -- joined by nothing but a matching
// `json:` tag. A typo in either tag, or in the `toml:` tag, is silent: the
// decoder does not reject unknown fields (deliberately, so an older binary can
// still read a newer file), so the key parses, the value is dropped on the
// floor, and the option reads as its zero value forever.
//
// Nothing in the suite catches that for a new key, which is why this exists:
// track-client-ips governs whether client addresses are reported at all, and a
// silently-ignored one would look exactly like the feature being off.
func TestTrackClientIPsRoundTrips(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		toml string
		want bool
	}{
		{
			name: "absent means off",
			toml: "secret = \"ee367a189aee18fa31c190054efd4a8e9573746f726167652e676f6f676c65617069732e636f6d\"\n" +
				"bind-to = \"0.0.0.0:443\"\n",
			want: false,
		},
		{
			name: "explicitly off",
			toml: "secret = \"ee367a189aee18fa31c190054efd4a8e9573746f726167652e676f6f676c65617069732e636f6d\"\n" +
				"bind-to = \"0.0.0.0:443\"\n" +
				"track-client-ips = false\n",
			want: false,
		},
		{
			name: "on",
			toml: "secret = \"ee367a189aee18fa31c190054efd4a8e9573746f726167652e676f6f676c65617069732e636f6d\"\n" +
				"bind-to = \"0.0.0.0:443\"\n" +
				"track-client-ips = true\n",
			want: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			conf, err := config.Parse([]byte(tc.toml))
			require.NoError(t, err)

			require.Equal(t, tc.want, conf.TrackClientIPs.Get(false),
				"the value written in the file must reach the parsed config")
		})
	}
}

// The default passed at the call site is the only default there is, and it must
// stay false.
//
// TypeBool.Get is `t.Value || defaultValue`, so a true default would make the
// option permanently true: an operator writing track-client-ips = false could
// not turn address reporting off, and nothing would say so. The reason to care
// is in ProxyOpts.TrackClientIPs -- addresses are the one thing here that a
// seized server should not be able to hand over.
func TestTrackClientIPsCannotBeDefaultedOn(t *testing.T) {
	t.Parallel()

	conf, err := config.Parse([]byte(
		"secret = \"ee367a189aee18fa31c190054efd4a8e9573746f726167652e676f6f676c65617069732e636f6d\"\n" +
			"bind-to = \"0.0.0.0:443\"\n" +
			"track-client-ips = false\n"))
	require.NoError(t, err)

	require.True(t, conf.TrackClientIPs.Get(true),
		"this documents TypeBool.Get's OR semantics: a true default wins over an explicit false, "+
			"which is exactly why the proxy must pass false")
	require.False(t, conf.TrackClientIPs.Get(false),
		"and why passing false makes the file the authority")
}
