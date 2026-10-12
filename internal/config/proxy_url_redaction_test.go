package config_test

import (
	"net/url"
	"strings"
	"testing"

	"github.com/Arman2122/mtg-proxy/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// An upstream proxy URL carries the proxy's credentials: socks5://user:pass@host.
// The password is the one part of it nothing but the dialer needs, so none of
// the places that print a proxy URL -- the Debug dump of the configuration, the
// refusal of a URL, doctor's lines -- may show it.

const (
	proxyUser     = "proxyuser"
	proxyPassword = "pr0xyP4ssw0rd"

	// proxyTestSecret is any secret the parser accepts, so that a config with a
	// proxy in it parses as far as the proxy.
	proxyTestSecret = "7oe1GqLy6TBc38CV3jx7q09nb29nbGUuY29t"
)

// proxyTOMLString is a value as a TOML basic string holds it: the DEL byte,
// which a basic string may not carry as it is, is written as an escape.
func proxyTOMLString(value string) string {
	return strings.ReplaceAll(value, "\x7f", `\u007f`)
}

func TestTypeProxyURLRedacted(t *testing.T) {
	t.Parallel()

	for raw, want := range map[string]string{
		"socks5://" + proxyUser + ":" + proxyPassword + "@10.0.0.2:1080": "socks5://" + proxyUser + ":xxxxx@10.0.0.2:1080",
		"socks5://" + proxyUser + "@10.0.0.2:1080":                       "socks5://" + proxyUser + "@10.0.0.2:1080",
		"socks5://10.0.0.2:1080":                                         "socks5://10.0.0.2:1080",
		"socks5://10.0.0.2":                                              "socks5://10.0.0.2:1080",
	} {
		value := config.TypeProxyURL{}
		require.NoError(t, value.Set(raw))

		assert.Equal(t, want, value.Redacted(), "for %q", raw)
	}

	assert.Empty(t, config.TypeProxyURL{}.Redacted(), "an unset URL has nothing to show")
}

// TestProxyURLRefusalsNeverEchoThePassword drives every way a proxy URL is
// refused, with the password inside the refused text, through the type itself
// and through the whole parser.
func TestProxyURLRefusalsNeverEchoThePassword(t *testing.T) {
	t.Parallel()

	for name, raw := range map[string]string{
		"a space in the host":      "socks5://" + proxyUser + ":" + proxyPassword + "@exa mple.com:1080",
		"no scheme":                "://" + proxyUser + ":" + proxyPassword + "@10.0.0.2:1080",
		"no host":                  "socks5://" + proxyUser + ":" + proxyPassword + "@",
		"another scheme":           "http://" + proxyUser + ":" + proxyPassword + "@10.0.0.2:1080",
		"a bad escape in password": "socks5://" + proxyUser + ":" + proxyPassword + "%zz@10.0.0.2:1080",
		"a control character":      "socks5://" + proxyUser + ":" + proxyPassword + "@10.0.0.2:1080/\x7f",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			err := (&config.TypeProxyURL{}).Set(raw)
			require.Error(t, err, "the URL must be refused")
			assert.NotContains(t, err.Error(), proxyPassword, "Set echoed the password")

			_, err = config.Parse([]byte(`
secret = "` + proxyTestSecret + `"
bind-to = "0.0.0.0:3128"

[network]
proxies = ["` + proxyTOMLString(raw) + `"]
`))
			require.Error(t, err, "the config must be refused")
			assert.NotContains(t, err.Error(), proxyPassword, "Parse echoed the password")
		})
	}
}

// TestRefusingAProxyURLStillSaysWhy keeps the redaction from turning every
// refusal into a bare "no": the operator still learns what was wrong.
func TestRefusingAProxyURLStillSaysWhy(t *testing.T) {
	t.Parallel()

	err := (&config.TypeProxyURL{}).Set("http://" + proxyUser + ":" + proxyPassword + "@10.0.0.2:1080")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported schema: http")

	err = (&config.TypeProxyURL{}).Set("socks5://" + proxyUser + ":" + proxyPassword + "@")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "url has to have a schema")

	err = (&config.TypeProxyURL{}).Set("://x")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not correct URL")
	assert.Contains(t, err.Error(), "missing protocol scheme", "the parser's own reason must survive")
}

// TestConfigStringRedactsProxyPasswords is the Debug dump: it names the proxy
// and its user, so the log still says which upstream is configured, and never
// its password.
func TestConfigStringRedactsProxyPasswords(t *testing.T) {
	t.Parallel()

	conf, err := config.Parse([]byte(`
secret = "` + proxyTestSecret + `"
bind-to = "0.0.0.0:3128"

[network]
proxies = [
  "socks5://` + proxyUser + `:` + proxyPassword + `@10.0.0.2:1080",
  "socks5://127.0.0.1:1081",
]
`))
	require.NoError(t, err)

	rendered := conf.String()

	assert.NotContains(t, rendered, proxyPassword, "a proxy password reached the log rendering")
	assert.Contains(t, rendered, proxyUser, "the proxy's user must survive redaction")
	assert.Contains(t, rendered, "10.0.0.2:1080", "the proxy's address must survive redaction")
	assert.Contains(t, rendered, "127.0.0.1:1081", "a proxy without credentials is shown whole")

	// The redaction is of the rendering only: the parsed value keeps the
	// password, because the dialer needs it.
	require.Len(t, conf.Network.Proxies, 2)

	password, set := conf.Network.Proxies[0].Get(nil).User.Password()
	assert.True(t, set)
	assert.Equal(t, proxyPassword, password)
}

// TestRedactionDoesNotTouchTheParsedURL pins that Redacted only reads, and that
// String and MarshalText keep the password: the config is written back from them.
func TestRedactionDoesNotTouchTheParsedURL(t *testing.T) {
	t.Parallel()

	value := config.TypeProxyURL{}
	require.NoError(t, value.Set("socks5://"+proxyUser+":"+proxyPassword+"@10.0.0.2:1080"))

	before := *value.Get(nil)
	_ = value.Redacted()

	assert.Equal(t, before, *value.Get(nil))

	parsed, err := url.Parse(value.String())
	require.NoError(t, err)

	password, _ := parsed.User.Password()
	assert.Equal(t, proxyPassword, password, "String keeps the password: it is what the config is written back from")
}
