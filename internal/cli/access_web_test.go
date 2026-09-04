package cli

import (
	"net/url"
	"strings"
	"testing"

	"github.com/Arman2122/mtg-proxy/internal/config"
	"github.com/Arman2122/mtg-proxy/mtglib"
	"github.com/stretchr/testify/require"
)

func webAccessConfig(t *testing.T, web string) *config.Config {
	t.Helper()

	conf, err := config.Parse([]byte(`
secret = "7oe1GqLy6TBc38CV3jx7q09nb29nbGUuY29t"
bind-to = "0.0.0.0:3128"

[[listener]]
bind-to = "127.0.0.1:2398"
accept = ["dd", "plain"]
` + web + `

[secrets]
alice = "7oe1GqLy6TBc38CV3jx7q09nb29nbGUuY29t"
bob = "7uY1aHFYeS5fhR-jpySw4TLTZ29vZ2xlLmNvbQ"
`))
	require.NoError(t, err)

	return conf
}

const enabledWeb = `
[web]
enabled = true
host = "proxy.example.com"
bind-to = "127.0.0.1:8099"
backend = "127.0.0.1:2398"
token-key = "/etc/mtg-proxy/web.key"
cover-dir = "/var/www/site"
`

func webAccess(t *testing.T, conf *config.Config) *accessResponseWeb {
	t.Helper()

	secrets := conf.GetSecrets()
	names := make([]string, 0, len(secrets))

	for name := range secrets {
		names = append(names, name)
	}

	// Sorted, as the caller sorts them.
	for i := range names {
		for j := i + 1; j < len(names); j++ {
			if names[j] < names[i] {
				names[i], names[j] = names[j], names[i]
			}
		}
	}

	return makeWebAccess(conf, secrets, names)
}

// A WEB-capable client refuses an ee secret before it touches the network, so
// the link has to carry the dd spelling of the same key. Emitting the ee form
// here would produce a link that fails with no diagnostic anywhere.
func TestWebAccessLinksCarryTheDDSecret(t *testing.T) {
	t.Parallel()

	conf := webAccessConfig(t, enabledWeb)

	web := webAccess(t, conf)
	require.NotNil(t, web)
	require.Equal(t, "proxy.example.com", web.Host)
	require.Len(t, web.Secrets, 2)

	for name, entry := range web.Secrets {
		require.True(t, strings.HasPrefix(entry.Secret, "dd"), name)
		require.Len(t, entry.Secret, 34, name)

		parsed, err := url.Parse(entry.TgURL)
		require.NoError(t, err, name)
		require.Equal(t, "tg", parsed.Scheme, name)
		require.Equal(t, "webproxy", parsed.Host, name)
		require.Equal(t, "proxy.example.com", parsed.Query().Get("server"), name)
		require.Equal(t, entry.Secret, parsed.Query().Get("secret"), name)

		// The client's own form has one field and forces 443, so a port in the
		// link would be a value it cannot honour.
		require.Empty(t, parsed.Query().Get("port"), name)
	}
}

// The same key, told two ways. If these ever stopped agreeing, a WEB user and a
// direct user of one credential would be two different clients to the proxy.
func TestWebAccessIsTheSameKeyAsTheProxyLink(t *testing.T) {
	t.Parallel()

	conf := webAccessConfig(t, enabledWeb)
	secrets := conf.GetSecrets()

	web := webAccess(t, conf)
	require.NotNil(t, web)

	for name, entry := range web.Secrets {
		var parsed mtglib.Secret
		require.NoError(t, parsed.Set(entry.Secret), name)
		require.Equal(t, secrets[name].Key, parsed.Key, name)
		require.Equal(t, mtglib.SecretModeDD, parsed.Mode, name)
	}
}

// t.me has not registered the webproxy route: an https link there resolves as
// the username @webproxy and opens a stranger's contact page.
func TestWebAccessEmitsNoTMeLink(t *testing.T) {
	t.Parallel()

	web := webAccess(t, webAccessConfig(t, enabledWeb))
	require.NotNil(t, web)

	for name, entry := range web.Secrets {
		require.NotContains(t, entry.TgURL, "t.me", name)
	}
}

func TestNoWebAccessWithoutARelay(t *testing.T) {
	t.Parallel()

	require.Nil(t, webAccess(t, webAccessConfig(t, "")))

	disabled := `
[web]
host = "proxy.example.com"
bind-to = "127.0.0.1:8099"
backend = "127.0.0.1:2398"
token-key = "/etc/mtg-proxy/web.key"
cover-dir = "/var/www/site"
`
	require.Nil(t, webAccess(t, webAccessConfig(t, disabled)))
}
