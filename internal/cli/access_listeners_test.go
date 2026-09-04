package cli

import (
	"net"
	"net/url"
	"sort"
	"strings"
	"testing"

	"github.com/Arman2122/mtg-proxy/internal/config"
	"github.com/Arman2122/mtg-proxy/mtglib"
	"github.com/stretchr/testify/require"
)

// listenerAccessConfig is a proxy with a public obfuscated2 socket beside the
// FakeTLS one, and the loopback socket a WEB relay backend uses.
func listenerAccessConfig(t *testing.T, listeners string) *config.Config {
	t.Helper()

	conf, err := config.Parse([]byte(`
bind-to = "0.0.0.0:443"
public-ipv4 = "203.0.113.9"
` + listeners + `

[secrets]
alice = "7oe1GqLy6TBc38CV3jx7q09nb29nbGUuY29t"
bob = "7uY1aHFYeS5fhR-jpySw4TLTZ29vZ2xlLmNvbQ"
`))
	require.NoError(t, err)

	return conf
}

// listenerAccess runs the builder the way Access.Run does, with the address
// family blocks already resolved.
func listenerAccess(t *testing.T, conf *config.Config) []accessResponseListener {
	t.Helper()

	secrets := conf.GetSecrets()

	names := make([]string, 0, len(secrets))
	for name := range secrets {
		names = append(names, name)
	}

	sort.Strings(names)

	ipv4 := &accessResponseURLs{IP: net.ParseIP("203.0.113.9")}

	return makeListenerAccess(conf, secrets, names, ipv4, nil)
}

// A public obfuscated2 listener produces a link per user, in the wire form that
// socket accepts, on that socket's own port.
//
// Before this existed, access described bind-to alone: it printed the ee secret
// against the FakeTLS port, which is the one form a client arriving on an
// obfuscated2 socket will not take. An operator who configured a listener had
// nothing to hand a user.
func TestListenerAccessBuildsALinkPerUser(t *testing.T) {
	t.Parallel()

	conf := listenerAccessConfig(t, `
[[listener]]
bind-to = "0.0.0.0:8444"
accept = ["dd"]
public = true
`)

	listeners := listenerAccess(t, conf)
	require.Len(t, listeners, 1)

	entry := listeners[0]
	require.Equal(t, "0.0.0.0:8444", entry.BindTo)
	require.Equal(t, []string{"dd"}, entry.Accept)
	require.True(t, entry.Public)
	require.Empty(t, entry.Unreachable)
	require.NotNil(t, entry.IPv4)
	require.EqualValues(t, 8444, entry.IPv4.Port, "the listener's own port, not bind-to's")

	require.Len(t, entry.IPv4.Secrets, 2, "every configured user gets a link")

	alice := entry.IPv4.Secrets["alice"]["dd"]

	parsed, err := url.Parse(alice.TgURL)
	require.NoError(t, err)
	require.Equal(t, "tg", parsed.Scheme)
	require.Equal(t, "proxy", parsed.Host)
	require.Equal(t, "203.0.113.9", parsed.Query().Get("server"))
	require.Equal(t, "8444", parsed.Query().Get("port"))
	require.Equal(t, alice.Secret, parsed.Query().Get("secret"))
	require.True(t, strings.HasPrefix(alice.Secret, "dd"),
		"a dd socket is offered the dd spelling")

	require.NotEmpty(t, alice.TmeURL)
	require.NotEmpty(t, alice.TgQrCode)
	require.NotEmpty(t, alice.TmeQrCode)
}

// The link offered on a listener carries the SAME key as the user's ee secret.
//
// This is the property the whole three-mode design rests on: one account, one
// quota bucket, one set of counters, whichever door the client comes through.
// A builder that minted a fresh secret here would look right in every other
// assertion and quietly give the user a second identity.
func TestListenerAccessReusesTheUsersOwnKey(t *testing.T) {
	t.Parallel()

	conf := listenerAccessConfig(t, `
[[listener]]
bind-to = "0.0.0.0:8444"
accept = ["dd", "plain"]
public = true
`)

	secrets := conf.GetSecrets()
	entry := listenerAccess(t, conf)[0]

	for _, name := range []string{"alice", "bob"} {
		secret := secrets[name]
		key := secret.Key[:]

		dd := entry.IPv4.Secrets[name]["dd"]
		plain := entry.IPv4.Secrets[name]["plain"]

		require.Equal(t, "dd"+hexOf(key), dd.Secret)
		require.Equal(t, hexOf(key), plain.Secret,
			"the plain form is the bare key, with no prefix at all")

		require.Equal(t, strings.TrimPrefix(dd.Secret, "dd"), plain.Secret,
			"both forms of one user's link must carry the same sixteen bytes")
	}
}

// Every accepted form is offered, because which one a client will take is the
// client's business, not the operator's.
func TestListenerAccessOffersEveryAcceptedForm(t *testing.T) {
	t.Parallel()

	conf := listenerAccessConfig(t, `
[[listener]]
bind-to = "0.0.0.0:8444"
accept = ["dd", "plain"]
public = true
`)

	forms := listenerAccess(t, conf)[0].IPv4.Secrets["alice"]

	require.Len(t, forms, 2)
	require.Contains(t, forms, "dd")
	require.Contains(t, forms, "plain")
}

// A loopback listener gets no links, and says why.
//
// That is the shape of a WEB relay backend, so its having no public link is
// correct rather than a misconfiguration -- and an operator reading the output
// should be told which of the two it is.
func TestListenerAccessExplainsALoopbackBackend(t *testing.T) {
	t.Parallel()

	conf := listenerAccessConfig(t, `
[[listener]]
bind-to = "127.0.0.1:2398"
accept = ["dd"]
proxy-protocol = true
`)

	entry := listenerAccess(t, conf)[0]

	require.Nil(t, entry.IPv4, "a loopback socket must not be advertised to anyone")
	require.Nil(t, entry.IPv6)
	require.Contains(t, entry.Unreachable, "loopback")
	require.Contains(t, entry.Unreachable, "WEB relay backend",
		"the operator should know this is the expected shape, not a mistake")
}

// A config with no [[listener]] produces no listener block at all, so the
// output a deployment got before this existed is unchanged.
func TestListenerAccessIsAbsentWithoutListeners(t *testing.T) {
	t.Parallel()

	conf := listenerAccessConfig(t, "")

	require.Nil(t, listenerAccess(t, conf))
}

// Both listeners are described, in the order the file declares them.
func TestListenerAccessKeepsFileOrder(t *testing.T) {
	t.Parallel()

	conf := listenerAccessConfig(t, `
[[listener]]
bind-to = "0.0.0.0:8444"
accept = ["dd"]
public = true

[[listener]]
bind-to = "127.0.0.1:2398"
accept = ["plain"]
`)

	listeners := listenerAccess(t, conf)
	require.Len(t, listeners, 2)
	require.Equal(t, "0.0.0.0:8444", listeners[0].BindTo)
	require.Equal(t, "127.0.0.1:2398", listeners[1].BindTo)
}

// hexOf renders key bytes the way a secret does.
func hexOf(key []byte) string {
	secret := mtglib.Secret{Mode: mtglib.SecretModePlain}
	copy(secret.Key[:], key)

	return secret.PlainHex()
}
