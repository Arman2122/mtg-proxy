package config_test

import (
	"fmt"
	"testing"

	"github.com/Arman2122/mtg-proxy/internal/config"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

// webConfigTOML is the shape a panel would emit for a WEB-enabled inbound: the
// proxy's own settings untouched, one loopback [[listener]], and a [web] table
// naming it.
func webConfigTOML(web string) string {
	return fmt.Sprintf(`
secret = "7oe1GqLy6TBc38CV3jx7q09nb29nbGUuY29t"
bind-to = "0.0.0.0:3128"

[[listener]]
bind-to = "127.0.0.1:2398"
accept = ["dd", "plain"]

%s

[secrets]
alice = "7oe1GqLy6TBc38CV3jx7q09nb29nbGUuY29t"
`, web)
}

const usableWeb = `
[web]
enabled = true
host = "proxy.example.com"
bind-to = "127.0.0.1:8099"
backend = "127.0.0.1:2398"
token-key = "/etc/mtg-proxy/web.key"
cover-dir = "/var/www/site"
`

type WebConfigTestSuite struct {
	suite.Suite
}

func (suite *WebConfigTestSuite) parse(web string) *config.Config {
	conf, err := config.Parse([]byte(webConfigTOML(web)))
	suite.Require().NoError(err)

	return conf
}

func (suite *WebConfigTestSuite) TestUsableConfiguration() {
	conf := suite.parse(usableWeb)

	suite.Require().NoError(conf.Validate())
	suite.Require().NoError(conf.ValidateWeb())

	listener, found := conf.WebBackendListener()
	suite.Require().True(found)
	suite.Equal("127.0.0.1:2398", listener.BindTo.Get(""))
}

// The relay dials one of the proxy's own sockets, so the address has to name a
// stanza that exists. Without this the failure is a connection refused per
// stream, forever, with the relay reporting nothing wrong.
func (suite *WebConfigTestSuite) TestBackendMustNameAListener() {
	conf := suite.parse(`
[web]
enabled = true
host = "proxy.example.com"
bind-to = "127.0.0.1:8099"
backend = "127.0.0.1:9999"
token-key = "/etc/mtg-proxy/web.key"
cover-dir = "/var/www/site"
`)

	suite.Require().ErrorContains(conf.ValidateWeb(), "names no [[listener]]")
}

// A WEB client can only hold a dd or plain secret, and this relay hands out dd.
// A backend that does not accept it would refuse every stream after a
// successful handshake, which looks like a working relay and a broken proxy.
func (suite *WebConfigTestSuite) TestBackendMustAcceptDD() {
	conf, err := config.Parse([]byte(`
secret = "7oe1GqLy6TBc38CV3jx7q09nb29nbGUuY29t"
bind-to = "0.0.0.0:3128"

[[listener]]
bind-to = "127.0.0.1:2398"
accept = ["plain"]

[web]
enabled = true
host = "proxy.example.com"
bind-to = "127.0.0.1:8099"
backend = "127.0.0.1:2398"
token-key = "/etc/mtg-proxy/web.key"
cover-dir = "/var/www/site"
`))
	suite.Require().NoError(err)
	suite.Require().ErrorContains(conf.ValidateWeb(), "does not accept dd")
}

// The hostname must serve a plausible website to everyone who is not a Telegram
// client, and there is no default: a starter page every operator installed would
// be a better distinguisher than anything the protocol leaks.
func (suite *WebConfigTestSuite) TestExactlyOneCoverSite() {
	suite.Run("neither", func() {
		conf := suite.parse(`
[web]
enabled = true
host = "proxy.example.com"
bind-to = "127.0.0.1:8099"
backend = "127.0.0.1:2398"
token-key = "/etc/mtg-proxy/web.key"
`)
		suite.Require().ErrorContains(conf.ValidateWeb(), "cover-dir or cover-upstream")
	})

	suite.Run("both", func() {
		conf := suite.parse(`
[web]
enabled = true
host = "proxy.example.com"
bind-to = "127.0.0.1:8099"
backend = "127.0.0.1:2398"
token-key = "/etc/mtg-proxy/web.key"
cover-dir = "/var/www/site"
cover-upstream = "http://127.0.0.1:8080"
`)
		suite.Require().ErrorContains(conf.ValidateWeb(), "cover-dir or cover-upstream")
	})
}

// A key invented at startup works until the first restart and then hands this
// relay's own live tokens to the cover site.
func (suite *WebConfigTestSuite) TestTokenKeyIsRequired() {
	conf := suite.parse(`
[web]
enabled = true
host = "proxy.example.com"
bind-to = "127.0.0.1:8099"
backend = "127.0.0.1:2398"
cover-dir = "/var/www/site"
`)

	suite.Require().ErrorContains(conf.ValidateWeb(), "token-key")
}

// A host a WEB client would refuse must never reach a running relay. Some of
// these are caught while parsing and some while validating; which one does it
// is an implementation detail, and the property is that none of them starts.
func (suite *WebConfigTestSuite) TestHostMustBeOneAClientAccepts() {
	testData := map[string]string{
		"a URL":        "https://proxy.example.com/",
		"with a port":  "proxy.example.com:443",
		"single label": "localhost",
		"an IP":        "203.0.113.7",
		"empty":        "",
	}

	for name, host := range testData {
		suite.Run(name, func() {
			conf, err := config.Parse([]byte(webConfigTOML(fmt.Sprintf(`
[web]
enabled = true
host = %q
bind-to = "127.0.0.1:8099"
backend = "127.0.0.1:2398"
token-key = "/etc/mtg-proxy/web.key"
cover-dir = "/var/www/site"
`, host))))
			if err != nil {
				return
			}

			suite.Require().Error(conf.ValidateWeb())
		})
	}
}

func (suite *WebConfigTestSuite) TestDisabledIsRefusedByTheRelayAlone() {
	conf := suite.parse(`
[web]
host = "proxy.example.com"
bind-to = "127.0.0.1:8099"
backend = "127.0.0.1:2398"
token-key = "/etc/mtg-proxy/web.key"
cover-dir = "/var/www/site"
`)

	// The proxy still starts. Only the relay refuses, and that separation is
	// the point: editing the relay's settings must never take the MTProto port
	// down.
	suite.Require().NoError(conf.Validate())
	suite.Require().ErrorContains(conf.ValidateWeb(), "not enabled")
}

// The relay finds its listener by address, and an address has more than one
// spelling. Matching on the string would leave the relay reporting that its own
// backend does not exist.
func (suite *WebConfigTestSuite) TestBackendAddressIsComparedByValue() {
	conf, err := config.Parse([]byte(`
secret = "7oe1GqLy6TBc38CV3jx7q09nb29nbGUuY29t"
bind-to = "0.0.0.0:3128"

[[listener]]
bind-to = "[::1]:2398"
accept = ["dd"]

[web]
enabled = true
host = "proxy.example.com"
bind-to = "127.0.0.1:8099"
backend = "[0:0:0:0:0:0:0:1]:2398"
token-key = "/etc/mtg-proxy/web.key"
cover-dir = "/var/www/site"
`))
	suite.Require().NoError(err)

	_, found := conf.WebBackendListener()
	suite.True(found, "a differently spelled address is the same socket")
}

func TestWebConfig(t *testing.T) {
	t.Parallel()
	suite.Run(t, &WebConfigTestSuite{})
}

// The panel writes this table before every deployment has a binary that
// understands it, so an older one has to load the file and ignore the block --
// including the tables written after it.
func TestAnOldBinaryIgnoresTheWebTable(t *testing.T) {
	t.Parallel()

	conf, err := config.Parse([]byte(webConfigTOML(usableWeb)))
	require.NoError(t, err)

	require.NoError(t, conf.Validate())
	require.Len(t, conf.GetSecrets(), 1, "the [secrets] table after [web] must still load")
}

func TestClientIPSourceParsing(t *testing.T) {
	t.Parallel()

	testData := map[string]config.ClientIPSource{
		"proxy-protocol":  config.ClientIPProxyProtocol,
		"x-forwarded-for": config.ClientIPForwardedFor,
		"XFF":             config.ClientIPForwardedFor,
	}

	for value, expected := range testData {
		var source config.TypeClientIPSource

		require.NoError(t, source.Set(value))
		require.Equal(t, expected, source.Get(config.ClientIPProxyProtocol))
	}

	var source config.TypeClientIPSource
	require.Error(t, source.Set("socket"))

	// Unset means proxy-protocol: the header a browser cannot forge, rather
	// than one it can.
	require.Equal(t, config.ClientIPProxyProtocol, source.Get(config.ClientIPProxyProtocol))
}
