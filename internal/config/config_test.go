package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Arman2122/mtg-proxy/internal/config"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type ConfigTestSuite struct {
	suite.Suite
}

func (suite *ConfigTestSuite) ReadConfig(filename string) []byte {
	data, err := os.ReadFile(filepath.Join("testdata", filename))
	suite.NoError(err)

	return data
}

func (suite *ConfigTestSuite) TestParseEmpty() {
	_, err := config.Parse([]byte{})
	suite.Error(err)
}

func (suite *ConfigTestSuite) TestParseBrokenToml() {
	_, err := config.Parse(suite.ReadConfig("broken.toml"))
	suite.Error(err)
}

func (suite *ConfigTestSuite) TestParseOnlySecret() {
	_, err := config.Parse(suite.ReadConfig("only_secret.toml"))
	suite.Error(err)
}

func (suite *ConfigTestSuite) TestParseMinimalConfig() {
	conf, err := config.Parse(suite.ReadConfig("minimal.toml"))
	suite.NoError(err)
	suite.Equal("7oe1GqLy6TBc38CV3jx7q09nb29nbGUuY29t", conf.Secret.Base64())
	suite.Require().Len(conf.BindTo, 1)
	suite.Equal("0.0.0.0:3128", conf.BindTo[0].Get(""))
}

func (suite *ConfigTestSuite) TestParseMultiBind() {
	conf, err := config.Parse(suite.ReadConfig("multi_bind.toml"))
	suite.NoError(err)
	suite.Require().Len(conf.BindTo, 2)
	suite.Equal("127.0.0.1:443", conf.BindTo[0].Get(""))
	suite.Equal("[::1]:443", conf.BindTo[1].Get(""))
}

func (suite *ConfigTestSuite) TestMultiBindGetAddrs() {
	conf, err := config.Parse(suite.ReadConfig("multi_bind.toml"))
	suite.NoError(err)

	addrs := conf.GetBindAddrs()
	suite.Equal([]string{"127.0.0.1:443", "[::1]:443"}, addrs)
}

func (suite *ConfigTestSuite) TestMultiBindGetFirstPort() {
	conf, err := config.Parse(suite.ReadConfig("multi_bind.toml"))
	suite.NoError(err)
	suite.Equal(uint(443), conf.GetFirstBindPort())
}

func (suite *ConfigTestSuite) TestGetFirstBindPortEmpty() {
	conf := &config.Config{}
	suite.Equal(uint(0), conf.GetFirstBindPort())
}

func (suite *ConfigTestSuite) TestParseEmptyBindArray() {
	_, err := config.Parse(suite.ReadConfig("empty_bind.toml"))
	suite.Error(err)
}

func (suite *ConfigTestSuite) TestParseInvalidBindAddr() {
	_, err := config.Parse(suite.ReadConfig("invalid_bind_addr.toml"))
	suite.Error(err)
}

func (suite *ConfigTestSuite) TestParseNonStringBind() {
	_, err := config.Parse(suite.ReadConfig("non_string_bind.toml"))
	suite.Error(err)
}

func (suite *ConfigTestSuite) TestValidateDuplicateBindAddrs() {
	conf, err := config.Parse(suite.ReadConfig("duplicate_bind.toml"))
	suite.NoError(err)
	suite.Error(conf.Validate())
}

func (suite *ConfigTestSuite) TestParsePublicIP() {
	conf, err := config.Parse(suite.ReadConfig("public_ip.toml"))
	suite.NoError(err)
	suite.Equal("203.0.113.1", conf.PublicIPv4.Get(nil).String())
	suite.Equal("2001:db8::1", conf.PublicIPv6.Get(nil).String())
}

func (suite *ConfigTestSuite) TestParsePublicIPv4Only() {
	conf, err := config.Parse(suite.ReadConfig("public_ip_v4_only.toml"))
	suite.NoError(err)
	suite.Equal("203.0.113.1", conf.PublicIPv4.Get(nil).String())
	suite.Nil(conf.PublicIPv6.Get(nil))
}

func (suite *ConfigTestSuite) TestParsePublicIPInvalid() {
	_, err := config.Parse(suite.ReadConfig("public_ip_invalid.toml"))
	suite.Error(err)
}

func (suite *ConfigTestSuite) TestParsePublicIPNotSet() {
	conf, err := config.Parse(suite.ReadConfig("minimal.toml"))
	suite.NoError(err)
	suite.Nil(conf.PublicIPv4.Get(nil))
	suite.Nil(conf.PublicIPv6.Get(nil))
}

func (suite *ConfigTestSuite) TestString() {
	conf, err := config.Parse(suite.ReadConfig("minimal.toml"))
	suite.NoError(err)
	suite.NotEmpty(conf.String())
}

func (suite *ConfigTestSuite) TestDomainFrontingIPIgnoredWhenHostSet() {
	conf, err := config.Parse(suite.ReadConfig("minimal.toml"))
	suite.NoError(err)

	suite.NoError(conf.DomainFronting.Host.Set("fronting-backend"))
	suite.NoError(conf.DomainFronting.IP.Set("10.0.0.10"))
	suite.NoError(conf.Validate())
	suite.Equal("fronting-backend", conf.GetDomainFrontingHost())
}

func (suite *ConfigTestSuite) TestDomainFrontingHostFromTOML() {
	conf, err := config.Parse(suite.ReadConfig("domain_fronting_host.toml"))
	suite.NoError(err)
	suite.NoError(conf.Validate())
	suite.Equal("fronting-backend", conf.GetDomainFrontingHost())
}

func (suite *ConfigTestSuite) TestDomainFrontingHostAcceptsLiteralIP() {
	conf, err := config.Parse(suite.ReadConfig("domain_fronting_host_ip.toml"))
	suite.NoError(err)
	suite.NoError(conf.Validate())
	suite.Equal("10.0.0.1", conf.GetDomainFrontingHost())
}

func (suite *ConfigTestSuite) TestDomainFrontingIPIgnoredFromTOML() {
	conf, err := config.Parse(suite.ReadConfig("domain_fronting_ip.toml"))
	suite.NoError(err)
	suite.NoError(conf.Validate())
	// Deprecated [domain-fronting].ip is parsed but never used to derive
	// the dial target — the user must migrate to [domain-fronting].host.
	suite.NotNil(conf.DomainFronting.IP.Get(nil))
	suite.Equal("", conf.GetDomainFrontingHost())
}

func (suite *ConfigTestSuite) TestDomainFrontingNotSet() {
	conf, err := config.Parse(suite.ReadConfig("minimal.toml"))
	suite.NoError(err)
	suite.NoError(conf.Validate())
	suite.Equal("", conf.GetDomainFrontingHost())
}

func (suite *ConfigTestSuite) TestParseAdTag() {
	conf, err := config.Parse(suite.ReadConfig("adtag.toml"))
	suite.Require().NoError(err)
	suite.NoError(conf.Validate())

	global := conf.GetAdTag()
	suite.Require().NotNil(global)
	suite.Equal("0123456789abcdef0123456789abcdef", conf.AdTag.String())

	suite.Equal("s3cr3t", conf.GetAPIToken())

	perSecret := conf.GetSecretAdTags()
	suite.Require().Contains(perSecret, "bob")
	suite.NotContains(perSecret, "alice")
}

func (suite *ConfigTestSuite) TestParseAdTagBadLength() {
	_, err := config.Parse([]byte("bind-to = \"0.0.0.0:3128\"\nsecret = \"7oe1GqLy6TBc38CV3jx7q09nb29nbGUuY29t\"\nad-tag = \"abcd\"\n"))
	suite.Error(err)
}

func (suite *ConfigTestSuite) TestValidateAdTagUnknownSecret() {
	conf, err := config.Parse(suite.ReadConfig("adtag_unknown_secret.toml"))
	suite.Require().NoError(err)
	suite.Error(conf.Validate())
}

func (suite *ConfigTestSuite) TestParseMinimalNoAdTag() {
	conf, err := config.Parse(suite.ReadConfig("minimal.toml"))
	suite.Require().NoError(err)
	suite.NoError(conf.Validate())
	suite.Nil(conf.GetAdTag())
	suite.Nil(conf.GetSecretAdTags())
	suite.Equal("", conf.GetAPIToken())
}

func TestConfig(t *testing.T) {
	t.Parallel()
	suite.Run(t, &ConfigTestSuite{})
}

// The one caller of Config.String is a Debug log line, and a log file outlives
// the process and is read by whatever ships it. Every credential in the file has
// to be gone from that string, and the names have to survive -- knowing which
// clients are configured is the reason to log the configuration at all.
//
// The secret values are matched as substrings of the whole rendering rather than
// by key, so a credential that reappears under a field nobody thought about
// still fails this.
func TestConfigStringRedactsEveryCredential(t *testing.T) {
	t.Parallel()

	const (
		aliceSecret = "7oe1GqLy6TBc38CV3jx7q09nb29nbGUuY29t"
		bobSecret   = "7ni1GqLy6TBc38CV3jx7q09nb29nbGUuY29t"
		apiToken    = "s3cr3t-management-token"
		// Ad tags are what @MTProxybot issued to this operator; whoever holds
		// one can present another proxy's traffic as theirs.
		globalAdTag = "0123456789abcdef0123456789abcdef"
		bobAdTag    = "fedcba9876543210fedcba9876543210"
	)

	conf, err := config.Parse([]byte(`
secret = "` + aliceSecret + `"
bind-to = "0.0.0.0:3128"
api-token = "` + apiToken + `"
ad-tag = "` + globalAdTag + `"

[secrets]
alice = "` + aliceSecret + `"
bob = "` + bobSecret + `"

[secret-ad-tags]
bob = "` + bobAdTag + `"
`))
	require.NoError(t, err)

	rendered := conf.String()

	// The hex spelling is what a Secret marshals to, so both are checked: the
	// input spelling and the one the encoder would actually emit.
	for _, credential := range []string{
		aliceSecret,
		bobSecret,
		apiToken,
		globalAdTag,
		bobAdTag,
		conf.Secret.String(),
		conf.Secrets["bob"].String(),
	} {
		require.NotContains(t, rendered, credential, "a credential reached the log rendering")
	}

	require.Contains(t, rendered, "alice", "the secret names must survive redaction")
	require.Contains(t, rendered, "bob")
	require.Contains(t, rendered, "0.0.0.0:3128", "ordinary settings must survive redaction")
}
