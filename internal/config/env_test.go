package config_test

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/Arman2122/mtg-proxy/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

const (
	envTestSecretHex    = "ee367a189aee18fa31c190054efd4a8e9573746f726167652e676f6f676c65617069732e636f6d"
	envTestSecretBase64 = "7oe1GqLy6TBc38CV3jx7q09nb29nbGUuY29t"

	// A bare 16-byte key in the format of the official
	// telegrammessenger/proxy image (its Docker Hub example value).
	envTestBareKey = "00baadf00d15abad1deaa515baadcafe"
)

const envTestMultiSecretConfig = `
bind-to = "0.0.0.0:3128"
ad-tag = "0123456789abcdef0123456789abcdef"

[secrets]
alice = "ee367a189aee18fa31c190054efd4a8e9573746f726167652e676f6f676c65617069732e636f6d"
bob = "7oe1GqLy6TBc38CV3jx7q09nb29nbGUuY29t"

[secret-ad-tags]
bob = "fedcba9876543210fedcba9876543210"
`

// EnvTestSuite mutates process environment via T().Setenv, so its top-level
// test must not run in parallel.
type EnvTestSuite struct {
	suite.Suite
}

func (suite *EnvTestSuite) ParseConfig(text string) *config.Config {
	conf, err := config.Parse([]byte(text))
	suite.Require().NoError(err)

	return conf
}

func (suite *EnvTestSuite) MinimalConfig() *config.Config {
	return suite.ParseConfig("bind-to = \"0.0.0.0:3128\"\nsecret = \"" + envTestSecretBase64 + "\"\n")
}

func (suite *EnvTestSuite) TestNoEnvKeepsConfigUntouched() {
	conf := suite.ParseConfig(envTestMultiSecretConfig)
	suite.NoError(conf.ApplyEnvironment())
	suite.Len(conf.Secrets, 2)
	suite.NotNil(conf.GetAdTag())
	suite.Contains(conf.GetSecretAdTags(), "bob")
}

func (suite *EnvTestSuite) TestSecretOverridesSecretSet() {
	suite.T().Setenv("SECRET", envTestSecretHex)

	conf := suite.ParseConfig(envTestMultiSecretConfig)
	suite.NoError(conf.ApplyEnvironment())
	suite.NoError(conf.Validate())

	suite.Empty(conf.Secrets)
	suite.Nil(conf.GetSecretAdTags())
	suite.Equal(envTestSecretHex, conf.Secret.Hex())
	suite.True(conf.GetSecrets()["default"].Valid())
}

func (suite *EnvTestSuite) TestPrefixedSecretWins() {
	suite.T().Setenv("SECRET", "garbage")
	suite.T().Setenv("MTG_SECRET", envTestSecretBase64)

	conf := suite.MinimalConfig()
	suite.NoError(conf.ApplyEnvironment())
	suite.Equal(envTestSecretBase64, conf.Secret.Base64())
}

func (suite *EnvTestSuite) TestBareKeyNeedsHost() {
	suite.T().Setenv("SECRET", envTestBareKey)

	conf := suite.MinimalConfig()
	suite.ErrorContains(conf.ApplyEnvironment(), "SECRET_HOST")
}

// A bare key also arrives base64url-encoded, which is why the hostless guard
// keys off the parsed secret mode rather than hex decodability.
func (suite *EnvTestSuite) TestBareKeyBase64NeedsHost() {
	raw, err := hex.DecodeString(envTestBareKey)
	suite.Require().NoError(err)
	suite.T().Setenv("SECRET", base64.RawURLEncoding.EncodeToString(raw))

	conf := suite.MinimalConfig()
	suite.ErrorContains(conf.ApplyEnvironment(), "SECRET_HOST")
}

func (suite *EnvTestSuite) TestBareKeyBase64WithHost() {
	raw, err := hex.DecodeString(envTestBareKey)
	suite.Require().NoError(err)
	suite.T().Setenv("SECRET", base64.RawURLEncoding.EncodeToString(raw))
	suite.T().Setenv("SECRET_HOST", "storage.googleapis.com")

	conf := suite.MinimalConfig()
	suite.NoError(conf.ApplyEnvironment())
	suite.NoError(conf.Validate())
	suite.Equal("storage.googleapis.com", conf.Secret.Host)
	suite.Equal(envTestBareKey, hex.EncodeToString(conf.Secret.Key[:]))
}

func (suite *EnvTestSuite) TestBareKeyWithHost() {
	suite.T().Setenv("SECRET", envTestBareKey)
	suite.T().Setenv("SECRET_HOST", "storage.googleapis.com")

	conf := suite.MinimalConfig()
	suite.NoError(conf.ApplyEnvironment())
	suite.NoError(conf.Validate())
	suite.Equal("storage.googleapis.com", conf.Secret.Host)
	suite.Equal(envTestBareKey, hex.EncodeToString(conf.Secret.Key[:]))
}

func (suite *EnvTestSuite) TestGarbageSecret() {
	suite.T().Setenv("SECRET", "garbage")

	conf := suite.MinimalConfig()
	suite.Error(conf.ApplyEnvironment())
}

func (suite *EnvTestSuite) TestTagSetsAdTag() {
	suite.T().Setenv("TAG", "fedcba9876543210fedcba9876543210")

	conf := suite.MinimalConfig()
	suite.NoError(conf.ApplyEnvironment())
	suite.Equal("fedcba9876543210fedcba9876543210", conf.AdTag.String())
}

func (suite *EnvTestSuite) TestEmptyTagClearsAdTag() {
	suite.T().Setenv("TAG", "")

	conf := suite.ParseConfig(envTestMultiSecretConfig)
	suite.NoError(conf.ApplyEnvironment())
	suite.Nil(conf.GetAdTag())
}

func (suite *EnvTestSuite) TestBadTag() {
	suite.T().Setenv("TAG", "abcd")

	conf := suite.MinimalConfig()
	suite.Error(conf.ApplyEnvironment())
}

func (suite *EnvTestSuite) TestBindToSingle() {
	suite.T().Setenv("MTG_BIND_TO", "0.0.0.0:443")

	conf := suite.MinimalConfig()
	suite.NoError(conf.ApplyEnvironment())
	suite.Equal([]string{"0.0.0.0:443"}, conf.GetBindAddrs())
}

func (suite *EnvTestSuite) TestBindToMultiple() {
	suite.T().Setenv("MTG_BIND_TO", "127.0.0.1:443, [::1]:443")

	conf := suite.MinimalConfig()
	suite.NoError(conf.ApplyEnvironment())
	suite.Equal([]string{"127.0.0.1:443", "[::1]:443"}, conf.GetBindAddrs())
}

func (suite *EnvTestSuite) TestBindToInvalid() {
	suite.T().Setenv("MTG_BIND_TO", "example.com:443")

	conf := suite.MinimalConfig()
	suite.Error(conf.ApplyEnvironment())
}

func (suite *EnvTestSuite) TestBindToEmpty() {
	suite.T().Setenv("MTG_BIND_TO", " , ")

	conf := suite.MinimalConfig()
	suite.Error(conf.ApplyEnvironment())
}

func TestEnv(t *testing.T) {
	suite.Run(t, &EnvTestSuite{})
}

// C6 (D29): the environment's secret fully defines the secret set, so the
// file's [[retiring-secret]] entries -- previous keys of names no longer in
// effect -- are cleared with the rest of the file's set. That is the kill
// direction: a previous key is accepted only beside the file that granted it.
// Mutates the process environment, so it does not run in parallel.
//
// The "default" file is the case where the clear is the only defence: the
// file's previous key of its top-level secret is still named "default"
// beside the environment's secret, so rule 3 would not drop it, and without
// the clear the old key would be accepted next to the pinned one.
func TestTheSecretEnvironmentClearsRetiringEntries(t *testing.T) {
	const block = `
[[retiring-secret]]
name = "%s"
secret = "ee0f1e2d3c4b5a69788796a5b4c3d2e1f0676f6f676c652e636f6d"
until = "2999-01-01T00:00:00Z"
`

	now := time.Date(2026, 10, 8, 9, 30, 0, 0, time.UTC)

	// Neither spelling of the variable is set, whatever the test process
	// inherited; t.Setenv restores both afterwards.
	for _, name := range []string{"SECRET", "MTG_SECRET"} {
		t.Setenv(name, "")
		require.NoError(t, os.Unsetenv(name))
	}

	for _, file := range []struct {
		name, text string
	}{
		{"a [secrets] name", envTestMultiSecretConfig + fmt.Sprintf(block, "alice")},
		{"the top-level secret, as default", "bind-to = \"0.0.0.0:3128\"\nsecret = \"" + envTestSecretBase64 + "\"\n" +
			fmt.Sprintf(block, "default")},
	} {
		conf, err := config.Parse([]byte(file.text))
		require.NoError(t, err)
		require.NoError(t, conf.ApplyEnvironment())
		require.Equal(t, 1, len(conf.RetiringSecrets), "%s: without the variable the file's entry stays", file.name)
		require.Equal(t, 1, len(conf.GetRetiringSecrets(now).Usable), "%s: and is usable", file.name)

		for _, variable := range []string{"SECRET", "MTG_SECRET"} {
			t.Run(file.name+"/"+variable, func(t *testing.T) {
				t.Setenv(variable, envTestSecretHex)

				conf, err := config.Parse([]byte(file.text))
				require.NoError(t, err)
				require.NoError(t, conf.ApplyEnvironment())

				assert.True(t, conf.RetiringSecrets == nil, "%d entries survived the variable", len(conf.RetiringSecrets))
				rotEmptyReport(t, conf.GetRetiringSecrets(now), "under the variable")
				assert.NotContains(t, conf.String(), "retiringSecrets")
			})
		}
	}
}
