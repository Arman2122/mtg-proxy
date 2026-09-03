package mtglib_test

import (
	"testing"

	"github.com/Arman2122/mtg-proxy/mtglib"
	"github.com/Arman2122/mtg-proxy/mtglib/obfuscation"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type SecretModeTestSuite struct {
	suite.Suite
}

func (suite *SecretModeTestSuite) TestZeroValueIsFakeTLS() {
	var mode mtglib.SecretMode

	suite.Equal(mtglib.SecretModeFakeTLS, mode)
	suite.Equal("ee", mode.String())
}

func (suite *SecretModeTestSuite) TestString() {
	suite.Equal("ee", mtglib.SecretModeFakeTLS.String())
	suite.Equal("dd", mtglib.SecretModeDD.String())
	suite.Equal("plain", mtglib.SecretModePlain.String())
	suite.Equal("unknown(200)", mtglib.SecretMode(200).String())
}

func (suite *SecretModeTestSuite) TestParse() {
	testData := map[string]mtglib.SecretMode{
		"ee":      mtglib.SecretModeFakeTLS,
		"EE":      mtglib.SecretModeFakeTLS,
		"faketls": mtglib.SecretModeFakeTLS,
		" ee ":    mtglib.SecretModeFakeTLS,
		"dd":      mtglib.SecretModeDD,
		"plain":   mtglib.SecretModePlain,
	}

	for name, expected := range testData {
		param, exp := name, expected

		suite.T().Run(param, func(t *testing.T) {
			parsed, err := mtglib.ParseSecretMode(param)
			assert.NoError(t, err)
			assert.Equal(t, exp, parsed)
		})
	}
}

func (suite *SecretModeTestSuite) TestParseIncorrect() {
	for _, v := range []string{"", "eee", "e", "faketl", "abridged", "0xee"} {
		param := v

		suite.T().Run(param, func(t *testing.T) {
			_, err := mtglib.ParseSecretMode(param)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "plain")
		})
	}
}

func (suite *SecretModeTestSuite) TestMarshalRoundTrip() {
	for _, v := range []mtglib.SecretMode{
		mtglib.SecretModeFakeTLS, mtglib.SecretModeDD, mtglib.SecretModePlain,
	} {
		mode := v

		suite.T().Run(mode.String(), func(t *testing.T) {
			data, err := mode.MarshalText()
			assert.NoError(t, err)
			assert.Equal(t, mode.String(), string(data))

			var parsed mtglib.SecretMode

			assert.NoError(t, parsed.UnmarshalText(data))
			assert.Equal(t, mode, parsed)
		})
	}
}

func (suite *SecretModeTestSuite) TestUnmarshalTextIncorrect() {
	mode := mtglib.SecretModePlain

	suite.Error(mode.UnmarshalText([]byte("nonsense")))
	suite.Equal(mtglib.SecretModePlain, mode, "a failed unmarshal must not clobber the value")
}

func (suite *SecretModeTestSuite) TestModeSetOf() {
	empty := mtglib.ModeSetOf()
	suite.True(empty.Empty())
	suite.False(empty.Has(mtglib.SecretModeFakeTLS))
	suite.Empty(empty.Strings())
	suite.Equal("", empty.String())

	set := mtglib.ModeSetOf(mtglib.SecretModeDD, mtglib.SecretModePlain)
	suite.False(set.Empty())
	suite.True(set.Has(mtglib.SecretModeDD))
	suite.True(set.Has(mtglib.SecretModePlain))
	suite.False(set.Has(mtglib.SecretModeFakeTLS))
	suite.Equal([]string{"dd", "plain"}, set.Strings())
	suite.Equal("dd,plain", set.String())
}

func (suite *SecretModeTestSuite) TestModeSetStringsSorted() {
	set := mtglib.ModeSetOf(mtglib.SecretModePlain, mtglib.SecretModeFakeTLS, mtglib.SecretModeDD)

	suite.Equal([]string{"dd", "ee", "plain"}, set.Strings())
	suite.Equal("dd,ee,plain", set.String())
}

func (suite *SecretModeTestSuite) TestParseModeSet() {
	set, err := mtglib.ParseModeSet([]string{"plain", "dd", "dd"})
	suite.NoError(err)
	suite.Equal(mtglib.ModeSetOf(mtglib.SecretModeDD, mtglib.SecretModePlain), set)

	set, err = mtglib.ParseModeSet(nil)
	suite.NoError(err)
	suite.True(set.Empty())

	_, err = mtglib.ParseModeSet([]string{"dd", "eee"})
	suite.Error(err)
}

// The FakeTLS-only default listener policy honours no obfuscated2 tag at all:
// its entry path never reaches the trial decryption loop.
func (suite *SecretModeTestSuite) TestTagsFakeTLSIsEmpty() {
	suite.True(mtglib.ModeSetOf(mtglib.SecretModeFakeTLS).Tags().Empty())
	suite.True(mtglib.ModeSetOf().Tags().Empty())
}

// dd means padded-intermediate and nothing else.
func (suite *SecretModeTestSuite) TestTagsDDIsExactlyPaddedIntermediate() {
	tags := mtglib.ModeSetOf(mtglib.SecretModeDD).Tags()

	suite.False(tags.Empty())
	suite.True(tags.Has(obfuscation.TagPaddedIntermediate))
	suite.False(tags.Has(obfuscation.TagIntermediate))
	suite.False(tags.Has(obfuscation.TagAbridged))
}

// F15: a bare 16-byte secret places no constraint on the client's transport --
// tdlib sends intermediate, tdesktop and iOS send abridged, and any of them may
// pick padded-intermediate. Honouring a subset silently breaks part of the
// client population.
func (suite *SecretModeTestSuite) TestTagsPlainIsAllThree() {
	tags := mtglib.ModeSetOf(mtglib.SecretModePlain).Tags()

	suite.True(tags.Has(obfuscation.TagPaddedIntermediate))
	suite.True(tags.Has(obfuscation.TagIntermediate))
	suite.True(tags.Has(obfuscation.TagAbridged))
}

func (suite *SecretModeTestSuite) TestTagsUnion() {
	tags := mtglib.ModeSetOf(mtglib.SecretModeDD, mtglib.SecretModePlain).Tags()

	suite.Equal(mtglib.ModeSetOf(mtglib.SecretModePlain).Tags(), tags)
}

func TestSecretMode(t *testing.T) {
	t.Parallel()
	suite.Run(t, &SecretModeTestSuite{})
}
