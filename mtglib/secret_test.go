package mtglib_test

import (
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/Arman2122/mtg-proxy/mtglib"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type SecretTestSuite struct {
	suite.Suite
}

func (suite *SecretTestSuite) TestParseSecret() {
	secretData, _ := hex.DecodeString("d11c6cbbd9efe7fed5bc0db220b09665")
	s := mtglib.Secret{
		Host: "google.com",
	}

	copy(s.Key[:], secretData)

	testData := map[string]string{
		"hex":    "eed11c6cbbd9efe7fed5bc0db220b09665676f6f676c652e636f6d",
		"base64": "7tEcbLvZ7-f-1bwNsiCwlmVnb29nbGUuY29t",
	}

	for name, value := range testData {
		param := value

		suite.T().Run(name, func(t *testing.T) {
			parsed, err := mtglib.ParseSecret(param)
			assert.NoError(t, err)
			assert.Equal(t, s.Key, parsed.Key)
			assert.Equal(t, s.Host, parsed.Host)
			assert.Equal(t, mtglib.SecretModeFakeTLS, parsed.Mode)

			newSecret := mtglib.Secret{}
			assert.NoError(t, newSecret.UnmarshalText([]byte(param)))
			assert.Equal(t, s.Key, newSecret.Key)
			assert.Equal(t, s.Host, newSecret.Host)
			assert.Equal(t, mtglib.SecretModeFakeTLS, newSecret.Mode)
		})
	}
}

// TestFrozenSerialization is the panel contract. A separate repo parses the
// strings Hex(), Base64() and String() return for a hosted (ee) secret, so the
// expected values below are LITERALS lifted from the pre-mode implementation
// (git show HEAD:mtglib/secret.go), not regenerated from this one. If a change
// to makeBytes makes this test fail, the change is wrong, not the test.
func (suite *SecretTestSuite) TestFrozenSerialization() {
	testData := []struct {
		key       string
		host      string
		hex       string
		base64    string
		stringRep string
	}{
		{
			key:       "d11c6cbbd9efe7fed5bc0db220b09665",
			host:      "google.com",
			hex:       "eed11c6cbbd9efe7fed5bc0db220b09665676f6f676c652e636f6d",
			base64:    "7tEcbLvZ7-f-1bwNsiCwlmVnb29nbGUuY29t",
			stringRep: "7tEcbLvZ7-f-1bwNsiCwlmVnb29nbGUuY29t",
		},
		{
			key:       "00000000000000000000000000000001",
			host:      "a",
			hex:       "ee0000000000000000000000000000000161",
			base64:    "7gAAAAAAAAAAAAAAAAAAAAFh",
			stringRep: "7gAAAAAAAAAAAAAAAAAAAAFh",
		},
		{
			key:       "ffffffffffffffffffffffffffffffff",
			host:      "www.cloudflare.com",
			hex:       "eeffffffffffffffffffffffffffffffff7777772e636c6f7564666c6172652e636f6d",
			base64:    "7v____________________93d3cuY2xvdWRmbGFyZS5jb20",
			stringRep: "7v____________________93d3cuY2xvdWRmbGFyZS5jb20",
		},
		{
			key:       "deadbeefdeadbeefdeadbeefdeadbeef",
			host:      "storage.googleapis.com",
			hex:       "eedeadbeefdeadbeefdeadbeefdeadbeef73746f726167652e676f6f676c65617069732e636f6d",
			base64:    "7t6tvu_erb7v3q2-796tvu9zdG9yYWdlLmdvb2dsZWFwaXMuY29t",
			stringRep: "7t6tvu_erb7v3q2-796tvu9zdG9yYWdlLmdvb2dsZWFwaXMuY29t",
		},
	}

	for _, v := range testData {
		param := v

		suite.T().Run(param.host, func(t *testing.T) {
			raw, err := hex.DecodeString(param.key)
			assert.NoError(t, err)

			// Deliberately a bare literal with no Mode: the zero value MUST stay
			// FakeTLS, which is what keeps every such literal in this tree correct.
			s := mtglib.Secret{Host: param.host}
			copy(s.Key[:], raw)

			assert.Equal(t, param.hex, s.Hex())
			assert.Equal(t, param.base64, s.Base64())
			assert.Equal(t, param.stringRep, s.String())

			marshalled, err := s.MarshalText()
			assert.NoError(t, err)
			assert.Equal(t, param.stringRep, string(marshalled))
		})
	}
}

func (suite *SecretTestSuite) TestSerialize() {
	s := mtglib.Secret{}

	data, err := s.MarshalText()
	suite.NoError(err)
	suite.Empty(data)

	secretData, _ := hex.DecodeString("d11c6cbbd9efe7fed5bc0db220b09665")
	s = mtglib.Secret{
		Host: "google.com",
	}

	copy(s.Key[:], secretData)

	suite.Equal("eed11c6cbbd9efe7fed5bc0db220b09665676f6f676c652e636f6d", s.Hex())
	suite.Equal("7tEcbLvZ7-f-1bwNsiCwlmVnb29nbGUuY29t", s.Base64())
}

func (suite *SecretTestSuite) TestMarshalData() {
	secretData, _ := hex.DecodeString("d11c6cbbd9efe7fed5bc0db220b09665")
	s := mtglib.Secret{
		Host: "google.com",
	}

	copy(s.Key[:], secretData)

	data, err := json.Marshal(&s)
	suite.NoError(err)
	suite.Equal(string(data), `"7tEcbLvZ7-f-1bwNsiCwlmVnb29nbGUuY29t"`)
}

// Length discriminates before the first byte does, so all three of these parse
// -- including a 16-byte value that happens to start with 0xee or 0xdd.
func (suite *SecretTestSuite) TestParseModes() {
	testData := []struct {
		name string
		text string
		mode mtglib.SecretMode
		key  string
		host string
	}{
		{"plain-hex", "d11c6cbbd9efe7fed5bc0db220b09665", mtglib.SecretModePlain, "d11c6cbbd9efe7fed5bc0db220b09665", ""},
		{"plain-leading-ee", "eed11c6cbbd9efe7fed5bc0db220b096", mtglib.SecretModePlain, "eed11c6cbbd9efe7fed5bc0db220b096", ""},
		{"plain-leading-dd", "ddd11c6cbbd9efe7fed5bc0db220b096", mtglib.SecretModePlain, "ddd11c6cbbd9efe7fed5bc0db220b096", ""},
		{"dd-hex", "ddd11c6cbbd9efe7fed5bc0db220b09665", mtglib.SecretModeDD, "d11c6cbbd9efe7fed5bc0db220b09665", ""},
		{
			"ee-hex", "eed11c6cbbd9efe7fed5bc0db220b09665676f6f676c652e636f6d",
			mtglib.SecretModeFakeTLS, "d11c6cbbd9efe7fed5bc0db220b09665", "google.com",
		},
	}

	for _, v := range testData {
		param := v

		suite.T().Run(param.name, func(t *testing.T) {
			parsed, err := mtglib.ParseSecret(param.text)
			assert.NoError(t, err)
			assert.Equal(t, param.mode, parsed.Mode)
			assert.Equal(t, param.host, parsed.Host)
			assert.Equal(t, param.key, hex.EncodeToString(parsed.Key[:]))
		})
	}
}

func (suite *SecretTestSuite) TestRoundTripAllModes() {
	key, _ := hex.DecodeString("d11c6cbbd9efe7fed5bc0db220b09665")

	testData := []struct {
		name string
		mode mtglib.SecretMode
		host string
		hex  string
	}{
		{"ee", mtglib.SecretModeFakeTLS, "google.com", "eed11c6cbbd9efe7fed5bc0db220b09665676f6f676c652e636f6d"},
		{"dd", mtglib.SecretModeDD, "", "ddd11c6cbbd9efe7fed5bc0db220b09665"},
		{"plain", mtglib.SecretModePlain, "", "d11c6cbbd9efe7fed5bc0db220b09665"},
	}

	for _, v := range testData {
		param := v

		suite.T().Run(param.name, func(t *testing.T) {
			s := mtglib.Secret{Host: param.host, Mode: param.mode}
			copy(s.Key[:], key)

			assert.Equal(t, param.hex, s.Hex())

			for form, text := range map[string]string{"hex": s.Hex(), "base64": s.Base64()} {
				parsed, err := mtglib.ParseSecret(text)
				assert.NoError(t, err, form)
				assert.Equal(t, s, parsed, form)
			}
		})
	}
}

// The link helpers render the same 16 bytes in another form regardless of the
// stored mode.
func (suite *SecretTestSuite) TestLinkHelpers() {
	s, err := mtglib.ParseSecret("eed11c6cbbd9efe7fed5bc0db220b09665676f6f676c652e636f6d")
	suite.NoError(err)

	suite.Equal("d11c6cbbd9efe7fed5bc0db220b09665", s.PlainHex())
	suite.Equal("ddd11c6cbbd9efe7fed5bc0db220b09665", s.DDHex())
	suite.Equal("eed11c6cbbd9efe7fed5bc0db220b09665676f6f676c652e636f6d", s.Hex())
}

func (suite *SecretTestSuite) TestIncorrectSecret() {
	testData := []string{
		"aaa",
		"+ueJ0q91t5XOnFYP8Xac3A",
		// 17 bytes that are not the dd form.
		"eed11c6cbbd9efe7fed5bc0db220b09665",
		"efd11c6cbbd9efe7fed5bc0db220b09665",
		"ed11c6cbbd9efe7fed5bc0db220b09665",
		"",
		"+**",
		"ee",
		// 18+ bytes that do not start with 0xee.
		"ddd11c6cbbd9efe7fed5bc0db220b09665676f6f676c652e636f6d",
		// All-zero keys are refused at parse time in every mode.
		"00000000000000000000000000000000",
		"dd00000000000000000000000000000000",
		"ee00000000000000000000000000000000676f6f676c652e636f6d",
	}

	for _, v := range testData {
		param := v

		suite.T().Run(param, func(t *testing.T) {
			_, err := mtglib.ParseSecret(param)
			assert.Error(t, err)
		})
	}
}

// An ee-prefixed secret with no hostname is 17 bytes, so it lands in the dd arm
// and is refused there. It is loud either way, which is what matters.
// Set overwrites the whole receiver. UnmarshalText is reached through a
// pre-populated Secret in the config decoder, so a leftover Host from an
// earlier ee value must not survive a re-Set to a hostless mode.
func (suite *SecretTestSuite) TestSetOverwritesPopulatedSecret() {
	s := mtglib.Secret{Host: "google.com"}
	copy(s.Key[:], []byte("0123456789abcdef"))

	suite.Require().NoError(s.Set("d11c6cbbd9efe7fed5bc0db220b09665"))
	suite.Equal(mtglib.SecretModePlain, s.Mode)
	suite.Empty(s.Host)
	suite.Equal("d11c6cbbd9efe7fed5bc0db220b09665", hex.EncodeToString(s.Key[:]))
}

func (suite *SecretTestSuite) TestEEWithoutHostname() {
	_, err := mtglib.ParseSecret("eed11c6cbbd9efe7fed5bc0db220b09665")
	suite.Error(err)
	suite.Contains(err.Error(), "0xdd")
}

func (suite *SecretTestSuite) TestInvariant() {
	generated := mtglib.GenerateSecret("google.com")

	parsed, err := mtglib.ParseSecret(generated.Hex())
	suite.NoError(err)
	suite.Equal(generated.Key, parsed.Key)
	suite.Equal(generated.Host, parsed.Host)
	suite.Equal("google.com", parsed.Host)
	suite.Equal(mtglib.SecretModeFakeTLS, generated.Mode)
}

func (suite *SecretTestSuite) TestGenerateSecretMode() {
	testData := []struct {
		mode mtglib.SecretMode
		host string
	}{
		{mtglib.SecretModeFakeTLS, "google.com"},
		{mtglib.SecretModeDD, ""},
		{mtglib.SecretModePlain, ""},
	}

	for _, v := range testData {
		param := v

		suite.T().Run(param.mode.String(), func(t *testing.T) {
			generated, err := mtglib.GenerateSecretMode(param.mode, param.host)
			assert.NoError(t, err)
			assert.Equal(t, param.mode, generated.Mode)
			assert.Equal(t, param.host, generated.Host)
			assert.True(t, generated.Valid())

			parsed, err := mtglib.ParseSecret(generated.Hex())
			assert.NoError(t, err)
			assert.Equal(t, generated, parsed)
		})
	}
}

func (suite *SecretTestSuite) TestGenerateSecretModeIncorrect() {
	_, err := mtglib.GenerateSecretMode(mtglib.SecretModeFakeTLS, "")
	suite.Error(err)

	_, err = mtglib.GenerateSecretMode(mtglib.SecretModeDD, "google.com")
	suite.Error(err)

	_, err = mtglib.GenerateSecretMode(mtglib.SecretModePlain, "google.com")
	suite.Error(err)

	_, err = mtglib.GenerateSecretMode(mtglib.SecretMode(200), "")
	suite.Error(err)
}

func (suite *SecretTestSuite) TestValid() {
	s := mtglib.Secret{}
	suite.False(s.Valid())

	s.Key[0] = 1
	suite.False(s.Valid())

	s.Host = "11"
	suite.True(s.Valid())
}

// A hostless secret is valid in dd and plain -- there is no place on the wire
// for a hostname there, so demanding one would mean storing a lie.
func (suite *SecretTestSuite) TestValidPerMode() {
	testData := []struct {
		name     string
		mode     mtglib.SecretMode
		host     string
		expected bool
	}{
		{"ee-with-host", mtglib.SecretModeFakeTLS, "google.com", true},
		{"ee-without-host", mtglib.SecretModeFakeTLS, "", false},
		{"dd-without-host", mtglib.SecretModeDD, "", true},
		{"plain-without-host", mtglib.SecretModePlain, "", true},
	}

	for _, v := range testData {
		param := v

		suite.T().Run(param.name, func(t *testing.T) {
			s := mtglib.Secret{Host: param.host, Mode: param.mode}
			s.Key[0] = 1

			assert.Equal(t, param.expected, s.Valid())

			// An empty key is never valid, whatever the mode.
			empty := mtglib.Secret{Host: param.host, Mode: param.mode}
			assert.False(t, empty.Valid())
		})
	}
}

func (suite *SecretTestSuite) TestHosted() {
	suite.True(mtglib.Secret{}.Hosted())
	suite.True(mtglib.Secret{Mode: mtglib.SecretModeFakeTLS}.Hosted())
	suite.False(mtglib.Secret{Mode: mtglib.SecretModeDD}.Hosted())
	suite.False(mtglib.Secret{Mode: mtglib.SecretModePlain}.Hosted())
}

func TestSecret(t *testing.T) {
	t.Parallel()
	suite.Run(t, &SecretTestSuite{})
}
