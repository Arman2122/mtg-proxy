package webrelay_test

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/Arman2122/mtg-proxy/internal/webrelay"
	"github.com/Arman2122/mtg-proxy/mtglib"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

// The published vectors. These come from the client's own specification, so
// reproducing them exactly is the interop assertion in this file: a derivation
// that merely looks right fails only against a real client.
const (
	vectorHost        = "proxy.example.com"
	vectorKeyHex      = "000102030405060708090a0b0c0d0e0f"
	vectorPlainBridge = "MHLEY5PmW1GWqJkSrlmJpvJUiLhBH_QKy6yKg8a0JPk"
	vectorDDBridge    = "IpJrt3e7sKtzPyoXy6w-Zj6GGEvsvclN66JzQEfPYLA"
)

func vectorSecret(t require.TestingT, mode mtglib.SecretMode) mtglib.Secret {
	raw, err := hex.DecodeString(vectorKeyHex)
	require.NoError(t, err)

	secret := mtglib.Secret{Mode: mode}
	copy(secret.Key[:], raw)

	return secret
}

type CapabilityTestSuite struct {
	suite.Suite
}

func (suite *CapabilityTestSuite) TestPublishedVectors() {
	plain, err := webrelay.Derive(vectorSecret(suite.T(), mtglib.SecretModePlain), vectorHost)
	suite.Require().NoError(err)
	suite.Equal(vectorPlainBridge, plain.String())

	dd, err := webrelay.Derive(vectorSecret(suite.T(), mtglib.SecretModeDD), vectorHost)
	suite.Require().NoError(err)
	suite.Equal(vectorDDBridge, dd.String())

	suite.Len(plain.String(), webrelay.CapabilityLength)
	suite.Len(dd.String(), webrelay.CapabilityLength)
}

// The dd byte is part of the HMAC KEY, not a mode flag we may strip: a 17-byte
// key, not 16. Hashing the bare key reproduces the PLAIN vector instead, which
// is a sharper statement than "it fails".
func (suite *CapabilityTestSuite) TestDDByteIsPartOfKey() {
	secret := vectorSecret(suite.T(), mtglib.SecretModeDD)

	mac := hmac.New(sha256.New, secret.Key[:])
	mac.Write([]byte("tdesktop-web-proxy-bridge-v1\n" + vectorHost))
	withoutDD := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	suite.NotEqual(vectorDDBridge, withoutDD)
	suite.Equal(vectorPlainBridge, withoutDD)
}

// Hex and base64url spellings that decode to the same bytes must derive the
// same capability, so an operator may configure either.
func (suite *CapabilityTestSuite) TestSecretSpellingIrrelevant() {
	for _, spelling := range []string{
		"dd" + vectorKeyHex,
		base64.RawURLEncoding.EncodeToString(append([]byte{0xdd}, suite.rawKey()...)),
	} {
		suite.Run(spelling, func() {
			secret := mtglib.Secret{}
			suite.Require().NoError(secret.Set(spelling))

			capability, err := webrelay.Derive(secret, vectorHost)
			suite.Require().NoError(err)
			suite.Equal(vectorDDBridge, capability.String())
		})
	}
}

// A WEB client refuses an ee secret before it ever opens a connection, so a
// capability derived from one could never be presented.
func (suite *CapabilityTestSuite) TestFakeTLSSecretRejected() {
	secret := vectorSecret(suite.T(), mtglib.SecretModeFakeTLS)
	secret.Host = "storage.googleapis.com"

	_, err := webrelay.Derive(secret, vectorHost)
	suite.Require().ErrorIs(err, webrelay.ErrUnsupportedSecretMode)
}

func (suite *CapabilityTestSuite) TestDistinctInputsDistinctCapabilities() {
	base, err := webrelay.Derive(vectorSecret(suite.T(), mtglib.SecretModePlain), vectorHost)
	suite.Require().NoError(err)

	otherHost, err := webrelay.Derive(vectorSecret(suite.T(), mtglib.SecretModePlain), "other.example.com")
	suite.Require().NoError(err)
	suite.NotEqual(base, otherHost)

	otherKey := vectorSecret(suite.T(), mtglib.SecretModePlain)
	otherKey.Key[15] ^= 0x01

	otherSecret, err := webrelay.Derive(otherKey, vectorHost)
	suite.Require().NoError(err)
	suite.NotEqual(base, otherSecret)
}

func (suite *CapabilityTestSuite) rawKey() []byte {
	raw, err := hex.DecodeString(vectorKeyHex)
	suite.Require().NoError(err)

	return raw
}

type CanonicalHostTestSuite struct {
	suite.Suite
}

func (suite *CanonicalHostTestSuite) TestAccepted() {
	testData := map[string]string{
		"proxy.example.com":     "proxy.example.com",
		"PROXY.Example.COM":     "proxy.example.com",
		"xn--e1afmkfd.xn--p1ai": "xn--e1afmkfd.xn--p1ai",
		"пример.рф":             "xn--e1afmkfd.xn--p1ai",
		"a.b.c.example.com":     "a.b.c.example.com",
		"proxy-1.example.com":   "proxy-1.example.com",
	}

	for input, expected := range testData {
		suite.Run(input, func() {
			actual, err := webrelay.CanonicalHost(input)
			suite.Require().NoError(err)
			suite.Equal(expected, actual)
		})
	}
}

func (suite *CanonicalHostTestSuite) TestRejected() {
	longLabel := ""
	for range 64 {
		longLabel += "a"
	}

	longName := ""
	for range 10 {
		longName += "abcdefghijklmnopqrstuvwxyz0123456789."
	}

	testData := map[string]string{
		"empty":            "",
		"scheme":           "https://proxy.example.com",
		"port":             "proxy.example.com:443",
		"path":             "proxy.example.com/bridge",
		"query":            "proxy.example.com?bridge=x",
		"fragment":         "proxy.example.com#android=x",
		"userinfo":         "user@proxy.example.com",
		"ipv6 brackets":    "[2001:db8::1]",
		"trailing dot":     "proxy.example.com.",
		"leading dot":      ".example.com",
		"empty label":      "proxy..example.com",
		"ipv4 literal":     "203.0.113.7",
		"single label":     "example",
		"localhost":        "localhost",
		"underscore":       "proxy_1.example.com",
		"leading hyphen":   "-proxy.example.com",
		"space":            "proxy example.com",
		"fullwidth dotted": "proxy．．example.com",
		"label too long":   longLabel + ".example.com",
		"name too long":    longName + "example.com",
	}

	for name, input := range testData {
		suite.Run(name, func() {
			_, err := webrelay.CanonicalHost(input)
			suite.Require().ErrorIs(err, webrelay.ErrInvalidHost)
		})
	}
}

// Derive canonicalises for the caller, so an uppercase or Unicode spelling of
// the vector host must still land on the published value.
func (suite *CanonicalHostTestSuite) TestDeriveCanonicalises() {
	capability, err := webrelay.Derive(vectorSecret(suite.T(), mtglib.SecretModePlain), "PROXY.Example.COM")
	suite.Require().NoError(err)
	suite.Equal(vectorPlainBridge, capability.String())

	_, err = webrelay.Derive(vectorSecret(suite.T(), mtglib.SecretModePlain), "proxy.example.com.")
	suite.Require().ErrorIs(err, webrelay.ErrInvalidHost)
}

type ParseCapabilityTestSuite struct {
	suite.Suite
}

func (suite *ParseCapabilityTestSuite) TestCanonical() {
	capability, ok := webrelay.ParseCapability(vectorPlainBridge)
	suite.Require().True(ok)
	suite.Equal(vectorPlainBridge, capability.String())
}

func (suite *ParseCapabilityTestSuite) TestRejected() {
	// The 43rd character carries only four meaningful bits. "...JPl" sets one
	// of the two unused ones: right length, right alphabet, decodes to the same
	// 32 bytes -- and is a second spelling of an authentic capability, so it
	// must not select the bridge.
	nonCanonical := vectorPlainBridge[:webrelay.CapabilityLength-1] + "l"
	suite.Require().Len(nonCanonical, webrelay.CapabilityLength)

	decoded, err := base64.RawURLEncoding.DecodeString(nonCanonical)
	suite.Require().NoError(err)
	suite.Equal(vectorPlainBridge, base64.RawURLEncoding.EncodeToString(decoded),
		"the fixture must re-encode to the canonical vector")

	testData := map[string]string{
		"empty":           "",
		"too short":       vectorPlainBridge[:webrelay.CapabilityLength-1],
		"too long":        vectorPlainBridge + "A",
		"padded":          vectorPlainBridge + "=",
		"standard base64": "MHLEY5PmW1GWqJkSrlmJpvJUiLhBH/QKy6yKg8a0JPk",
		"plus alphabet":   "IpJrt3e7sKtzPyoXy6w+Zj6GGEvsvclN66JzQEfPYLA",
		"invalid rune":    vectorPlainBridge[:webrelay.CapabilityLength-1] + "!",
		"non-canonical":   nonCanonical,
		"leading space":   " " + vectorPlainBridge[1:],
	}

	for name, input := range testData {
		suite.Run(name, func() {
			_, ok := webrelay.ParseCapability(input)
			suite.False(ok)
		})
	}
}

type RegistryTestSuite struct {
	suite.Suite
}

func (suite *RegistryTestSuite) secrets(count int) []mtglib.Secret {
	secrets := make([]mtglib.Secret, 0, count)

	for i := range count {
		secret := mtglib.Secret{Mode: mtglib.SecretModeDD}
		secret.Key[0] = byte(i + 1)
		secrets = append(secrets, secret)
	}

	return secrets
}

func (suite *RegistryTestSuite) TestLookupFindsEachProfile() {
	secrets := suite.secrets(5)

	registry, err := webrelay.NewRegistry(vectorHost, secrets)
	suite.Require().NoError(err)
	suite.Equal(5, registry.Len())

	for expected, secret := range secrets {
		capability, err := webrelay.Derive(secret, vectorHost)
		suite.Require().NoError(err)

		index, ok := registry.Lookup(capability.String())
		suite.Require().True(ok)
		suite.Equal(expected, index)
	}
}

func (suite *RegistryTestSuite) TestLookupMisses() {
	registry, err := webrelay.NewRegistry(vectorHost, suite.secrets(3))
	suite.Require().NoError(err)

	// An authentic capability for a host this registry does not serve, a
	// capability for an unconfigured secret, and a non-canonical parameter.
	stranger, err := webrelay.Derive(vectorSecret(suite.T(), mtglib.SecretModePlain), vectorHost)
	suite.Require().NoError(err)

	elsewhere, err := webrelay.Derive(suite.secrets(1)[0], "other.example.com")
	suite.Require().NoError(err)

	for _, param := range []string{
		stranger.String(),
		elsewhere.String(),
		vectorPlainBridge[:webrelay.CapabilityLength-1] + "l",
		"",
	} {
		_, ok := registry.Lookup(param)
		suite.False(ok)
	}
}

func (suite *RegistryTestSuite) TestEmptyRegistry() {
	registry, err := webrelay.NewRegistry(vectorHost, nil)
	suite.Require().NoError(err)
	suite.Equal(0, registry.Len())

	_, ok := registry.Lookup(vectorPlainBridge)
	suite.False(ok)
}

func (suite *RegistryTestSuite) TestCollisionRejected() {
	secrets := suite.secrets(2)
	secrets = append(secrets, secrets[0])

	_, err := webrelay.NewRegistry(vectorHost, secrets)
	suite.Require().ErrorIs(err, webrelay.ErrCapabilityCollision)
}

func (suite *RegistryTestSuite) TestInvalidProfileRejected() {
	secrets := suite.secrets(1)
	secrets = append(secrets, mtglib.Secret{Mode: mtglib.SecretModeFakeTLS, Host: "example.org"})

	_, err := webrelay.NewRegistry(vectorHost, secrets)
	suite.Require().ErrorIs(err, webrelay.ErrUnsupportedSecretMode)

	_, err = webrelay.NewRegistry("localhost", suite.secrets(1))
	suite.Require().ErrorIs(err, webrelay.ErrInvalidHost)
}

func TestCapability(t *testing.T) {
	t.Parallel()
	suite.Run(t, &CapabilityTestSuite{})
}

func TestCanonicalHost(t *testing.T) {
	t.Parallel()
	suite.Run(t, &CanonicalHostTestSuite{})
}

func TestParseCapability(t *testing.T) {
	t.Parallel()
	suite.Run(t, &ParseCapabilityTestSuite{})
}

func TestRegistry(t *testing.T) {
	t.Parallel()
	suite.Run(t, &RegistryTestSuite{})
}

func TestCapabilityStringIsAlwaysCanonical(t *testing.T) {
	t.Parallel()

	// Every derived capability must survive the server-side parse, otherwise a
	// profile could exist that no client can ever select.
	for i := range 256 {
		secret := mtglib.Secret{Mode: mtglib.SecretModeDD}
		secret.Key[0] = 1
		secret.Key[1] = byte(i)

		capability, err := webrelay.Derive(secret, vectorHost)
		require.NoError(t, err)

		parsed, ok := webrelay.ParseCapability(capability.String())
		assert.True(t, ok)
		assert.Equal(t, capability, parsed)
	}
}

// A hostname saved in a legacy 8-bit codepage -- exactly what an operator in the
// regions this proxy serves is likely to produce -- must be rejected outright.
// IDNA mapping replaces the invalid byte with U+FFFD and punycodes THAT, which
// slips past the disallowed-rune check that catches U+FFFD spelled validly, and
// derives a capability over an A-label no client will ever compute.
func (suite *CanonicalHostTestSuite) TestInvalidUTF8Rejected() {
	const (
		latin1 = "caf\xe9.example.com"      // café in Latin-1/CP1252
		wrong  = "xn--caf-7t7s.example.com" // what U+FFFD substitution produced
		right  = "xn--caf-dma.example.com"  // the real A-label for café
	)

	_, err := webrelay.CanonicalHost(latin1)
	suite.Require().ErrorIs(err, webrelay.ErrInvalidHost)

	// The asymmetry that hid the defect: only one of the two spellings of the
	// mis-derived name was ever accepted, so nothing round-tripped and nothing
	// complained.
	_, err = webrelay.CanonicalHost(wrong)
	suite.Require().ErrorIs(err, webrelay.ErrInvalidHost)

	for _, spelling := range []string{right, "café.example.com"} {
		canonical, err := webrelay.CanonicalHost(spelling)
		suite.Require().NoError(err)
		suite.Equal(right, canonical)
	}
}

// CanonicalHost must be a fixed point on its own output: the client hashes the
// canonical bytes, so a second pass that alters or rejects them means the server
// derives a capability over a name no client sends. The seeds run under an
// ordinary `go test`, so this is a regression test as well as a fuzz target.
func FuzzCanonicalHost(f *testing.F) {
	for _, seed := range []string{
		"",
		vectorHost,
		"PROXY.Example.COM",
		"пример.рф",
		"xn--e1afmkfd.xn--p1ai",
		"caf\xe9.example.com",
		"café.example.com",
		"xn--caf-dma.example.com",
		"xn--caf-7t7s.example.com",
		"proxy.example.com.",
		"proxy．．example.com",
		"192.0.2.1",
		"a.b",
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, host string) {
		canonical, err := webrelay.CanonicalHost(host)
		if err != nil {
			return
		}

		again, err := webrelay.CanonicalHost(canonical)
		require.NoError(t, err, "%q canonicalises to %q, which is itself rejected", host, canonical)
		require.Equal(t, canonical, again, "%q canonicalises to %q, then to %q", host, canonical, again)
	})
}

// The lenient decoder must see through every base64 spelling of the same 32
// bytes, because each one is an authentic capability wearing a disguise.
func (suite *ParseCapabilityTestSuite) TestLenientAcceptsEverySpelling() {
	canonical, ok := webrelay.ParseCapability(vectorPlainBridge)
	suite.Require().True(ok)

	for name, input := range lenientSpellings(vectorPlainBridge, "MHLEY5PmW1GWqJkSrlmJpvJUiLhBH/QKy6yKg8a0JPk") {
		suite.Run(name, func() {
			decoded, ok := webrelay.ParseCapabilityLenient(input)
			suite.Require().True(ok)
			suite.Equal(canonical, decoded)
		})
	}
}

// net/url's query decoders turn the standard alphabet's "+" into a space, so a
// handler that read the parameter with url.Values hands the registry a mangled
// spelling of a genuine capability. Recognising it anyway is what keeps that
// request out of the cover site's access log.
func (suite *ParseCapabilityTestSuite) TestLenientUndoesQueryPlusMangling() {
	const mangled = "IpJrt3e7sKtzPyoXy6w Zj6GGEvsvclN66JzQEfPYLA"

	decoded, ok := webrelay.ParseCapabilityLenient(mangled)
	suite.Require().True(ok)
	suite.Equal(vectorDDBridge, decoded.String())
}

func (suite *ParseCapabilityTestSuite) TestLenientStillRejectsNonCapabilities() {
	testData := map[string]string{
		"empty":          "",
		"too short":      vectorPlainBridge[:webrelay.CapabilityLength-1],
		"33 bytes":       vectorPlainBridge + "A",
		"double padded":  vectorPlainBridge + "==",
		"invalid rune":   vectorPlainBridge[:webrelay.CapabilityLength-1] + "!",
		"leading space":  " " + vectorPlainBridge,
		"mixed alphabet": "IpJrt3e7sKtzPyoXy6w+Zj6GGEvsvclN66JzQEfPYL_",
	}

	for name, input := range testData {
		suite.Run(name, func() {
			_, ok := webrelay.ParseCapabilityLenient(input)
			suite.False(ok)
		})
	}
}

// lenientSpellings names the noncanonical forms of one capability: the tier-two
// disguises. base64url is the canonical spelling and standard is the same 32
// bytes over the +/ alphabet.
func lenientSpellings(base64url, standard string) map[string]string {
	return map[string]string{
		"padded":          base64url + "=",
		"standard base64": standard,
		"standard padded": standard + "=",
		// The 43rd character carries only four meaningful bits; flipping the
		// lowest unused one leaves the decoded 32 bytes identical.
		"unused bits set": base64url[:webrelay.CapabilityLength-1] + unusedBitsSet(base64url),
	}
}

// unusedBitsSet returns a replacement for the final character that decodes to
// the same byte with an unused low bit set.
func unusedBitsSet(base64url string) string {
	last := base64url[webrelay.CapabilityLength-1]
	alphabet := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	value := strings.IndexByte(alphabet, last)

	return string(alphabet[value^0x01])
}

// RecognitionTestSuite covers the three tiers the package doc names. Getting the
// middle one wrong hands an operator's real capability to a third party's access
// log, which is the whole reason the tier exists.
type RecognitionTestSuite struct {
	suite.Suite

	registry *webrelay.Registry
}

func (suite *RecognitionTestSuite) SetupTest() {
	registry, err := webrelay.NewRegistry(vectorHost, []mtglib.Secret{
		vectorSecret(suite.T(), mtglib.SecretModePlain),
	})
	suite.Require().NoError(err)

	suite.registry = registry
}

// Tier one. The exact canonical spelling selects the profile, and is authentic
// too -- the same value on the wrong path is a tier-two request.
func (suite *RecognitionTestSuite) TestExactSpellingSelectsTheProfile() {
	index, ok := suite.registry.Lookup(vectorPlainBridge)
	suite.Require().True(ok)
	suite.Equal(0, index)
	suite.True(suite.registry.IsAuthentic(vectorPlainBridge))
}

// Tier two. Authentic but unusable: Lookup must refuse to serve the bridge and
// IsAuthentic must still recognise the value, so the handler answers locally
// instead of proxying a genuine capability to the public site.
func (suite *RecognitionTestSuite) TestAuthenticButUnusable() {
	for name, input := range lenientSpellings(vectorPlainBridge, "MHLEY5PmW1GWqJkSrlmJpvJUiLhBH/QKy6yKg8a0JPk") {
		suite.Run(name, func() {
			_, ok := suite.registry.Lookup(input)
			suite.False(ok, "a noncanonical spelling must never select the bridge")
			suite.True(suite.registry.IsAuthentic(input), "and must never reach the cover site")
		})
	}
}

// Tier three. Every one of these decodes to 32 bytes under the lenient reader,
// so it is the constant-time scan and not the decoder that rejects them.
func (suite *RecognitionTestSuite) TestUnauthentic() {
	testData := map[string]string{
		"unknown canonical": vectorDDBridge,
		"not base64":        "not-a-real-capability",
		"empty":             "",
		"all zero bytes":    strings.Repeat("A", webrelay.CapabilityLength),
	}
	for name, input := range lenientSpellings(vectorDDBridge, "IpJrt3e7sKtzPyoXy6w+Zj6GGEvsvclN66JzQEfPYLA") {
		testData["unknown "+name] = input
	}

	for name, input := range testData {
		suite.Run(name, func() {
			_, ok := suite.registry.Lookup(input)
			suite.False(ok)
			suite.False(suite.registry.IsAuthentic(input))
		})
	}
}

// The same "+"-to-space mangling at the registry boundary: still tier two, so
// still a local 404 rather than a trip through the public upstream.
func (suite *RecognitionTestSuite) TestQueryPlusManglingStaysAuthentic() {
	registry, err := webrelay.NewRegistry(vectorHost, []mtglib.Secret{
		vectorSecret(suite.T(), mtglib.SecretModeDD),
	})
	suite.Require().NoError(err)

	const mangled = "IpJrt3e7sKtzPyoXy6w Zj6GGEvsvclN66JzQEfPYLA"

	_, ok := registry.Lookup(mangled)
	suite.False(ok)
	suite.True(registry.IsAuthentic(mangled))
}

func (suite *RecognitionTestSuite) TestEmptyRegistryRecognisesNothing() {
	registry, err := webrelay.NewRegistry(vectorHost, nil)
	suite.Require().NoError(err)
	suite.False(registry.IsAuthentic(vectorPlainBridge))
	suite.False(registry.IsAuthentic(vectorPlainBridge + "="))
}

func TestRecognition(t *testing.T) {
	t.Parallel()
	suite.Run(t, &RecognitionTestSuite{})
}
