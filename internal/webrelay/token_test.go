package webrelay

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type TokenTestSuite struct {
	suite.Suite

	signer *Signer
}

func (suite *TokenTestSuite) SetupTest() {
	key := make([]byte, TokenKeySize)
	for i := range key {
		key[i] = byte(i)
	}

	signer, err := NewSigner(key)
	suite.Require().NoError(err)

	suite.signer = signer
}

func (suite *TokenTestSuite) TestMintedTokensLookLikeCapabilities() {
	for _, kind := range []TokenKind{KindBootstrap, KindSession} {
		token, err := suite.signer.Mint(kind)
		suite.Require().NoError(err)

		suite.Len(token, TokenLength)
		suite.True(suite.signer.Verify(token, kind))

		// The same length and alphabet as a bridge capability, on purpose: a
		// header value and a query value should not be distinguishable by shape.
		suite.Len(token, CapabilityLength)
	}
}

func (suite *TokenTestSuite) TestTokensAreUnique() {
	seen := make(map[string]struct{}, 64)

	for range 64 {
		token, err := suite.signer.Mint(KindBootstrap)
		suite.Require().NoError(err)

		_, duplicate := seen[token]
		suite.Require().False(duplicate)

		seen[token] = struct{}{}
	}
}

// The kind byte is what stops a bootstrap being presented as a session bearer.
// Without it, the page's own embedded token would authenticate the carrier.
func (suite *TokenTestSuite) TestAKindIsNotInterchangeable() {
	bootstrap, err := suite.signer.Mint(KindBootstrap)
	suite.Require().NoError(err)

	session, err := suite.signer.Mint(KindSession)
	suite.Require().NoError(err)

	suite.False(suite.signer.Verify(bootstrap, KindSession))
	suite.False(suite.signer.Verify(session, KindBootstrap))

	// Both are still recognised as ours, which is what keeps a misused token out
	// of the cover site's access log.
	suite.True(suite.signer.IsAuthentic(bootstrap))
	suite.True(suite.signer.IsAuthentic(session))
}

func (suite *TokenTestSuite) TestAnotherKeyDoesNotVerify() {
	token, err := suite.signer.Mint(KindBootstrap)
	suite.Require().NoError(err)

	other, err := NewSigner(make([]byte, TokenKeySize))
	suite.Require().NoError(err)

	suite.False(other.Verify(token, KindBootstrap))
	suite.False(other.IsAuthentic(token))
}

func (suite *TokenTestSuite) TestOnlyTheCanonicalSpellingVerifies() {
	token, err := suite.signer.Mint(KindBootstrap)
	suite.Require().NoError(err)

	for _, mangled := range []string{
		"",
		token + "=",
		token[:len(token)-1],
		strings.ReplaceAll(token, "_", "/"),
		strings.ToUpper(token),
	} {
		if mangled == token {
			continue
		}

		suite.False(suite.signer.Verify(mangled, KindBootstrap), mangled)
	}
}

// A flipped bit anywhere is a token this relay did not mint.
func (suite *TokenTestSuite) TestATamperedTokenIsRejected() {
	token, err := suite.signer.Mint(KindSession)
	suite.Require().NoError(err)

	raw, err := base64.RawURLEncoding.DecodeString(token)
	suite.Require().NoError(err)

	for i := range raw {
		tampered := append([]byte(nil), raw...)
		tampered[i] ^= 0x01

		spelled := base64.RawURLEncoding.EncodeToString(tampered)
		suite.False(suite.signer.Verify(spelled, KindSession), i)
		suite.False(suite.signer.IsAuthentic(spelled), i)
	}
}

func (suite *TokenTestSuite) TestKeySizeIsEnforced() {
	for _, size := range []int{0, 16, 31, 33, 64} {
		_, err := NewSigner(make([]byte, size))
		suite.Require().ErrorIs(err, ErrTokenKeySize)
	}
}

func TestToken(t *testing.T) {
	t.Parallel()
	suite.Run(t, &TokenTestSuite{})
}

// A relay that generated its own key when the file was missing would work
// perfectly until its first restart, and then start handing its own live
// clients' tokens to the cover site.
func TestTokenKeyIsNeverInvented(t *testing.T) {
	t.Parallel()

	_, err := LoadTokenKey(filepath.Join(t.TempDir(), "absent.key"))
	require.ErrorIs(t, err, ErrTokenKeyMissing)
}

func TestTokenKeyRoundTrip(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "token.key")
	require.NoError(t, GenerateTokenKey(path))

	signer, err := LoadTokenKey(path)
	require.NoError(t, err)

	token, err := signer.Mint(KindBootstrap)
	require.NoError(t, err)

	// A second load of the same file recognises the first load's tokens. That
	// is the property the whole file exists for: it survives a restart.
	reloaded, err := LoadTokenKey(path)
	require.NoError(t, err)
	require.True(t, reloaded.Verify(token, KindBootstrap))
}

// Rotating the key invalidates every live session, so replacing the file is
// always deliberate rather than a side effect of running a command twice.
func TestTokenKeyIsNotOverwritten(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "token.key")
	require.NoError(t, GenerateTokenKey(path))

	before, err := os.ReadFile(path)
	require.NoError(t, err)

	require.Error(t, GenerateTokenKey(path))

	after, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, before, after)
}

func TestTokenKeySizeIsCheckedOnDisk(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "short.key")
	require.NoError(t, os.WriteFile(path, make([]byte, 8), 0o600))

	_, err := LoadTokenKey(path)
	require.ErrorIs(t, err, ErrTokenKeySize)
}

// Anyone who can read the key can mint credentials the recognition tier accepts.
func TestTokenKeyPermissionsAreChecked(t *testing.T) {
	t.Parallel()

	if runtime.GOOS == "windows" {
		t.Skip("Windows expresses file access through ACLs, not a permission triple")
	}

	path := filepath.Join(t.TempDir(), "loose.key")
	require.NoError(t, GenerateTokenKey(path))
	require.NoError(t, os.Chmod(path, 0o644))

	_, err := LoadTokenKey(path)
	require.ErrorIs(t, err, ErrTokenKeyPermissions)
}
