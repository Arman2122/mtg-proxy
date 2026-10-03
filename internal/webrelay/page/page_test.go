package page_test

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/Arman2122/mtg-proxy/internal/webrelay/page"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

const (
	testHost  = "proxy.example.com"
	testToken = "MHLEY5PmW1GWqJkSrlmJpvJUiLhBH_QKy6yKg8a0JPk"
)

type PageTestSuite struct {
	suite.Suite

	bridge *page.Bridge
}

func (suite *PageTestSuite) SetupTest() {
	bridge, err := page.New(testHost)
	suite.Require().NoError(err)

	suite.bridge = bridge
}

func (suite *PageTestSuite) render() page.Document {
	doc, err := suite.bridge.Render(testToken)
	suite.Require().NoError(err)

	return doc
}

func (suite *PageTestSuite) csp() string {
	return suite.render().Header.Get("Content-Security-Policy")
}

// The three headers that must never appear. Each of them independently breaks
// the client's own system-browser fallback, which loads this document inside a
// frame owned by a loopback parent.
func (suite *PageTestSuite) TestNoFramingOrIsolationHeaders() {
	doc := suite.render()

	for _, name := range []string{
		"X-Frame-Options",
		"Cross-Origin-Opener-Policy",
		"Cross-Origin-Embedder-Policy",
	} {
		suite.Empty(doc.Header.Get(name), name)
	}
}

func (suite *PageTestSuite) TestFrameAncestorsNamesTheLoopbackParent() {
	suite.Contains(suite.csp(), "frame-ancestors http://127.0.0.1:*")
}

// connect-src is the document's entire network surface. Anything missing here
// is a carrier that cannot reach the relay; anything extra is reach the bridge
// does not need.
func (suite *PageTestSuite) TestConnectSourceIsTheOriginAndItsSocket() {
	suite.Contains(suite.csp(), "connect-src 'self' wss://"+testHost)
}

func (suite *PageTestSuite) TestPolicyDeniesEverythingElse() {
	csp := suite.csp()

	for _, directive := range []string{
		"default-src 'none'",
		"base-uri 'none'",
		"child-src 'none'",
		"font-src 'none'",
		"form-action 'none'",
		"frame-src 'none'",
		"img-src 'none'",
		"manifest-src 'none'",
		"media-src 'none'",
		"object-src 'none'",
		"style-src 'none'",
		"worker-src 'none'",
		"sandbox allow-same-origin allow-scripts",
	} {
		suite.Contains(csp, directive)
	}
}

// allow-same-origin is not decoration: without it the sandbox gives the document
// an opaque origin, fetch sends Origin: null, and 'self' in connect-src matches
// nothing. The pair has to survive together.
func (suite *PageTestSuite) TestSandboxKeepsBothTokens() {
	csp := suite.csp()
	suite.Contains(csp, "allow-same-origin")
	suite.Contains(csp, "allow-scripts")
}

// The script runs only under the nonce this response minted. Two responses that
// shared one would let a cached copy of the first authorise a script in the
// second.
func (suite *PageTestSuite) TestNonceIsPerResponseAndAuthorisesTheScript() {
	pattern := regexp.MustCompile(`script-src 'nonce-([A-Za-z0-9_-]{22})'`)

	first := suite.render()
	second := suite.render()

	firstMatch := pattern.FindStringSubmatch(first.Header.Get("Content-Security-Policy"))
	secondMatch := pattern.FindStringSubmatch(second.Header.Get("Content-Security-Policy"))

	suite.Require().Len(firstMatch, 2)
	suite.Require().Len(secondMatch, 2)
	suite.NotEqual(firstMatch[1], secondMatch[1])

	suite.Contains(string(first.HTML()), `<script nonce="`+firstMatch[1]+`">`)
	suite.Contains(string(second.HTML()), `<script nonce="`+secondMatch[1]+`">`)
}

// One inline script and nothing else. A second element that loads or executes
// anything would need its own nonce and would be a second thing to review.
func (suite *PageTestSuite) TestExactlyOneScriptAndNoExternalReferences() {
	html := string(suite.render().HTML())

	suite.Equal(1, strings.Count(html, "<script"))
	suite.Equal(1, strings.Count(html, "</script>"))
	suite.NotContains(html, "src=")
	suite.NotContains(html, "<link")
	suite.NotContains(html, "http://")

	// The only occurrences of the origin are inside the boot object.
	suite.Equal(1, strings.Count(html, testHost))
}

func (suite *PageTestSuite) TestBootParametersReachTheScript() {
	html := string(suite.render().HTML())

	suite.Contains(html, `var TPROXY_BOOT={`)
	suite.Contains(html, `"host":"`+testHost+`"`)
	suite.Contains(html, `"token":"`+testToken+`"`)
	suite.Contains(html, `"mode":"`+page.CarrierMode+`"`)
}

func (suite *PageTestSuite) TestResponseIsUncacheable() {
	doc := suite.render()

	suite.Equal("no-store", doc.Header.Get("Cache-Control"))
	suite.Equal("no-referrer", doc.Header.Get("Referrer-Policy"))
	suite.Equal("nosniff", doc.Header.Get("X-Content-Type-Options"))
	suite.Equal("text/html; charset=utf-8", doc.Header.Get("Content-Type"))
}

func (suite *PageTestSuite) TestWriteToEmitsHeadersAndBody() {
	recorder := httptest.NewRecorder()

	suite.Require().NoError(suite.render().WriteTo(recorder))
	suite.Equal(http.StatusOK, recorder.Code)
	suite.Equal("no-store", recorder.Header().Get("Cache-Control"))
	suite.Contains(recorder.Body.String(), "TPROXY_BOOT")
	suite.NotEmpty(recorder.Header().Get("Content-Security-Policy"))
}

// A host that could carry a CRLF, a quote or a space would forge a response
// header out of the CSP. It cannot reach this package uncanonicalised today;
// the check is what keeps that true.
func (suite *PageTestSuite) TestHostIsRefusedUnlessCanonical() {
	for _, host := range []string{
		"",
		"localhost",
		"proxy.example.com\r\nX-Injected: 1",
		"Proxy.Example.Com",
		"proxy.example.com:443",
		"пример.рф",
		"proxy example com",
		strings.Repeat("a.", 200) + "example.com",
	} {
		_, err := page.New(host)
		suite.Require().ErrorIs(err, page.ErrInvalidHost, host)
	}
}

func (suite *PageTestSuite) TestTokenIsRefusedUnlessCanonical() {
	for _, token := range []string{
		"",
		testToken + "=",
		strings.ReplaceAll(testToken, "_", "/"),
		testToken[:len(testToken)-1] + "l", // trailing bits set
		"not a token",
	} {
		_, err := suite.bridge.Render(token)
		suite.Require().ErrorIs(err, page.ErrInvalidToken, token)
	}
}

// The bridge must be able to hold any token the relay mints, and the relay
// mints 32 bytes in unpadded base64url.
func (suite *PageTestSuite) TestAcceptsAMintedToken() {
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = byte(i)
	}

	_, err := suite.bridge.Render(base64.RawURLEncoding.EncodeToString(raw))
	suite.Require().NoError(err)
}

func TestPage(t *testing.T) {
	t.Parallel()
	suite.Run(t, &PageTestSuite{})
}

// The script is ES5 by syntax. The runtime APIs it uses are modern; the syntax
// level is what keeps it parseable in the oldest WebView a supported client
// embeds, and a stray arrow function or template literal is a silent blank page
// on exactly one platform.
// Rendering a page does not copy the script into it: the script is one part
// of the document, shared by every render, and a page per new session costs
// only its few hundred bytes of nonce, token and headers.
func TestRenderDoesNotCopyTheScript(t *testing.T) { //nolint: paralleltest // reads the allocator's totals
	bridge, err := page.New(testHost)
	require.NoError(t, err)

	const renders = 100

	docs := make([]page.Document, 0, renders)

	var before, after runtime.MemStats

	runtime.ReadMemStats(&before)

	for range renders {
		doc, err := bridge.Render(testToken)
		require.NoError(t, err)

		docs = append(docs, doc)
	}

	runtime.ReadMemStats(&after)

	perRender := (after.TotalAlloc - before.TotalAlloc) / renders
	require.Len(t, docs, renders)
	require.Less(t, perRender, uint64(4<<10), "a render allocates %d bytes", perRender)
}

func TestScriptStaysES5(t *testing.T) {
	t.Parallel()

	bridge, err := page.New(testHost)
	require.NoError(t, err)

	doc, err := bridge.Render(testToken)
	require.NoError(t, err)

	html := string(doc.HTML())
	script := html[strings.Index(html, "<script"):]

	for _, banned := range []struct {
		pattern *regexp.Regexp
		name    string
	}{
		{regexp.MustCompile(`=>`), "arrow function"},
		{regexp.MustCompile(`\blet\s`), "let"},
		{regexp.MustCompile("`"), "template literal"},
		{regexp.MustCompile(`\bclass\s+\w`), "class"},
		{regexp.MustCompile(`\bconst\s`), "const"},
		{regexp.MustCompile(`\.\.\.`), "spread"},
		{regexp.MustCompile(`\basync\s`), "async"},
	} {
		require.NotRegexp(t, banned.pattern, script, banned.name)
	}
}
