package webrelay

import (
	"bytes"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Arman2122/mtg-proxy/internal/webrelay/frame"
	"github.com/Arman2122/mtg-proxy/mtglib"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

const originHost = "proxy.example.com"

// coverMarker is what the cover site answers with. Every assertion that a
// request was NOT recognised looks for it, so the three tiers are told apart by
// what the client actually receives rather than by an internal flag.
const coverMarker = "the ordinary website"

type OriginTestSuite struct {
	suite.Suite

	origin  *Origin
	signer  *Signer
	secrets []mtglib.Secret
	clock   time.Time
	backend *pipeBackend
	covered chan *http.Request
}

func (suite *OriginTestSuite) SetupTest() {
	suite.clock = time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	suite.covered = make(chan *http.Request, 16)
	suite.backend = newPipeBackend()

	signer, err := NewSigner(bytes.Repeat([]byte{7}, TokenKeySize))
	suite.Require().NoError(err)

	suite.signer = signer
	suite.secrets = make([]mtglib.Secret, 0, 2)

	for i := range 2 {
		secret := mtglib.Secret{Mode: mtglib.SecretModeFakeTLS, Host: "www.cloudflare.com"}
		secret.Key[0] = byte(i + 1)
		suite.secrets = append(suite.secrets, secret)
	}

	cover := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		suite.covered <- r
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, coverMarker)
	})

	origin, err := NewOrigin(OriginOptions{
		Host:        originHost,
		Secrets:     suite.secrets,
		Signer:      signer,
		Cover:       cover,
		Backend:     suite.backend,
		MaxSessions: 2,
		now:         func() time.Time { return suite.clock },
	})
	suite.Require().NoError(err)

	suite.origin = origin
}

func (suite *OriginTestSuite) capability(index int) string {
	capability, err := Derive(WebSecret(suite.secrets[index]), originHost)
	suite.Require().NoError(err)

	return capability.String()
}

func (suite *OriginTestSuite) do(r *http.Request) *httptest.ResponseRecorder {
	recorder := httptest.NewRecorder()
	suite.origin.ServeHTTP(recorder, r)

	return recorder
}

func (suite *OriginTestSuite) get(target string) *httptest.ResponseRecorder {
	return suite.do(httptest.NewRequest(http.MethodGet, target, nil))
}

// isCover asserts the request reached the website untouched.
func (suite *OriginTestSuite) isCover(recorder *httptest.ResponseRecorder) {
	suite.Equal(http.StatusOK, recorder.Code)
	suite.Equal(coverMarker, recorder.Body.String())
}

// isLocal404 asserts the tier-two answer: authentic, unusable, never forwarded.
func (suite *OriginTestSuite) isLocal404(recorder *httptest.ResponseRecorder) {
	suite.Equal(http.StatusNotFound, recorder.Code)
	suite.Equal("no-store", recorder.Header().Get("Cache-Control"))
	suite.Empty(suite.covered, "an authentic credential was handed to the cover site")
}

func (suite *OriginTestSuite) TestExactBridgeRequestServesThePage() {
	recorder := suite.get("/?bridge=" + suite.capability(0))

	suite.Equal(http.StatusOK, recorder.Code)
	suite.Contains(recorder.Body.String(), "TPROXY_BOOT")
	suite.Equal("no-store", recorder.Header().Get("Cache-Control"))
	suite.NotEmpty(recorder.Header().Get("Content-Security-Policy"))
	suite.Empty(recorder.Header().Get("X-Frame-Options"))
}

// Every profile gets its own bridge, and each page carries a token minted for
// that request alone.
func (suite *OriginTestSuite) TestEachProfileAndEachRequestGetsItsOwnToken() {
	first := suite.get("/?bridge=" + suite.capability(0)).Body.String()
	second := suite.get("/?bridge=" + suite.capability(1)).Body.String()
	again := suite.get("/?bridge=" + suite.capability(0)).Body.String()

	suite.NotEqual(first, second)
	suite.NotEqual(first, again)
}

// Tier three. Nothing authentic is present, so the origin must behave exactly
// as though it were not here -- on the API paths too, which may be real routes
// of whatever site is being fronted.
func (suite *OriginTestSuite) TestUnauthenticatedRequestsReachTheWebsite() {
	for _, target := range []string{
		"/",
		"/?bridge=",
		"/?bridge=not-a-capability",
		"/index.html",
		"/api/v1/session",
		"/api/v1/ws",
		"/api/v1/down?cursor=1",
	} {
		suite.Run(target, func() {
			suite.isCover(suite.get(target))
		})
	}
}

// Tier two, and the reason it exists: any of these forwarded to the cover site
// would write an operator's real capability into a third party's access log.
func (suite *OriginTestSuite) TestAnAuthenticCapabilityIsNeverForwarded() {
	capability := suite.capability(0)

	raw, err := base64.RawURLEncoding.DecodeString(capability)
	suite.Require().NoError(err)

	testData := map[string]*http.Request{
		"on the wrong path":     httptest.NewRequest(http.MethodGet, "/somewhere?bridge="+capability, nil),
		"with the wrong method": httptest.NewRequest(http.MethodPost, "/?bridge="+capability, nil),
		"under another name":    httptest.NewRequest(http.MethodGet, "/?b="+capability, nil),
		"with an extra field":   httptest.NewRequest(http.MethodGet, "/?bridge="+capability+"&x=1", nil),
		"duplicated":            httptest.NewRequest(http.MethodGet, "/?bridge="+capability+"&bridge="+capability, nil),
		"padded":                httptest.NewRequest(http.MethodGet, "/?bridge="+capability+"%3D", nil),
		"padded standard":       httptest.NewRequest(http.MethodGet, "/?bridge="+escape(base64.StdEncoding.EncodeToString(raw)), nil),
	}

	for name, request := range testData {
		suite.Run(name, func() {
			suite.isLocal404(suite.do(request))
		})
	}
}

// Percent-encoding is a transport spelling, not a capability spelling: every
// HTTP stack between here and the client may add or remove it, so the decoded
// value is what counts. Serving the bridge for one leaks nothing -- whoever
// sent it already holds the capability -- and refusing it would make the relay
// depend on a normalisation no layer guarantees.
func (suite *OriginTestSuite) TestAPercentEncodedCapabilityStillSelectsTheBridge() {
	capability := suite.capability(0)
	encoded := "%" + hexOf(capability[0]) + capability[1:]

	recorder := suite.do(httptest.NewRequest(http.MethodGet, "/?bridge="+encoded, nil))

	suite.Equal(http.StatusOK, recorder.Code)
	suite.Contains(recorder.Body.String(), "TPROXY_BOOT")
	suite.Empty(suite.covered, "the capability must not have reached the cover site")
}

// A capability does not have to arrive where the bridge expects it to be a
// secret worth not leaking.
func (suite *OriginTestSuite) TestAnAuthenticCapabilityInAHeaderIsNotForwarded() {
	request := httptest.NewRequest(http.MethodGet, "/some/page", nil)
	request.Header.Set("X-Something", "prefix "+suite.capability(1))

	suite.isLocal404(suite.do(request))
}

func (suite *OriginTestSuite) TestAnAuthenticTokenIsNotForwarded() {
	token, err := suite.signer.Mint(KindSession)
	suite.Require().NoError(err)

	request := httptest.NewRequest(http.MethodGet, "/anything", nil)
	request.Header.Set("Authorization", "Bearer "+token)

	suite.isLocal404(suite.do(request))
}

// helpers -------------------------------------------------------------------

// escape percent-encodes the characters a query value may not carry literally,
// so a standard-alphabet spelling survives the trip intact.
func escape(value string) string {
	return url.QueryEscape(value)
}

func hexOf(b byte) string {
	const digits = "0123456789ABCDEF"

	return string([]byte{digits[b>>4], digits[b&0x0F]})
}

// session creation ----------------------------------------------------------

func (suite *OriginTestSuite) bootstrap() string {
	body := suite.get("/?bridge=" + suite.capability(0)).Body.String()

	const marker = `"token":"`

	start := strings.Index(body, marker)
	suite.Require().Positive(start)

	rest := body[start+len(marker):]
	end := strings.IndexByte(rest, '"')
	suite.Require().Positive(end)

	return rest[:end]
}

func (suite *OriginTestSuite) createSession(token string, body []byte) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodPost, sessionPath, bytes.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+token)

	return suite.do(request)
}

func helloBytes(t require.TestingT) []byte {
	encoded, err := frame.Limits{}.EncodeBatch(nil, []frame.Frame{frame.NewHello()}, frame.ClientToRelay)
	require.NoError(t, err)

	return encoded
}

func (suite *OriginTestSuite) TestSessionCreation() {
	token := suite.bootstrap()
	recorder := suite.createSession(token, helloBytes(suite.T()))

	suite.Equal(http.StatusOK, recorder.Code)
	suite.Len(recorder.Header().Get("X-Session-Token"), TokenLength)
	suite.Equal("websocket", recorder.Header().Get("X-Carrier-Mode"))
	suite.Equal("no-store", recorder.Header().Get("Cache-Control"))

	welcome, err := frame.Limits{}.DecodeBatch(recorder.Body.Bytes(), frame.RelayToClient)
	suite.Require().NoError(err)
	suite.Require().Len(welcome, 1)
	suite.Equal(frame.TypeWelcome, welcome[0].Type)
}

// The bridge retries an ambiguous failure with the same body, so creation is
// idempotent on the bootstrap. Without this a lost response leaves a second
// session nobody owns.
func (suite *OriginTestSuite) TestSessionCreationIsIdempotent() {
	token := suite.bootstrap()
	hello := helloBytes(suite.T())

	first := suite.createSession(token, hello)
	second := suite.createSession(token, hello)

	suite.Equal(http.StatusOK, second.Code)
	suite.Equal(first.Header().Get("X-Session-Token"), second.Header().Get("X-Session-Token"))
	suite.Equal(first.Body.Bytes(), second.Body.Bytes())
	suite.Equal(1, suite.origin.store.countSessions())
}

func (suite *OriginTestSuite) TestSessionCreationRefusals() {
	hello := helloBytes(suite.T())

	suite.Run("a body that is not HELLO", func() {
		suite.isLocal404(suite.createSession(suite.bootstrap(), []byte("not a frame")))
	})

	suite.Run("an oversized body", func() {
		suite.isLocal404(suite.createSession(suite.bootstrap(), bytes.Repeat([]byte{0}, 128)))
	})

	suite.Run("a second body under one bootstrap", func() {
		token := suite.bootstrap()
		suite.Equal(http.StatusOK, suite.createSession(token, hello).Code)

		other := append(append([]byte(nil), hello...), hello...)
		suite.isLocal404(suite.createSession(token, other))
	})

	suite.Run("an expired bootstrap", func() {
		token := suite.bootstrap()
		suite.clock = suite.clock.Add(BootstrapTTL + time.Second)

		suite.isLocal404(suite.createSession(token, hello))
	})

	suite.Run("a session token used as a bootstrap", func() {
		session, err := suite.signer.Mint(KindSession)
		suite.Require().NoError(err)

		suite.isLocal404(suite.createSession(session, hello))
	})

	suite.Run("a cookie", func() {
		request := httptest.NewRequest(http.MethodPost, sessionPath, bytes.NewReader(hello))
		request.Header.Set("Authorization", "Bearer "+suite.bootstrap())
		request.Header.Set("Cookie", "session=1")

		suite.isLocal404(suite.do(request))
	})

	suite.Run("two Authorization fields", func() {
		request := httptest.NewRequest(http.MethodPost, sessionPath, bytes.NewReader(hello))
		request.Header.Add("Authorization", "Bearer "+suite.bootstrap())
		request.Header.Add("Authorization", "Bearer "+suite.bootstrap())

		// Authentic values are present, so this may not reach the website --
		// but it is not a usable credential either.
		suite.isLocal404(suite.do(request))
	})
}

// Capacity is a retryable transport failure, not a refusal: the bootstrap stays
// unspent so the byte-identical request works once there is room. Getting this
// backwards turns a moment of load into a client that must go all the way back
// to deriving its capability again.
func (suite *OriginTestSuite) TestCapacityLeavesTheBootstrapUnspent() {
	hello := helloBytes(suite.T())
	sessions := make([]string, 0, 2)

	for range 2 {
		recorder := suite.createSession(suite.bootstrap(), hello)
		suite.Require().Equal(http.StatusOK, recorder.Code)

		sessions = append(sessions, recorder.Header().Get("X-Session-Token"))
	}

	token := suite.bootstrap()
	full := suite.createSession(token, hello)

	suite.Equal(http.StatusServiceUnavailable, full.Code)
	suite.Equal("1", full.Header().Get("Retry-After"))
	suite.Equal("no-store", full.Header().Get("Cache-Control"))

	// One session goes, and the identical request now works.
	release := httptest.NewRequest(http.MethodDelete, sessionPath, nil)
	release.Header.Set("Authorization", "Bearer "+sessions[0])
	suite.Require().Equal(http.StatusNoContent, suite.do(release).Code)

	suite.Equal(http.StatusOK, suite.createSession(token, hello).Code)
}

func (suite *OriginTestSuite) TestSessionDeletion() {
	token := suite.bootstrap()
	session := suite.createSession(token, helloBytes(suite.T())).Header().Get("X-Session-Token")

	request := httptest.NewRequest(http.MethodDelete, sessionPath, nil)
	request.Header.Set("Authorization", "Bearer "+session)

	suite.Equal(http.StatusNoContent, suite.do(request).Code)
	suite.Equal(0, suite.origin.store.countSessions())

	// A repeat names a session this relay no longer holds. It is still ours, so
	// it is answered locally.
	suite.isLocal404(suite.do(request))
}

func TestOrigin(t *testing.T) {
	t.Parallel()
	suite.Run(t, &OriginTestSuite{})
}

// The recognition scan must not be a way to spend the origin's CPU: a request
// carrying a great many token-shaped strings is bounded, not walked.
func TestRecognitionScanIsBounded(t *testing.T) {
	t.Parallel()

	signer, err := NewSigner(bytes.Repeat([]byte{9}, TokenKeySize))
	require.NoError(t, err)

	secret := mtglib.Secret{Mode: mtglib.SecretModeDD}
	secret.Key[0] = 1

	origin, err := NewOrigin(OriginOptions{
		Host:    originHost,
		Secrets: []mtglib.Secret{secret},
		Signer:  signer,
		Cover:   http.NotFoundHandler(),
		Backend: newPipeBackend(),
	})
	require.NoError(t, err)

	noise := make([]string, 0, 512)
	for range 512 {
		noise = append(noise, base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{3}, 32)))
	}

	request := httptest.NewRequest(http.MethodGet, "/?x="+strings.Join(noise, "+"), nil)

	start := time.Now()
	origin.ServeHTTP(httptest.NewRecorder(), request)

	require.Less(t, time.Since(start), time.Second)
}

func TestCoverSiteRefusesDirectoryListings(t *testing.T) {
	t.Parallel()

	root := t.TempDir()

	cover, err := NewStaticCover(root)
	require.NoError(t, err)

	recorder := httptest.NewRecorder()
	cover.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/", nil))

	require.Equal(t, http.StatusNotFound, recorder.Code)
	require.NotContains(t, recorder.Body.String(), "<pre>")
}

func TestCoverSiteRequiresARealDirectory(t *testing.T) {
	t.Parallel()

	_, err := NewStaticCover("/definitely/not/here")
	require.Error(t, err)
}

// An origin that came up without a cover site would answer everything itself,
// which is the one configuration that cannot look like a website.
func TestOriginRequiresACoverSite(t *testing.T) {
	t.Parallel()

	signer, err := NewSigner(bytes.Repeat([]byte{9}, TokenKeySize))
	require.NoError(t, err)

	secret := mtglib.Secret{Mode: mtglib.SecretModeDD}
	secret.Key[0] = 1

	_, err = NewOrigin(OriginOptions{
		Host:    originHost,
		Secrets: []mtglib.Secret{secret},
		Signer:  signer,
		Backend: newPipeBackend(),
	})
	require.ErrorIs(t, err, ErrNoCoverSite)
}

// The client's address must come from wherever the deployment says, never from
// the socket: behind a front proxy that is loopback for every user alive.
func TestClientAddressComesFromTheConfiguredSource(t *testing.T) {
	t.Parallel()

	var seen net.Addr

	signer, err := NewSigner(bytes.Repeat([]byte{9}, TokenKeySize))
	require.NoError(t, err)

	secret := mtglib.Secret{Mode: mtglib.SecretModeDD}
	secret.Key[0] = 1

	origin, err := NewOrigin(OriginOptions{
		Host:    originHost,
		Secrets: []mtglib.Secret{secret},
		Signer:  signer,
		Cover:   http.NotFoundHandler(),
		Backend: newPipeBackend(),
		ClientIP: func(*http.Request) net.Addr {
			seen = &net.TCPAddr{IP: net.IPv4(203, 0, 113, 9), Port: 4242}

			return seen
		},
	})
	require.NoError(t, err)

	require.NotNil(t, origin)
	require.Nil(t, seen, "the resolver runs only for a carrier request")
}
