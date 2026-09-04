package webrelay

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Arman2122/mtg-proxy/internal/webrelay/frame"
	"github.com/Arman2122/mtg-proxy/internal/webrelay/page"
	"github.com/Arman2122/mtg-proxy/internal/webrelay/ws"
	"github.com/Arman2122/mtg-proxy/mtglib"
)

// The paths this origin answers. They are ordinary-looking application routes on
// purpose: a request to one of them without an authentic credential is served by
// the cover site, exactly as if the relay were not here.
const (
	sessionPath = "/api/v1/session"
	carrierPath = "/api/v1/ws"
	bridgeQuery = "bridge"

	// subprotocolPrefix precedes the session token in the WebSocket handshake.
	subprotocolPrefix = "tproxy-v1."

	// maxCredentialAtoms bounds the recognition scan. A request cannot be made
	// expensive to classify by carrying a thousand token-shaped strings.
	maxCredentialAtoms = 64
)

// OriginOptions configures the public origin.
type OriginOptions struct {
	// Host is the canonical public hostname. It is the name the capability was
	// derived over, so it is fixed for the life of the process.
	Host string

	// Secrets are the profiles this relay serves, in the panel's order.
	Secrets []mtglib.Secret

	// Signer mints and recognises the bootstrap and session tokens.
	Signer *Signer

	// Cover handles every request that carries no authentic credential.
	Cover http.Handler

	// Backend opens the loopback connection each stream needs.
	Backend Backend

	// Limits are the two wire bounds a deployment may lower.
	Limits frame.Limits

	// MaxSessions bounds concurrent carrier sessions.
	MaxSessions int

	// MaxStreams bounds the streams inside one session.
	MaxStreams int

	// DialTimeout bounds one backend dial.
	DialTimeout time.Duration

	// ClientIP resolves the browser's address from a request. Returning nil
	// means the address is unknown, which is fatal for a stream but not for the
	// origin.
	ClientIP func(r *http.Request) net.Addr

	// Logger is optional.
	Logger mtglib.Logger

	// now is overridable in tests.
	now func() time.Time
}

// Origin is the HTTP face of the relay: one hostname, serving a website to
// everyone and a carrier to the clients that can prove they belong here.
//
// # The three tiers
//
// Every request lands in exactly one of three classes, and the classification
// happens before any routing decision:
//
//  1. Authentic and usable -- the carrier operation.
//  2. Authentic but unusable -- expired, spent, wrong method, wrong path, a
//     non-canonical spelling, a duplicated field. Answered LOCALLY with an
//     uncacheable 404. Never delegated, because delegating it writes an
//     operator's real credential into a third party's access log.
//  3. Everything else -- the cover site, unaltered, on every path including the
//     API ones, which may be genuine routes of whatever site is being fronted.
//
// The consequence worth stating plainly: this origin must be the only gateway
// for its hostname. Routing some paths around it re-creates the distinguisher
// the three tiers exist to remove -- a prober would see one component's 404 and
// another's, and could tell them apart by header order and timing.
type Origin struct {
	host     string
	registry *Registry
	signer   *Signer
	bridge   *page.Bridge
	cover    http.Handler
	store    *store
	welcome  []byte

	backend     Backend
	limits      frame.Limits
	maxStreams  int
	dialTimeout time.Duration
	clientIP    func(r *http.Request) net.Addr
	log         mtglib.Logger

	global *budget
}

// NewOrigin builds the origin. Every failure here is a startup failure: a relay
// that came up with an unusable profile set would serve the cover site to its
// own users, which is indistinguishable from working.
func NewOrigin(opts OriginOptions) (*Origin, error) {
	host, err := CanonicalHost(opts.Host)
	if err != nil {
		return nil, err
	}

	web := make([]mtglib.Secret, 0, len(opts.Secrets))
	for _, secret := range opts.Secrets {
		web = append(web, WebSecret(secret))
	}

	registry, err := NewRegistry(host, web)
	if err != nil {
		return nil, err
	}

	bridge, err := page.New(host)
	if err != nil {
		return nil, fmt.Errorf("cannot build the bridge page: %w", err)
	}

	if opts.Signer == nil {
		return nil, ErrTokenKeyMissing
	}

	if opts.Cover == nil {
		return nil, ErrNoCoverSite
	}

	welcome, err := frame.NewWelcome().EncodeForClient()
	if err != nil {
		return nil, fmt.Errorf("cannot encode WELCOME: %w", err)
	}

	return &Origin{
		host:        host,
		registry:    registry,
		signer:      opts.Signer,
		bridge:      bridge,
		cover:       opts.Cover,
		store:       newStore(opts.MaxSessions, opts.now),
		welcome:     welcome,
		backend:     opts.Backend,
		limits:      opts.Limits,
		maxStreams:  opts.MaxStreams,
		dialTimeout: opts.DialTimeout,
		clientIP:    opts.ClientIP,
		log:         opts.Logger,
		global:      newBudget(DefaultGlobalPendingBytes, DefaultGlobalPendingItems),
	}, nil
}

// ErrNoCoverSite means no handler was configured for unauthenticated requests.
// There is no safe default: serving nothing, or a built-in page, makes every
// deployment that skipped the decision look identical to a prober.
var ErrNoCoverSite = errors.New("no cover site configured for the WEB relay origin")

func (o *Origin) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if o.serveCarrier(w, r) {
		return
	}

	// Nothing usable. If anything authentic appears anywhere in the request's
	// metadata, this is ours and stays ours.
	if o.recognises(r) {
		o.notFound(w)

		return
	}

	o.cover.ServeHTTP(w, r)
}

// serveCarrier handles the request if it is authentic AND usable, reporting
// whether it did.
func (o *Origin) serveCarrier(w http.ResponseWriter, r *http.Request) bool {
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/":
		return o.serveBridge(w, r)
	case r.Method == http.MethodPost && r.URL.Path == sessionPath:
		return o.serveSessionCreate(w, r)
	case r.Method == http.MethodDelete && r.URL.Path == sessionPath:
		return o.serveSessionDelete(w, r)
	case r.URL.Path == carrierPath:
		return o.serveWebSocket(w, r)
	default:
		return false
	}
}

// serveBridge answers the one request that hands out a bootstrap.
//
// The match is exact: one query field, named bridge, spelled canonically,
// resolving to a configured profile. Everything else -- a missing field, a
// duplicated one, an extra one alongside it, a padded spelling -- fails here and
// is then classified by the recognition scan, so an authentic capability written
// wrongly gets the local 404 and an unauthentic one gets the website.
func (o *Origin) serveBridge(w http.ResponseWriter, r *http.Request) bool {
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil || len(query) != 1 {
		return false
	}

	values, ok := query[bridgeQuery]
	if !ok || len(values) != 1 {
		return false
	}

	profile, ok := o.registry.Lookup(values[0])
	if !ok {
		return false
	}

	token, err := o.signer.Mint(KindBootstrap)
	if err != nil {
		o.logError("cannot mint a bootstrap token", err)
		o.notFound(w)

		return true
	}

	document, err := o.bridge.Render(token)
	if err != nil {
		o.logError("cannot render the bridge page", err)
		o.notFound(w)

		return true
	}

	o.store.issueBootstrap(token, profile)

	if err := document.WriteTo(w); err != nil {
		o.logError("cannot write the bridge page", err)
	}

	return true
}

func (o *Origin) serveSessionCreate(w http.ResponseWriter, r *http.Request) bool {
	token, ok := bearer(r)
	if !ok || !o.signer.Verify(token, KindBootstrap) {
		return false
	}

	// From here the credential is authentic, so every remaining outcome is
	// ours to answer -- never the cover site's.
	if hasCookies(r) {
		o.notFound(w)

		return true
	}

	// A creation body is one HELLO frame and nothing else, so it is read under
	// a cap far below any general body limit.
	body, err := io.ReadAll(io.LimitReader(r.Body, frame.MaxSessionCreateBody+1))
	if err != nil || len(body) > frame.MaxSessionCreateBody {
		o.notFound(w)

		return true
	}

	if err := frame.DecodeHello(body); err != nil {
		o.notFound(w)

		return true
	}

	session, outcome := o.store.createSession(token, body, func() (string, error) {
		return o.signer.Mint(KindSession)
	})

	switch outcome {
	case admitted:
		header := w.Header()
		header.Set("X-Session-Token", session)
		header.Set("X-Down-Cursor", "0")
		header.Set("X-Carrier-Mode", page.CarrierMode)
		header.Set("Content-Type", "application/octet-stream")
		header.Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusOK)

		if _, err := w.Write(o.welcome); err != nil {
			o.logError("cannot write WELCOME", err)
		}

	case atCapacity:
		// The bootstrap is deliberately still unspent, so the byte-identical
		// request is safe to repeat. The bridge retries under a budget rather
		// than a fixed count.
		w.Header().Set("Retry-After", "1")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusServiceUnavailable)

	default: // refused
		o.notFound(w)
	}

	return true
}

func (o *Origin) serveSessionDelete(w http.ResponseWriter, r *http.Request) bool {
	token, ok := bearer(r)
	if !ok || !o.signer.Verify(token, KindSession) {
		return false
	}

	if hasCookies(r) {
		o.notFound(w)

		return true
	}

	if !o.store.remove(token) {
		// Authentic, but naming no session this relay holds. Idempotent applies
		// to a session that exists; this one does not, and telling a prober
		// apart from a client here costs nothing.
		o.notFound(w)

		return true
	}

	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)

	return true
}

func (o *Origin) serveWebSocket(w http.ResponseWriter, r *http.Request) bool {
	offered := r.Header.Get("Sec-Websocket-Protocol")

	token, ok := strings.CutPrefix(offered, subprotocolPrefix)
	if !ok || !o.signer.Verify(token, KindSession) {
		return false
	}

	// Cookies are NOT refused here, and that asymmetry is deliberate: a
	// browser's WebSocket constructor cannot be told to omit cookies the site
	// may have set, so refusing them would break the carrier on any hostname
	// that ever set one.
	if !ws.IsUpgrade(r) {
		o.notFound(w)

		return true
	}

	client := o.resolveClient(r)
	if client == nil {
		o.notFound(w)

		return true
	}

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	profile, ok := o.store.attach(token, cancel)
	if !ok {
		// Either the session is gone, or a second socket is trying to join one
		// that already has a carrier. The frame stream has one ordering and two
		// sockets feeding it have none.
		o.notFound(w)

		return true
	}

	defer o.store.detach(token)

	conn, err := ws.Upgrade(w, r, ws.Options{
		Subprotocol: offered,
		MaxMessage:  int(o.limits.EffectiveBatchBytes()),
	})
	if err != nil {
		o.notFound(w)

		return true
	}

	carrier := newSession(conn, SessionOptions{
		Backend:     o.backend,
		Limits:      o.limits,
		Global:      o.global,
		Logger:      o.log,
		ClientAddr:  client,
		MaxStreams:  o.maxStreams,
		DialTimeout: o.dialTimeout,
	})

	o.logSession(profile, client)

	if err := carrier.Serve(ctx); err != nil && !errors.Is(err, ws.ErrClosed) {
		o.logError("web relay session ended", err)
	}

	return true
}

// resolveClient is the browser's address as this process learned it. There is
// no fallback to the socket's own peer: behind a front proxy that would be
// loopback for every user in the world, and stamping that into the backend
// header would quietly turn off the blocklist, the per-IP limits and every log
// that names a user.
func (o *Origin) resolveClient(r *http.Request) net.Addr {
	if o.clientIP != nil {
		return o.clientIP(r)
	}

	addr, err := net.ResolveTCPAddr("tcp", r.RemoteAddr)
	if err != nil {
		return nil
	}

	return addr
}

// notFound is the tier-two answer: local, uncacheable, and carrying nothing.
func (o *Origin) notFound(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusNotFound)
	_, _ = io.WriteString(w, "404 page not found\n")
}

// recognises reports whether any authentic credential appears anywhere in the
// request's metadata -- any query value, any header value, under any name, in
// any spelling this relay could have minted.
//
// It is deliberately wider than the exact matches above. The question it answers
// is not "may this request proceed" but "would forwarding this request tell
// somebody else a secret", and the second question has to be asked about places
// the first one never looks: a capability in a header, a session token in a
// query, a padded spelling, a duplicated field.
//
// Bodies and trailers are never consumed, so classification cannot depend on
// reading something the cover site still needs.
func (o *Origin) recognises(r *http.Request) bool {
	found := false
	atoms := 0

	visit := func(value string) {
		for _, atom := range credentialAtoms(value) {
			if atoms++; atoms > maxCredentialAtoms {
				return
			}

			// Both tests, never short-circuited on the first: a request should
			// not be classifiable by how long the classification took.
			authentic := o.registry.IsAuthentic(atom) || o.signer.IsAuthentic(atom)
			found = found || authentic
		}
	}

	// RawQuery rather than r.URL.Query(): the standard decoder turns "+" into a
	// space, and a "+" is in the standard base64 alphabet, so a padded-standard
	// spelling of a real capability would arrive here already mangled.
	for _, pair := range strings.FieldsFunc(r.URL.RawQuery, func(r rune) bool { return r == '&' || r == ';' }) {
		_, value, _ := strings.Cut(pair, "=")

		if decoded, err := url.PathUnescape(value); err == nil {
			visit(decoded)
		} else {
			visit(value)
		}
	}

	if decoded, err := url.PathUnescape(r.URL.Path); err == nil {
		visit(decoded)
	}

	for _, values := range r.Header {
		for _, value := range values {
			visit(value)
		}
	}

	return found
}

// credentialAtoms splits a value into the substrings that could be a 32-byte
// credential in any base64 spelling. Splitting on the characters that appear in
// none of those alphabets is what pulls the token out of "Bearer X" and
// "tproxy-v1.X" without knowing either shape.
func credentialAtoms(value string) []string {
	atoms := strings.FieldsFunc(value, func(r rune) bool {
		switch {
		case r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			return false
		case r == '-', r == '_', r == '+', r == '/', r == '=':
			return false
		default:
			return true
		}
	})

	kept := atoms[:0]

	for _, atom := range atoms {
		// 43 unpadded, 44 padded. Anything else cannot decode to 32 bytes, and
		// checking the length first keeps this scan cheap on ordinary traffic.
		if len(atom) == CapabilityLength || len(atom) == CapabilityLength+1 {
			kept = append(kept, atom)
		}
	}

	return kept
}

// bearer extracts an Authorization: Bearer value, requiring exactly one header
// field. Two fields are not a credential, they are an attempt to have one read
// twice differently.
func bearer(r *http.Request) (string, bool) {
	values := r.Header.Values("Authorization")
	if len(values) != 1 {
		return "", false
	}

	token, ok := strings.CutPrefix(values[0], "Bearer ")
	if !ok {
		return "", false
	}

	return strings.TrimSpace(token), true
}

// hasCookies reports whether the request carries any cookie. The HTTP API
// refuses them: the bridge sends credentials:'omit', so a cookie on one of its
// requests means something other than the bridge made it.
func hasCookies(r *http.Request) bool {
	return len(r.Header.Values("Cookie")) > 0
}

func (o *Origin) logError(message string, err error) {
	if o.log != nil {
		o.log.WarningError(message, err)
	}
}

func (o *Origin) logSession(profile int, client net.Addr) {
	if o.log != nil {
		o.log.BindInt("profile", profile).
			BindStr("client", client.String()).
			Debug("web relay carrier attached")
	}
}
