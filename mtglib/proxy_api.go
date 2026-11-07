package mtglib

import (
	"context"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"slices"
	"time"
)

// SecretInfo is the JSON representation of a single named secret returned by
// GET /secrets. AdTag is the per-secret override (empty when none) and
// EffectiveAdTag is the tag actually applied after global fallback. The quota
// and expiry fields describe the secret's governance limits (omitted when
// unset), and QuotaUsed/QuotaRemaining report live usage.
type SecretInfo struct {
	Name           string `json:"name"`
	Secret         string `json:"secret"`
	Host           string `json:"host"`
	AdTag          string `json:"ad_tag,omitempty"`
	EffectiveAdTag string `json:"effective_ad_tag,omitempty"`

	Quota          int64      `json:"quota,omitempty"`
	QuotaUsed      int64      `json:"quota_used,omitempty"`
	QuotaRemaining *int64     `json:"quota_remaining,omitempty"`
	QuotaReset     string     `json:"quota_reset,omitempty"`
	ExpiresAt      *time.Time `json:"expires_at,omitempty"`
	Disabled       bool       `json:"disabled,omitempty"`

	// SpeedLimit is the user's cap in bytes per second, upload and download
	// combined across every connection, or absent for unlimited. It is set
	// with a human spelling ("5mbit", "1MB/s") and read back as a number, the
	// same way quota is.
	SpeedLimit int64 `json:"speed_limit,omitempty"`

	// SpeedLimitUp and SpeedLimitDown are the per-direction caps, from the
	// client's side, in the same unit; absent for unlimited.
	SpeedLimitUp   int64 `json:"speed_limit_up,omitempty"`
	SpeedLimitDown int64 `json:"speed_limit_down,omitempty"`

	// IPLimit is how many distinct addresses the user may be at once, or
	// absent for unlimited; ActiveIPs is how many they count as being at
	// right now. Neither is an address, so neither is gated.
	IPLimit   int `json:"ip_limit,omitempty"`
	ActiveIPs int `json:"active_ips,omitempty"`

	// ClientConns is how many live connections one address may hold to this
	// secret at once, or absent for unlimited. A limit, not an address.
	ClientConns int `json:"client_conns,omitempty"`

	// ClientSpeedLimit is the per-address ceiling in bytes per second, set as
	// client_speed with a human spelling and read back as a number, the way
	// speed is read back as speed_limit; absent for unlimited.
	ClientSpeedLimit int64 `json:"client_speed_limit,omitempty"`

	// ClientFair is whether the secret's speed limits are divided among its
	// addresses, client_fair; absent when they are not. A switch, not an
	// address.
	ClientFair bool `json:"client_fair,omitempty"`

	// Mode is the wire form this secret serialises to: "ee", "dd" or "plain".
	Mode string `json:"mode"`

	// Unserved is true when no configured listener can serve this secret's form:
	// a dd or plain secret on a proxy with no [[listener]]. The secret is stored
	// and valid, it just has no door. It is NOT an error -- one odd client must
	// never take an inbound offline -- but it is the thing an operator needs to
	// see.
	Unserved bool `json:"unserved,omitempty"`

	// Connections and LastSeen are the runtime view of this secret, carried
	// here so a caller rendering one user does not have to fetch and filter the
	// whole of GET /stats to learn whether anybody is on it. They are the same
	// numbers /stats reports, read from the same counters.
	Connections int64      `json:"connections"`
	LastSeen    *time.Time `json:"last_seen"`

	// ConnectedIPs and LastIP mirror the same fields on GET /stats, and are
	// filled in on exactly the same condition: only when the proxy is
	// configured with track-client-ips. See ProxyOpts.TrackClientIPs for why
	// that is off by default.
	//
	// Connections and LastSeen above are NOT gated, because they are not
	// addresses -- knowing that a user has two connections says nothing about
	// where they are.
	ConnectedIPs []string `json:"connected_ips,omitempty"`
	LastIP       string   `json:"last_ip,omitempty"`

	// ConnectedIPsLastSeen is when each connected address last moved a byte,
	// gated as ConnectedIPs is.
	ConnectedIPsLastSeen map[string]time.Time `json:"connected_ips_last_seen,omitempty"`

	// ExternalIPs and ExternalExpiresAt are the addresses a panel reported
	// this user present at elsewhere and when that report lapses, gated
	// exactly as ConnectedIPs is.
	ExternalIPs       []string   `json:"external_ips,omitempty"`
	ExternalExpiresAt *time.Time `json:"external_expires_at,omitempty"`

	// RetiringKeys, RetiringUntil, RetiringConnections and RetiringLastSeen mirror
	// the same four fields on GET /stats, read from the same set and the same
	// counters, and absent for a secret with no unexpired previous key. A count,
	// two times and a count: none is an address, so none is gated, and none is
	// ever a key.
	RetiringKeys        int        `json:"retiring_keys,omitempty"`
	RetiringUntil       *time.Time `json:"retiring_until,omitempty"`
	RetiringConnections int        `json:"retiring_connections,omitempty"`
	RetiringLastSeen    *time.Time `json:"retiring_last_seen,omitempty"`
}

// SnapshotSecrets returns the active secret set as a name-sorted list, exposing
// the secret material and both per-secret and effective advertising tags. It
// reads the atomic snapshot lock-free.
func (p *Proxy) SnapshotSecrets() []SecretInfo {
	set := p.secrets.Load()
	out := make([]SecretInfo, len(set.names))

	// The same containment test NewProxy uses for its startup warning, so
	// /secrets and the log can never disagree: served means every transport a
	// client of this form might pick is honoured, not merely that some
	// obfuscated listener exists.
	listenerTags := p.listenerModes.Tags()

	// One snapshot for the whole list rather than one per secret: the registry
	// is walked under a mutex that every connect and disconnect also takes, and
	// taking it once per user would put a stats read on that path N times for
	// one request. The addresses inside are already gated on tracking; the
	// counts are not, and a lookup of a user with no ledger is the zero
	// report, so nothing below needs a second branch.
	addresses := p.addressReports()

	// The overlap of every name that still accepts a previous key, read once for
	// the whole list and only when the set holds a retiring entry: the registry
	// is walked under liveMu, as for the addresses above, and the rotation
	// clock's high-water mark is not moved by a read that has nothing to judge.
	var overlaps map[string]retiringView
	if len(set.retiring) > 0 {
		overlaps = p.retiringViews(set, p.rotation.Now())
	}

	for i, name := range set.names {
		secret := set.secrets[i]
		info := SecretInfo{
			Name:     name,
			Secret:   secret.Base64(),
			Host:     secret.Host,
			Mode:     secret.Mode.String(),
			Unserved: !secret.Hosted() && !listenerTags.Covers(ModeSetOf(secret.Mode).Tags()),
		}

		if set.adTags[i] != nil {
			info.AdTag = hex.EncodeToString(set.adTags[i][:])
		}

		if eff := set.effectiveAdTag(i); eff != nil {
			info.EffectiveAdTag = hex.EncodeToString(eff[:])
		}

		fillLimitInfo(&info, set.limits[i], p.stats.quotaUsedValue(name))
		p.stats.fillRuntimeInfo(&info, name)

		report := addresses[name]
		info.ActiveIPs = report.ActiveIPs
		info.ConnectedIPs = report.ConnectedIPs
		info.ConnectedIPsLastSeen = report.ConnectedIPsLastSeen
		info.ExternalIPs = report.ExternalIPs
		info.ExternalExpiresAt = report.ExternalExpiresAt

		if view, ok := overlaps[name]; ok {
			info.RetiringKeys, info.RetiringConnections = view.keys, view.connections
			info.RetiringUntil, info.RetiringLastSeen = view.times()
		}

		out[i] = info
	}

	return out
}

// fillLimitInfo copies a secret's governance limits and live usage into a
// SecretInfo for the GET /secrets response.
func fillLimitInfo(info *SecretInfo, lim SecretLimits, used int64) {
	if lim.QuotaBytes > 0 {
		info.Quota = lim.QuotaBytes
		info.QuotaUsed = used

		remaining := lim.QuotaBytes - used
		if remaining < 0 {
			remaining = 0
		}

		info.QuotaRemaining = &remaining
	}

	if lim.QuotaReset != QuotaResetNone {
		info.QuotaReset = lim.QuotaReset.String()
	}

	if !lim.ExpiresAt.IsZero() {
		expires := lim.ExpiresAt
		info.ExpiresAt = &expires
	}

	info.Disabled = lim.Disabled
	info.SpeedLimit = lim.SpeedBytesPerSecond
	info.SpeedLimitUp = lim.SpeedUpBytesPerSecond
	info.SpeedLimitDown = lim.SpeedDownBytesPerSecond
	info.IPLimit = lim.IPLimit
	info.ClientConns = lim.ClientConns
	info.ClientSpeedLimit = lim.ClientSpeedBytesPerSecond
	info.ClientFair = lim.ClientFair
}

// ReplaceSecrets swaps the entire secret configuration (secrets + advertising
// tags) for cfg, going through the same validation, atomic swap and stale
// connection close as a file reload.
//
// cfg.Retiring is the COMPLETE list of retiring keys the new set holds, and nil
// is none, as for a reload: a ReplaceSecrets that leaves it nil ends every
// overlap in force, and closes the streams on the keys that were retiring. A
// config file that still grants an overlap grants it again at the next reload,
// until the entry's own until. The management API's PUT /secrets is the one
// caller that keeps the overlaps of the names it keeps, through its own step
// (replaceSecretsKeepingRetiring), not through this method.
func (p *Proxy) ReplaceSecrets(cfg SecretConfig) error {
	p.reloadMu.Lock()
	defer p.reloadMu.Unlock()

	return p.swapSecretConfigLocked(cfg)
}

// replaceSecretsKeepingRetiring is the PUT /secrets handler's replacement of the
// whole set: ReplaceSecrets, except that the retiring entries of every name cfg
// keeps stay, and those of every name it removes go with it. It is the handler's
// alone and not a second meaning of a nil cfg.Retiring, which is none wherever a
// SecretConfig is consumed.
//
// The API cannot express an overlap (there is no write field, D18), so a PUT
// built from a request body can only be silent about one. Reading that as "none"
// would make a rotation-unaware client -- the panel, today -- end every overlap
// the config file granted as a side effect, and the next restart would grant it
// again: a kill and then a revival nobody asked for. Reading it as "keep" is
// right, and the keeping is done here, under reloadMu, against the set as it is
// then: a reload or an API call that ran after the body was read has changed the
// entries, and a copy taken earlier would put back an entry that one of them had
// removed, with its until still ahead. cfg.Retiring is overwritten, not added to.
//
// An entry whose until has passed is kept like any other and then dropped by the
// build, which judges it by the rotation clock (rule 2), so the merge reads no
// clock of its own. A name whose primary the PUT changes keeps its entries all
// the same, and its old primary does not become one: the re-key is immediate. An
// entry that repeats a key the PUT now makes a primary is dropped by the build
// (rules 5 and 6), as in any swap.
func (p *Proxy) replaceSecretsKeepingRetiring(cfg SecretConfig) error {
	beforeKeepMergeLockHook()

	p.reloadMu.Lock()
	defer p.reloadMu.Unlock()

	// The set's own entries, read in place and in its order: toConfig would
	// build every name's maps, under the lock, for this one list (final review
	// A, n1).
	set := p.secrets.Load()

	var kept []RetiringSecret

	for _, entry := range set.retiring {
		name := set.names[entry.nameIdx]
		if _, ok := cfg.Secrets[name]; ok {
			kept = append(kept, RetiringSecret{Name: name, Secret: entry.secret, Until: entry.until})
		}
	}

	cfg.Retiring = kept

	return p.swapSecretConfigLocked(cfg)
}

// beforeKeepMergeLockHook runs in replaceSecretsKeepingRetiring before it takes
// reloadMu: the window in which a reload or another API call can change the
// entries the merge is about to read. A no-op in production. A test uses it to
// run a reload that removes an entry whose until is still ahead; an expiry sweep
// there would prove nothing, because the build drops an expired entry whatever
// the merge handed it. A variable so it can be replaced; a test that does must
// restore it and must not run in parallel.
var beforeKeepMergeLockHook = func() {}

// PutSecret adds or updates a single secret, optionally setting its per-secret
// advertising tag (nil clears the override) and governance limits (nil or a
// zero value clears them). Only a key change closes that secret's live
// connections; an adtag-only change leaves them running because closeStaleConns
// keys on the secret key, not the tag. A disable/expiry set here takes effect
// immediately because swapSecretConfigLocked also closes newly-denied streams.
// The name's retiring entries are kept, and the old primary never becomes one.
// The primary wins: a key that repeats one of the name's own entries makes that
// entry go (rule 6), and a key that is another name's retiring key makes that
// other name's entry go (rule 5), the key being this name's primary.
func (p *Proxy) PutSecret(name string, s Secret, adTag *[AdTagLength]byte, limits *SecretLimits) error {
	if name == "" {
		return fmt.Errorf("%w: empty name", ErrSecretInvalid)
	}

	if !s.Valid() {
		return ErrSecretInvalid
	}

	p.reloadMu.Lock()
	defer p.reloadMu.Unlock()

	cfg := p.secrets.Load().toConfig()
	cfg.Secrets[name] = s

	if adTag != nil {
		if cfg.SecretAdTags == nil {
			cfg.SecretAdTags = make(map[string][AdTagLength]byte)
		}

		cfg.SecretAdTags[name] = *adTag
	} else {
		delete(cfg.SecretAdTags, name)
	}

	if limits != nil && !limits.IsZero() {
		if cfg.Limits == nil {
			cfg.Limits = make(map[string]SecretLimits)
		}

		cfg.Limits[name] = *limits
	} else {
		delete(cfg.Limits, name)
	}

	return p.swapSecretConfigLocked(cfg)
}

// DeleteSecret removes a single secret, its advertising override and its
// limits. It returns ErrSecretNotFound for an unknown name and ErrLastSecret if
// the removal would empty the set. The removed secret's live connections are
// closed, and its retiring entries go with it (forget), whatever their until.
func (p *Proxy) DeleteSecret(name string) error {
	p.reloadMu.Lock()
	defer p.reloadMu.Unlock()

	cfg := p.secrets.Load().toConfig()

	if _, ok := cfg.Secrets[name]; !ok {
		return ErrSecretNotFound
	}

	if len(cfg.Secrets) == 1 {
		return ErrLastSecret
	}

	cfg.forget(name)

	return p.swapSecretConfigLocked(cfg)
}

// forget removes everything cfg files under name: the secret, its advertising
// override, its limits and its retiring entries. A set is built from the names
// in Secrets alone, so an override or limits left behind would never be read,
// and a retiring entry left behind would be dropped as dangling; they go all
// the same, so that the config handed to the swap says what the set will hold.
// Deleting from a nil map does nothing, so a config with no overrides or no
// limits needs no check. Retiring is rebuilt rather than filtered in place, so
// a slice the caller handed in is never rewritten under it, and it is nil when
// no entry is left, which is what none means.
func (c *SecretConfig) forget(name string) {
	delete(c.Secrets, name)
	delete(c.SecretAdTags, name)
	delete(c.Limits, name)

	var retiring []RetiringSecret

	for _, entry := range c.Retiring {
		if entry.Name != name {
			retiring = append(retiring, entry)
		}
	}

	c.Retiring = retiring
}

// GlobalAdTag returns the currently active global advertising tag, or nil when
// none is set.
func (p *Proxy) GlobalAdTag() *[AdTagLength]byte {
	return p.secrets.Load().globalAdTag
}

// SetGlobalAdTag sets (or, with nil, clears) the global advertising tag. It does
// not close any live connection: the tag only affects how new connections are
// routed.
func (p *Proxy) SetGlobalAdTag(tag *[AdTagLength]byte) error {
	p.reloadMu.Lock()
	defer p.reloadMu.Unlock()

	cfg := p.secrets.Load().toConfig()
	cfg.GlobalAdTag = tag

	return p.swapSecretConfigLocked(cfg)
}

// apiListener is the socket the management API serves on: the one the caller
// supplied, or one bound now under the proxy's own context. A nil listener
// with a nil error means no API was asked for.
//
// Bound under ctx rather than context.Background because the socket belongs to
// this proxy and to nothing else. A context already cancelled by the time the
// proxy is built is a proxy that is already stopping, and not starting its API
// is the right outcome -- reported, since the caller asked for one.
func apiListener(ctx context.Context, opts ProxyOpts) (net.Listener, error) {
	if opts.APIListener != nil {
		return opts.APIListener, nil
	}

	if opts.APIBindTo == "" {
		return nil, nil //nolint: nilnil // no API is not an error
	}

	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", opts.APIBindTo)
	if err != nil {
		return nil, fmt.Errorf("cannot bind %s: %w", opts.APIBindTo, err)
	}

	return ln, nil
}

// startAPIServer serves the management HTTP API on ln in background goroutines
// and shuts it down when ctx is cancelled. It supersedes ProxyStats.StartServer:
// the mux is built with access to the whole proxy so it can serve the secrets
// and adtag routes in addition to /stats and /reload.
//
// The server is part of the proxy's lifetime in both directions: it starts
// with it, and Shutdown waits for it to finish shutting down, so the socket is
// released by the time Shutdown returns. Without that wait a restart on the
// same address could race a server still winding down and lose.
func (p *Proxy) startAPIServer(ctx context.Context, ln net.Listener, token string) {
	srv := newAPIServer(ln.Addr().String(), p.buildAPIHandler(token))

	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			p.logger.WarningError("management API server error", err)
		}
	}()

	p.apiWaitGroup.Add(1)

	// G118: this goroutine's whole job starts when ctx is already cancelled, so
	// the request-scoped context it is told to use is exactly the one that must
	// not be used here.
	go func() { //nolint:gosec // the deadline is deliberately independent of ctx
		defer p.apiWaitGroup.Done()

		<-ctx.Done()

		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second) //nolint: mnd
		defer cancel()

		// contextcheck wants shutdownCtx derived from ctx. It must not be:
		// ctx is already cancelled by the time this line runs, so an
		// inherited context would abort the graceful shutdown instantly and
		// cut every in-flight API response.
		srv.Shutdown(shutdownCtx) //nolint: errcheck,contextcheck
	}()

	authState := "unauthenticated"
	if token != "" {
		authState = "bearer-token"
	}

	p.logger.BindStr("bind", ln.Addr().String()).BindStr("auth", authState).Info("Management API server started")
}

// Deadlines for the management API. Without them a client that opens a
// connection and dribbles header bytes holds a goroutine and a socket forever.
const (
	// Headers are a few hundred bytes and arrive in the first packet even on a
	// bad link, so 5s only ever hits a client that is not really sending.
	apiReadHeaderTimeout = 5 * time.Second
	// Bounds the request body too (PUT /secrets is the largest, still small).
	apiReadTimeout = 30 * time.Second
	// Must outlast the slowest handler: a /reload config re-read and secret swap,
	// or a big /stats drained by a loaded panel. Both are far under a minute.
	apiWriteTimeout = 60 * time.Second
	// Keep-alive idle between panel polls; the panel scrapes far more often.
	apiIdleTimeout = 120 * time.Second
)

// newAPIServer builds the management API HTTP server with the deadlines above.
func newAPIServer(bindTo string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              bindTo,
		Handler:           handler,
		ReadHeaderTimeout: apiReadHeaderTimeout,
		ReadTimeout:       apiReadTimeout,
		WriteTimeout:      apiWriteTimeout,
		IdleTimeout:       apiIdleTimeout,
	}
}

// buildAPIHandler wires every management route and wraps the mux in the bearer
// token middleware. When p has no file reloader, /reload keeps reporting the
// capability as unavailable (503).
func (p *Proxy) buildAPIHandler(token string) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /stats", p.handleStats)

	var reload func() error
	if p.reloader != nil {
		reload = p.ReloadSecrets
	}

	mux.HandleFunc("/reload", reloadHandler(reload, p.logger))

	mux.HandleFunc("GET /secrets", p.handleGetSecrets)
	mux.HandleFunc("PUT /secrets", p.handlePutSecrets)
	mux.HandleFunc("POST /secrets", p.handlePostSecret)
	mux.HandleFunc("GET /secrets/{name}", p.handleGetSecret)
	mux.HandleFunc("DELETE /secrets/{name}", p.handleDeleteSecret)
	mux.HandleFunc("POST /secrets/{name}/reset-quota", p.handleResetQuota)
	mux.HandleFunc("POST /secrets/{name}/kick", p.handleKick)
	mux.HandleFunc("GET /secrets/{name}/clients", p.handleGetClients)
	mux.HandleFunc("POST /secrets/{name}/bans", p.handleBan)
	mux.HandleFunc("GET /secrets/{name}/bans", p.handleGetBans)
	mux.HandleFunc("DELETE /secrets/{name}/bans/{address...}", p.handleUnban)
	mux.HandleFunc("GET /secrets/{name}/external-ips", p.handleGetExternalIPs)
	mux.HandleFunc("PUT /secrets/{name}/external-ips", p.handlePutExternalIPs)
	mux.HandleFunc("DELETE /secrets/{name}/external-ips", p.handleDeleteExternalIPs)

	mux.HandleFunc("GET /adtag", p.handleGetAdTag)
	mux.HandleFunc("PUT /adtag", p.handlePutAdTag)
	mux.HandleFunc("DELETE /adtag", p.handleDeleteAdTag)

	return withAuth(token, mux)
}

// withAuth guards next with an optional bearer token. An empty token is a
// pass-through, preserving the previous no-auth, localhost-bind behavior. The
// comparison is constant-time to avoid leaking the token through timing.
func withAuth(token string, next http.Handler) http.Handler {
	if token == "" {
		return next
	}

	expected := []byte("Bearer " + token)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := []byte(r.Header.Get("Authorization"))

		if subtle.ConstantTimeCompare(got, expected) != 1 {
			w.Header().Set("WWW-Authenticate", "Bearer")
			http.Error(w, "unauthorized", http.StatusUnauthorized)

			return
		}

		next.ServeHTTP(w, r)
	})
}

func (p *Proxy) handleGetSecrets(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"secrets": p.SnapshotSecrets()})
}

// handleStats serves GET /stats, enriching the base runtime counters with each
// secret's configured governance limits (quota ceiling, reset policy, expiry,
// disabled) taken from the active secret snapshot.
func (p *Proxy) handleStats(w http.ResponseWriter, _ *http.Request) {
	resp := p.stats.buildResponse()

	// The listener report and the obfuscated2 counters live on Proxy, not on
	// ProxyStats, so they are overlaid here. Cloned for the same reason Features
	// is: a caller must not be able to mutate the shared slice through a
	// response. The inner Accept has to be cloned too -- a slices.Clone alone
	// leaves it aliased to the proxy's own report. A nil clone stays nil and the
	// field stays omitted.
	resp.Listeners = slices.Clone(p.listeners)
	for i := range resp.Listeners {
		resp.Listeners[i].Accept = slices.Clone(resp.Listeners[i].Accept)
	}

	// Only a configured [[listener]] can make these counters mean anything, and
	// their absence is what keeps an untouched deployment's /stats identical.
	if !p.listenerModes.Empty() {
		resp.Obfuscated = obfuscatedJSONOf(&p.obfsStats)
	}

	// The FakeTLS door's counters are a top-level object of their own, never
	// something under Users: nothing about the door is a client, and the panel
	// bills every key under Users as one. Omitted until the door has counted
	// something, which is what keeps a proxy nobody has connected to reporting
	// the response it always did.
	if fake := fakeTLSJSONOf(&p.fakeStats, p.scanBudget); fake.counted() {
		resp.FakeTLSHandshake = fake
	}

	// Keyed on resp.Users rather than on the secret snapshot, deliberately: a
	// secret removed through DELETE /secrets keeps its counter bucket (nothing
	// ever deletes one), so it is still reported, and its connections are still
	// live until they are swept. The loop below is keyed on the snapshot
	// instead, because a limit only exists for a secret that still does.
	for name, report := range p.addressReports() {
		user, ok := resp.Users[name]
		if !ok {
			continue
		}

		user.ActiveIPs = report.ActiveIPs
		user.ConnectedIPs = report.ConnectedIPs
		user.ConnectedIPsLastSeen = report.ConnectedIPsLastSeen
		user.ExternalIPs = report.ExternalIPs
		user.ExternalExpiresAt = report.ExternalExpiresAt
		resp.Users[name] = user
	}

	// The per-address table's counts are scalars inside the user object, and
	// the overlay only ever fills a user that is already there: a name the table
	// holds and the counters do not is skipped, never added, because every key
	// under Users is billed as a client. A count is not an address, so neither
	// is gated on track-client-ips. The table's lock is taken alone, after
	// liveMu was let go above.
	for name, counts := range p.clients.counts() {
		user, ok := resp.Users[name]
		if !ok {
			continue
		}

		user.Clients = counts.clients
		user.ClientsOverflow = counts.overflow
		resp.Users[name] = user
	}

	set := p.secrets.Load()

	// The overlap of every name that still accepts a previous key: four scalars
	// inside a user object that is already there, for the same reason as the
	// counts above -- every key under Users is billed as a client, and a name is
	// not one for having an overlap. The clock is read only when the set holds a
	// retiring entry, and once for the whole response; a set that holds none costs
	// this length check.
	var overlaps map[string]retiringView
	if len(set.retiring) > 0 {
		overlaps = p.retiringViews(set, p.rotation.Now())
	}

	for i, name := range set.names {
		user, ok := resp.Users[name]
		if !ok {
			continue
		}

		lim := set.limits[i]

		if view, ok := overlaps[name]; ok {
			user.RetiringKeys, user.RetiringConnections = view.keys, view.connections
			user.RetiringUntil, user.RetiringLastSeen = view.times()
		}

		if lim.QuotaBytes > 0 {
			user.Quota = lim.QuotaBytes

			remaining := lim.QuotaBytes - user.QuotaUsed
			if remaining < 0 {
				remaining = 0
			}

			user.QuotaRemaining = &remaining
		}

		if lim.QuotaReset != QuotaResetNone {
			user.QuotaReset = lim.QuotaReset.String()
		}

		if !lim.ExpiresAt.IsZero() {
			expires := lim.ExpiresAt
			user.ExpiresAt = &expires
		}

		user.Disabled = lim.Disabled
		user.SpeedLimit = lim.SpeedBytesPerSecond
		user.SpeedLimitUp = lim.SpeedUpBytesPerSecond
		user.SpeedLimitDown = lim.SpeedDownBytesPerSecond
		user.IPLimit = lim.IPLimit
		user.ClientConns = lim.ClientConns
		user.ClientSpeedLimit = lim.ClientSpeedBytesPerSecond
		user.ClientFair = lim.ClientFair

		resp.Users[name] = user
	}

	writeJSON(w, http.StatusOK, resp)
}

// addressReportFor is the GET /secrets/{name}/external-ips body: the user's
// address view with the configured limit filled in. False for an unknown
// secret.
func (p *Proxy) addressReportFor(name string) (AddressReport, bool) {
	set := p.secrets.Load()

	var (
		limit int
		found bool
	)

	for i, n := range set.names {
		if n == name {
			limit, found = set.limits[i].IPLimit, true

			break
		}
	}

	if !found {
		return AddressReport{}, false
	}

	report, ok := p.addressReports()[name]
	if !ok {
		report = AddressReport{Name: name}
	}

	report.IPLimit = limit

	return report, true
}

// handleGetExternalIPs serves GET /secrets/{name}/external-ips.
func (p *Proxy) handleGetExternalIPs(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")

	report, ok := p.addressReportFor(name)
	if !ok {
		httpError(w, http.StatusNotFound, fmt.Errorf("%w: %q", ErrSecretNotFound, name))

		return
	}

	writeJSON(w, http.StatusOK, report)
}

// externalIPsRequest is the PUT /secrets/{name}/external-ips body: the
// addresses the user currently holds on other systems, and for how long this
// report should count. A panel sends it as a heartbeat, well inside the ttl.
type externalIPsRequest struct {
	IPs []string `json:"ips"`
	TTL string   `json:"ttl,omitempty"`
}

// handlePutExternalIPs serves PUT /secrets/{name}/external-ips. It replaces
// the user's reported set and answers with the merged view, so the panel
// sees what the proxy will enforce.
func (p *Proxy) handlePutExternalIPs(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")

	var req externalIPsRequest
	if !decodeJSON(w, r, &req) {
		return
	}

	addrs, ttl, err := ParseExternalAddresses(req.IPs, req.TTL)
	if err != nil {
		httpError(w, http.StatusBadRequest, err)

		return
	}

	if err := p.SetExternalAddresses(name, addrs, ttl); err != nil {
		httpError(w, secretMutationStatus(err), err)

		return
	}

	report, _ := p.addressReportFor(name)
	writeJSON(w, http.StatusOK, report)
}

// handleDeleteExternalIPs serves DELETE /secrets/{name}/external-ips.
func (p *Proxy) handleDeleteExternalIPs(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")

	if err := p.SetExternalAddresses(name, nil, DefaultExternalAddressTTL); err != nil {
		httpError(w, secretMutationStatus(err), err)

		return
	}

	writeJSON(w, http.StatusOK, statusOK)
}

// handleResetQuota serves POST /secrets/{name}/reset-quota, zeroing the secret's
// used-bytes counter and restarting its quota period. An unknown secret is 404.
func (p *Proxy) handleResetQuota(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")

	if !p.hasSecret(name) {
		httpError(w, http.StatusNotFound, ErrSecretNotFound)

		return
	}

	p.stats.ResetQuota(name)
	writeJSON(w, http.StatusOK, statusOK)
}

// hasSecret reports whether name is present in the active secret set.
func (p *Proxy) hasSecret(name string) bool {
	set := p.secrets.Load()

	for _, n := range set.names {
		if n == name {
			return true
		}
	}

	return false
}

// limitFields are the optional per-secret governance limits accepted by the
// secrets API. All fields are optional; omitting them (or sending zero values)
// clears the corresponding limit. Quota accepts human sizes ("10GB"), expires
// accepts RFC3339 or YYYY-MM-DD, quota_reset is "none" or "monthly", and speed
// accepts a rate ("5mbit", "1MB/s") -- the same spellings the config file
// takes, from the same parsers -- ip_limit is a count of addresses,
// client_conns a count of one address's live connections, client_speed one
// address's ceiling, spelled as speed is, and client_fair the switch that
// divides the secret's speed among its addresses.
type limitFields struct {
	Quota       string `json:"quota,omitempty"`
	QuotaReset  string `json:"quota_reset,omitempty"`
	Expires     string `json:"expires,omitempty"`
	Disabled    bool   `json:"disabled,omitempty"`
	Speed       string `json:"speed,omitempty"`
	SpeedUp     string `json:"speed_up,omitempty"`
	SpeedDown   string `json:"speed_down,omitempty"`
	IPLimit     int    `json:"ip_limit,omitempty"`
	ClientConns int    `json:"client_conns,omitempty"`
	ClientSpeed string `json:"client_speed,omitempty"`
	ClientFair  bool   `json:"client_fair,omitempty"`
}

// parse turns the raw string fields into a SecretLimits, returning an error for
// a malformed quota, reset policy, expiry, speed, ip limit, connection cap or
// per-address ceiling.
func (l limitFields) parse() (SecretLimits, error) {
	if l.IPLimit < 0 {
		return SecretLimits{}, fmt.Errorf("%w: ip_limit must not be negative (%d)", ErrSecretInvalid, l.IPLimit)
	}

	if l.ClientConns < 0 {
		return SecretLimits{}, fmt.Errorf("%w: client_conns must not be negative (%d)", ErrSecretInvalid, l.ClientConns)
	}

	quota, err := ParseQuotaBytes(l.Quota)
	if err != nil {
		return SecretLimits{}, err
	}

	reset, err := ParseQuotaReset(l.QuotaReset)
	if err != nil {
		return SecretLimits{}, err
	}

	expires, err := ParseExpiry(l.Expires)
	if err != nil {
		return SecretLimits{}, err
	}

	speed, err := ParseSpeed(l.Speed)
	if err != nil {
		return SecretLimits{}, err
	}

	speedUp, err := ParseSpeed(l.SpeedUp)
	if err != nil {
		return SecretLimits{}, fmt.Errorf("speed_up: %w", err)
	}

	speedDown, err := ParseSpeed(l.SpeedDown)
	if err != nil {
		return SecretLimits{}, fmt.Errorf("speed_down: %w", err)
	}

	clientSpeed, err := ParseSpeed(l.ClientSpeed)
	if err != nil {
		return SecretLimits{}, fmt.Errorf("client_speed: %w", err)
	}

	return SecretLimits{
		QuotaBytes:                quota,
		QuotaReset:                reset,
		ExpiresAt:                 expires,
		Disabled:                  l.Disabled,
		SpeedBytesPerSecond:       speed,
		SpeedUpBytesPerSecond:     speedUp,
		SpeedDownBytesPerSecond:   speedDown,
		IPLimit:                   l.IPLimit,
		ClientConns:               l.ClientConns,
		ClientSpeedBytesPerSecond: clientSpeed,
		ClientFair:                l.ClientFair,
	}, nil
}

// limits is parse, and then what no one field can say on its own: client_fair
// divides the secret's speed, so it needs speed, speed_up or speed_down in the
// same request. A POST replaces every limit of its secret and a PUT every
// secret, so a speed set before the request is gone by the time it applies.
// The per-address ceiling is not a speed fair share divides. Both handlers
// that take limits read them through here.
func (l limitFields) limits() (SecretLimits, error) {
	lim, err := l.parse()
	if err != nil {
		return SecretLimits{}, err
	}

	if lim.ClientFair && lim.fairTotals() == (fairTotals{}) {
		return SecretLimits{}, fmt.Errorf(
			"%w: client_fair divides the secret's speed and needs speed, speed_up or speed_down", ErrSecretInvalid)
	}

	return lim, nil
}

type secretEntry struct {
	Secret string `json:"secret"`
	AdTag  string `json:"ad_tag,omitempty"`
	limitFields
}

type putSecretsRequest struct {
	Secrets map[string]secretEntry `json:"secrets"`
	AdTag   string                 `json:"ad_tag,omitempty"`
}

func (p *Proxy) handlePutSecrets(w http.ResponseWriter, r *http.Request) {
	var req putSecretsRequest

	if !decodeJSON(w, r, &req) {
		return
	}

	cfg := SecretConfig{
		Secrets:      make(map[string]Secret, len(req.Secrets)),
		SecretAdTags: make(map[string][AdTagLength]byte),
	}

	for name, entry := range req.Secrets {
		secret, err := ParseSecret(entry.Secret)
		if err != nil {
			httpError(w, http.StatusBadRequest, fmt.Errorf("invalid secret %q: %w", name, err))

			return
		}

		cfg.Secrets[name] = secret

		tag, err := parseAdTagHex(entry.AdTag)
		if err != nil {
			httpError(w, http.StatusBadRequest, fmt.Errorf("invalid ad_tag for %q: %w", name, err))

			return
		}

		if tag != nil {
			cfg.SecretAdTags[name] = *tag
		}

		limits, err := entry.limits()
		if err != nil {
			httpError(w, http.StatusBadRequest, fmt.Errorf("invalid limits for %q: %w", name, err))

			return
		}

		if !limits.IsZero() {
			if cfg.Limits == nil {
				cfg.Limits = make(map[string]SecretLimits)
			}

			cfg.Limits[name] = limits
		}
	}

	global, err := parseAdTagHex(req.AdTag)
	if err != nil {
		httpError(w, http.StatusBadRequest, fmt.Errorf("invalid ad_tag: %w", err))

		return
	}

	cfg.GlobalAdTag = global

	// The body cannot say a retiring key, so it cannot end one: the entries of
	// the names it keeps stay.
	if err := p.replaceSecretsKeepingRetiring(cfg); err != nil {
		httpError(w, secretMutationStatus(err), err)

		return
	}

	writeJSON(w, http.StatusOK, statusOK)
}

type postSecretRequest struct {
	Name   string `json:"name"`
	Secret string `json:"secret"`
	AdTag  string `json:"ad_tag,omitempty"`
	limitFields
}

func (p *Proxy) handlePostSecret(w http.ResponseWriter, r *http.Request) {
	var req postSecretRequest

	if !decodeJSON(w, r, &req) {
		return
	}

	secret, err := ParseSecret(req.Secret)
	if err != nil {
		httpError(w, http.StatusBadRequest, fmt.Errorf("invalid secret: %w", err))

		return
	}

	tag, err := parseAdTagHex(req.AdTag)
	if err != nil {
		httpError(w, http.StatusBadRequest, fmt.Errorf("invalid ad_tag: %w", err))

		return
	}

	limits, err := req.limits()
	if err != nil {
		httpError(w, http.StatusBadRequest, fmt.Errorf("invalid limits: %w", err))

		return
	}

	if err := p.PutSecret(req.Name, secret, tag, &limits); err != nil {
		httpError(w, secretMutationStatus(err), err)

		return
	}

	writeJSON(w, http.StatusOK, statusOK)
}

// handleGetSecret serves GET /secrets/{name}: the one entry GET /secrets would
// list for that name, with the same live counters, or 404.
//
// It is the same snapshot the collection is built from, taken once, so the two
// cannot disagree about a user. It exists because a panel drawing one user's
// page was fetching the whole collection to pick one out -- and because a path
// that accepts DELETE and answers GET with 405 is the shape of an accident.
func (p *Proxy) handleGetSecret(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")

	for _, info := range p.SnapshotSecrets() {
		if info.Name == name {
			writeJSON(w, http.StatusOK, info)

			return
		}
	}

	httpError(w, http.StatusNotFound, fmt.Errorf("%w: %q", ErrSecretNotFound, name))
}

func (p *Proxy) handleDeleteSecret(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")

	if err := p.DeleteSecret(name); err != nil {
		httpError(w, secretMutationStatus(err), err)

		return
	}

	writeJSON(w, http.StatusOK, statusOK)
}

func (p *Proxy) handleGetAdTag(w http.ResponseWriter, _ *http.Request) {
	resp := map[string]any{"ad_tag": nil}

	if tag := p.GlobalAdTag(); tag != nil {
		resp["ad_tag"] = hex.EncodeToString(tag[:])
	}

	writeJSON(w, http.StatusOK, resp)
}

type putAdTagRequest struct {
	AdTag string `json:"ad_tag"`
}

func (p *Proxy) handlePutAdTag(w http.ResponseWriter, r *http.Request) {
	var req putAdTagRequest

	if !decodeJSON(w, r, &req) {
		return
	}

	tag, err := parseAdTagHex(req.AdTag)
	if err != nil {
		httpError(w, http.StatusBadRequest, err)

		return
	}

	if tag == nil {
		httpError(w, http.StatusBadRequest, errors.New("ad_tag is required; use DELETE /adtag to clear it"))

		return
	}

	if err := p.SetGlobalAdTag(tag); err != nil {
		httpError(w, secretMutationStatus(err), err)

		return
	}

	writeJSON(w, http.StatusOK, statusOK)
}

func (p *Proxy) handleDeleteAdTag(w http.ResponseWriter, _ *http.Request) {
	if err := p.SetGlobalAdTag(nil); err != nil {
		httpError(w, secretMutationStatus(err), err)

		return
	}

	writeJSON(w, http.StatusOK, statusOK)
}

var statusOK = map[string]string{"status": "ok"}

// secretMutationStatus maps a mutation error to an HTTP status: 404 for an
// unknown secret, 409 when a delete would empty the set or a ban would take the
// ban list past its bound, and 400 for every validation failure (invalid
// secret, invalid/oversized adtag, empty set).
func secretMutationStatus(err error) int {
	switch {
	case errors.Is(err, ErrSecretNotFound):
		return http.StatusNotFound
	case errors.Is(err, ErrLastSecret), errors.Is(err, ErrBanListFull):
		return http.StatusConflict
	default:
		return http.StatusBadRequest
	}
}

// parseAdTagHex decodes a hex advertising tag. An empty string yields (nil,
// nil) — meaning "no tag" — and any non-empty value must decode to exactly
// AdTagLength bytes.
func parseAdTagHex(s string) (*[AdTagLength]byte, error) {
	if s == "" {
		return nil, nil
	}

	decoded, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("ad_tag must be a hex string: %w", err)
	}

	if len(decoded) != AdTagLength {
		return nil, fmt.Errorf("ad_tag must be %d bytes (%d hex chars), got %d",
			AdTagLength, AdTagLength*2, len(decoded))
	}

	var out [AdTagLength]byte

	copy(out[:], decoded)

	return &out, nil
}

func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(dst); err != nil {
		httpError(w, http.StatusBadRequest, fmt.Errorf("invalid request body: %w", err))

		return false
	}

	return true
}

func writeJSON(w http.ResponseWriter, code int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(body) //nolint: errcheck,errchkjson
}

func httpError(w http.ResponseWriter, code int, err error) {
	writeJSON(w, code, map[string]string{"error": err.Error()})
}
