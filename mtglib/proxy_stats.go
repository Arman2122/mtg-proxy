package mtglib

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"os"
	"slices"
	"sync"
	"sync/atomic"
	"time"
)

// usageFlushInterval is how often persisted quota usage is written to disk.
const usageFlushInterval = 30 * time.Second

type secretStats struct {
	connections atomic.Int64
	bytesIn     atomic.Int64
	bytesOut    atomic.Int64
	lastSeen    atomic.Value // stores time.Time

	// quotaUsed counts bytes against the current quota period (client read +
	// write). It is incremented by countingConn, reset by a monthly rollover or
	// an explicit ResetQuota, and persisted across restarts. Unlike
	// bytesIn/bytesOut it is not a lifetime display counter.
	quotaUsed atomic.Int64

	// periodStart is the unix-nano start of the current quota period, used to
	// detect monthly rollovers. 0 means "not started yet".
	periodStart atomic.Int64

	// quotaCeiling is the user's quota as the data path sees it, 0 for
	// unlimited. It lives beside the counter, like the speed bucket, because
	// countingConn compares the two on every read and write and must not take
	// a lock or consult the secret set to do so. Set on every swap.
	quotaCeiling atomic.Int64

	// quotaCutoffs counts streams the ceiling ended: one per stream, however
	// many of its reads and writes found the quota gone. It is the difference
	// between a quota nobody reaches and one that is doing its job.
	quotaCutoffs atomic.Int64

	// adTagSkipped counts ad-tagged streams that fell back to the direct path
	// because their transport is not re-framable for the middle proxy.
	// adTagFailed counts the ones that could have been advertised and were
	// not, because the middle proxy could not be reached or refused them.
	adTagSkipped atomic.Int64
	adTagFailed  atomic.Int64

	// ipLimitRefused counts connections turned away for arriving from one
	// address too many. It is what tells an operator that a limit is being
	// felt: a limit nobody ever hits is doing nothing, and a user hitting
	// it constantly is either sharing a secret or roaming between networks.
	ipLimitRefused atomic.Int64

	// clientConnsRefused counts connections turned away for arriving from an
	// address already at the per-address connection cap. Kept apart from
	// ipLimitRefused: that one says how many places a user is at, this one how
	// many sockets one place opens, and the two are tuned differently.
	clientConnsRefused atomic.Int64

	// lastIP is the client address of the most recently admitted connection,
	// stored as a string. It is written only when the proxy is configured to
	// track addresses, so a deployment that does not ask for them never holds
	// one, and it is never persisted: FlushUsage writes quota counters alone.
	lastIP atomic.Value // stores string

	// speed is the user's token bucket, shared by every connection of theirs.
	// It lives here rather than in the secret set because the set is swapped
	// whole on every reload, and a bucket swapped with it would hand the user
	// a fresh burst each time; this struct is the runtime state that persists.
	speed speedLimiter

	// speedUp and speedDown are the per-direction buckets, drawn from by the
	// reads (what the client sends) and the writes (what it receives) alone,
	// on top of the combined one. Unlimited when the user has no such cap.
	speedUp   speedLimiter
	speedDown speedLimiter

	// clientThrottledNanos is the time this user's connections have spent
	// waiting at the per-address limiters of the addresses they came from, the
	// ceilings' included; throttled_ms reports it with the user's own buckets'.
	// A counter of the user's own, added to at every wait, rather than a sum
	// over the per-address table: the table forgets an address ten minutes
	// after its last stream, and the figure must never go back.
	clientThrottledNanos atomic.Int64
}

// rolloverIfNeeded zeroes quotaUsed when the monthly quota period has elapsed.
// It is a no-op for any reset policy other than monthly. The first call for a
// monthly secret simply anchors the period start. Concurrent callers race
// harmlessly: a compare-and-swap ensures only one performs the reset.
func (st *secretStats) rolloverIfNeeded(reset QuotaReset, now time.Time) {
	if reset != QuotaResetMonthly {
		return
	}

	startNano := st.periodStart.Load()
	if startNano == 0 {
		st.periodStart.CompareAndSwap(0, now.UnixNano())

		return
	}

	start := time.Unix(0, startNano)
	if now.Year() != start.Year() || now.Month() != start.Month() {
		if st.periodStart.CompareAndSwap(startNano, now.UnixNano()) {
			st.quotaUsed.Store(0)
		}
	}
}

// ProxyStats tracks per-secret connection stats with atomic counters.
// Thread-safe for concurrent access from proxy goroutines.
type ProxyStats struct {
	mu        sync.RWMutex
	users     map[string]*secretStats
	startedAt time.Time

	// Throttle: per-user connection caps recomputed every throttleInterval.
	throttleMu       sync.RWMutex
	throttleCaps     map[string]int64
	throttleLimit    int64
	throttleInterval time.Duration
	throttleActive   atomic.Bool
}

// NewProxyStats creates a new ProxyStats instance.
func NewProxyStats() *ProxyStats {
	return &ProxyStats{
		users:     make(map[string]*secretStats),
		startedAt: time.Now(),
	}
}

func (s *ProxyStats) getOrCreate(name string) *secretStats {
	s.mu.RLock()
	st, ok := s.users[name]
	s.mu.RUnlock()

	if ok {
		return st
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if st, ok = s.users[name]; ok {
		return st
	}

	st = &secretStats{}
	st.lastSeen.Store(time.Time{})
	st.lastIP.Store("")
	s.users[name] = st

	return st
}

// PreRegister adds a secret name to the stats map so it appears in output
// even if no connections have been made yet.
func (s *ProxyStats) PreRegister(name string) {
	s.getOrCreate(name)
}

// OnConnect increments the active connection count for the given secret.
func (s *ProxyStats) OnConnect(name string) {
	s.getOrCreate(name).connections.Add(1)
}

// OnDisconnect decrements the active connection count for the given secret.
func (s *ProxyStats) OnDisconnect(name string) {
	s.getOrCreate(name).connections.Add(-1)
}

// AddBytesIn adds to the bytes-in counter for the given secret.
func (s *ProxyStats) AddBytesIn(name string, n int64) {
	s.getOrCreate(name).bytesIn.Add(n)
}

// AddBytesOut adds to the bytes-out counter for the given secret.
func (s *ProxyStats) AddBytesOut(name string, n int64) {
	s.getOrCreate(name).bytesOut.Add(n)
}

// OnAdTagSkipped counts one ad-tagged stream that could not be routed through
// the middle proxy and went direct instead, losing only its sponsored channel.
func (s *ProxyStats) OnAdTagSkipped(name string) {
	s.getOrCreate(name).adTagSkipped.Add(1)
}

// SetSpeedLimit installs a user's speed limit, or unlimited for zero,
// re-rating the bucket their live connections are drawing from.
func (s *ProxyStats) SetSpeedLimit(name string, bytesPerSecond int64) {
	s.getOrCreate(name).speed.set(bytesPerSecond)
}

// SetDirectionalSpeedLimits installs a user's per-direction caps, or unlimited
// for zero, re-rating the buckets in place the way SetSpeedLimit does.
func (s *ProxyStats) SetDirectionalSpeedLimits(name string, upBytesPerSecond, downBytesPerSecond int64) {
	st := s.getOrCreate(name)
	st.speedUp.set(upBytesPerSecond)
	st.speedDown.set(downBytesPerSecond)
}

// OnIPLimitRefused counts one connection refused by the user's address limit.
func (s *ProxyStats) OnIPLimitRefused(name string) {
	s.getOrCreate(name).ipLimitRefused.Add(1)
}

// OnClientConnsRefused counts one connection refused by the per-address
// connection cap.
func (s *ProxyStats) OnClientConnsRefused(name string) {
	s.getOrCreate(name).clientConnsRefused.Add(1)
}

// SetQuotaCeiling installs the quota the data path holds a user to, or
// unlimited for zero. The live counter is untouched: a ceiling lowered below
// it ends the user's streams on their next byte and the sweep closes the
// idle ones.
func (s *ProxyStats) SetQuotaCeiling(name string, bytes int64) {
	s.getOrCreate(name).quotaCeiling.Store(bytes)
}

// OnAdTagFailed counts one ad-tagged stream whose transport the middle proxy
// does handle, and which went direct anyway because the middle proxy could not
// be reached or turned it away. Kept apart from OnAdTagSkipped: a skip is a
// design outcome, a failure is an operational one, and only the second means
// something is wrong.
func (s *ProxyStats) OnAdTagFailed(name string) {
	s.getOrCreate(name).adTagFailed.Add(1)
}

// UpdateLastSeen sets the last-seen timestamp for the given secret to now.
func (s *ProxyStats) UpdateLastSeen(name string) {
	s.getOrCreate(name).lastSeen.Store(time.Now())
}

// SetLastIP records the client address of the most recent admitted connection
// for the given secret. Callers gate this on the proxy's tracking setting; it
// is not checked here, so a caller that reaches this has already decided.
func (s *ProxyStats) SetLastIP(name, ip string) {
	s.getOrCreate(name).lastIP.Store(ip)
}

// QuotaUsed returns the bytes counted against the secret's current quota period,
// rolling the monthly period over first when it is due.
func (s *ProxyStats) QuotaUsed(name string, reset QuotaReset) int64 {
	st := s.getOrCreate(name)
	st.rolloverIfNeeded(reset, time.Now())

	return st.quotaUsed.Load()
}

// quotaUsedValue returns the raw used-bytes counter without a rollover. It is
// used for display, where the periodic loop and connection gate keep the value
// fresh.
func (s *ProxyStats) quotaUsedValue(name string) int64 {
	s.mu.RLock()
	st, ok := s.users[name]
	s.mu.RUnlock()

	if !ok {
		return 0
	}

	return st.quotaUsed.Load()
}

// fillRuntimeInfo copies the live counters for one secret onto a SecretInfo, so
// GET /secrets/{name} answers the same questions GET /stats does about that
// user without a caller having to fetch and filter the whole report.
//
// LastIP is copied here; ConnectedIPs is not, because it is derived from the
// proxy's connection registry rather than held on the counters, and the caller
// takes one snapshot of that for the whole list.
//
// A secret with no bucket is a secret nobody has ever connected to, which is
// zero connections and no last seen -- not an error, and not a reason to create
// a bucket as a side effect of reading.
func (s *ProxyStats) fillRuntimeInfo(info *SecretInfo, name string) {
	s.mu.RLock()
	st, ok := s.users[name]
	s.mu.RUnlock()

	if !ok {
		return
	}

	info.Connections = st.connections.Load()

	if lastSeen, _ := st.lastSeen.Load().(time.Time); !lastSeen.IsZero() {
		info.LastSeen = &lastSeen
	}

	info.LastIP, _ = st.lastIP.Load().(string)
}

// rollover applies a monthly quota rollover for a single secret if it is due.
func (s *ProxyStats) rollover(name string, reset QuotaReset, now time.Time) {
	s.getOrCreate(name).rolloverIfNeeded(reset, now)
}

// ResetQuota zeroes the used-bytes counter for the secret and restarts its quota
// period from now.
func (s *ProxyStats) ResetQuota(name string) {
	st := s.getOrCreate(name)
	st.quotaUsed.Store(0)
	st.periodStart.Store(time.Now().UnixNano())
}

// usageRecord is the persisted per-secret quota state.
type usageRecord struct {
	QuotaUsed   int64 `json:"quota_used"`
	PeriodStart int64 `json:"period_start"`
}

// LoadUsage restores persisted quota usage from path. A missing file is not an
// error (there is simply nothing to restore yet).
func (s *ProxyStats) LoadUsage(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}

		return fmt.Errorf("cannot read usage state %s: %w", path, err)
	}

	var records map[string]usageRecord
	if err := json.Unmarshal(data, &records); err != nil {
		return fmt.Errorf("cannot parse usage state %s: %w", path, err)
	}

	for name, rec := range records {
		st := s.getOrCreate(name)
		st.quotaUsed.Store(rec.QuotaUsed)
		st.periodStart.Store(rec.PeriodStart)
	}

	return nil
}

// FlushUsage writes the current quota usage of every known secret to path
// atomically (write-temp-then-rename), so a crash never leaves a truncated file.
func (s *ProxyStats) FlushUsage(path string) error {
	s.mu.RLock()
	records := make(map[string]usageRecord, len(s.users))

	for name, st := range s.users {
		records[name] = usageRecord{
			QuotaUsed:   st.quotaUsed.Load(),
			PeriodStart: st.periodStart.Load(),
		}
	}
	s.mu.RUnlock()

	data, err := json.Marshal(records)
	if err != nil {
		return fmt.Errorf("cannot marshal usage state: %w", err)
	}

	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil { //nolint: mnd
		return fmt.Errorf("cannot write usage state %s: %w", tmp, err)
	}

	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("cannot replace usage state %s: %w", path, err)
	}

	return nil
}

// SetThrottle configures connection throttling. Must be called before
// startThrottleLoop and before any connections arrive.
func (s *ProxyStats) SetThrottle(limit int64, interval time.Duration) {
	s.throttleLimit = limit
	s.throttleInterval = interval
	s.throttleCaps = make(map[string]int64)
}

// CanConnect returns true if the user is allowed to open a new connection
// under the current throttle caps. If throttling is not configured or the
// user has no cap, it always returns true.
func (s *ProxyStats) CanConnect(name string) bool {
	if s.throttleLimit == 0 {
		return true
	}

	s.throttleMu.RLock()
	userCap, hasCap := s.throttleCaps[name]
	s.throttleMu.RUnlock()

	if !hasCap {
		return true
	}

	return s.getOrCreate(name).connections.Load() < userCap
}

// startThrottleLoop runs a background goroutine that recomputes per-user
// caps every throttleInterval.
func (s *ProxyStats) startThrottleLoop(ctx context.Context, logger Logger) {
	go func() {
		ticker := time.NewTicker(s.throttleInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.recomputeCaps(logger)
			}
		}
	}()

	logger.BindStr("limit", fmt.Sprintf("%d", s.throttleLimit)).
		BindStr("interval", s.throttleInterval.String()).
		Info("throttle loop started")
}

func (s *ProxyStats) recomputeCaps(logger Logger) {
	s.mu.RLock()
	userConns := make(map[string]int64, len(s.users))
	for name, st := range s.users {
		userConns[name] = st.connections.Load()
	}
	s.mu.RUnlock()

	caps := computeFairCaps(userConns, s.throttleLimit)
	wasActive := s.throttleActive.Load()
	nowActive := len(caps) > 0

	s.throttleMu.Lock()
	s.throttleCaps = caps
	s.throttleActive.Store(nowActive)
	s.throttleMu.Unlock()

	if nowActive && !wasActive {
		logger.Warning("throttle activated")
	} else if !nowActive && wasActive {
		logger.Info("throttle deactivated")
	}
}

// computeFairCaps implements the fair-share algorithm. Users below the equal
// share keep their connections; remaining budget is split equally among the
// rest. Returns nil when no throttling is needed.
func computeFairCaps(userConns map[string]int64, limit int64) map[string]int64 {
	var total int64
	for _, c := range userConns {
		total += c
	}

	if total <= limit {
		return nil
	}

	remaining := make(map[string]int64, len(userConns))
	maps.Copy(remaining, userConns)

	budget := limit
	caps := make(map[string]int64)

	for len(remaining) > 0 {
		fairShare := budget / int64(len(remaining))
		changed := false

		for name, conns := range remaining {
			if conns <= fairShare {
				budget -= conns
				delete(remaining, name)
				changed = true
			}
		}

		if !changed {
			for name := range remaining {
				caps[name] = fairShare
			}

			break
		}
	}

	return caps
}

// Capability names reported in the "features" array of the /stats response.
// They are a PUBLIC CONTRACT: downstream tooling (the management panel) matches
// on these exact strings to decide whether an endpoint may be called, so
// renaming one is a breaking API change, not a refactor. Only add a name once
// the capability actually exists in the binary — advertising an absent one
// defeats the point of the array.
const (
	// FeatureClientIPs means the binary understands the track-client-ips
	// option, so a panel may offer the switch and may expect connected_ips and
	// last_ip on GET /stats when it is on. It says nothing about whether the
	// running deployment has actually enabled it -- the fields' presence says
	// that, and their absence is indistinguishable from an idle secret.
	FeatureClientIPs = "client-ips"

	// FeatureClientLimits means the per-address controls inside one secret are
	// honoured: [secret-limits.<name>] and the secrets API accept client-conns
	// (client_conns on the API), a cap on the live connections one address may
	// hold to the secret, and /stats reads it back as client_conns and counts
	// its refusals in client_conns_refused. The API is strict, so a client
	// must see this before it sends the field.
	FeatureClientLimits = "client-limits"

	// FeatureFakeTLS means the proxy speaks the FakeTLS (obfuscated) handshake.
	FeatureFakeTLS = "faketls"

	// FeatureHandshakeBudget means the FakeTLS door bounds the CPU it spends
	// scanning hellos no hint matched, [defense.handshake-budget] is honoured,
	// and /stats reports the door's counters as the top-level faketls_handshake
	// object once it has counted something.
	FeatureHandshakeBudget = "handshake-budget"

	// FeatureIPLimits means [secret-limits.<name>] and the secrets API accept
	// a per-user ip_limit, the proxy refuses a connection from one address
	// too many, /stats reports ip_limit, active_ips and ip_limit_refused, and
	// GET/PUT/DELETE /secrets/{name}/external-ips let a panel report the
	// addresses a user holds on other systems so the limit spans them.
	FeatureIPLimits = "ip-limits"

	// FeatureListeners means the [[listener]] config table is honoured: extra
	// sockets can be declared, and /stats reports what each one accepts.
	FeatureListeners = "listeners"

	// FeatureQuotaReset means POST /secrets/{name}/reset-quota is served.
	FeatureQuotaReset = "quota-reset"

	// FeatureSecretModes means the dd and plain secret forms parse and serve, so
	// a panel may hand out a link in any of the three wire forms.
	FeatureSecretModes = "secret-modes"

	// FeatureSecretsAPI means the GET/PUT/POST/DELETE /secrets routes are served.
	FeatureSecretsAPI = "secrets-api"

	// FeatureWebRelay means this binary carries the WEB proxy transport: the
	// `web-relay` and `generate-web-key` subcommands, and the [web] config
	// table they read.
	//
	// It is advertised by the PROXY, which does not serve that transport, and
	// that is the point: the panel decides whether to render the WEB settings
	// and start a second process, and the only thing it can ask is the running
	// binary. A proxy answering /stats is the one component it always has.
	FeatureWebRelay = "web-relay"

	// FeatureWebRelayWatch means the relay follows its config file by itself:
	// a changed [secrets] table is applied within seconds of the write
	// settling, with no signal sent. Advertised by the proxy for the same
	// reason as FeatureWebRelay -- a panel that writes the file and then
	// signals the relay can stop signalling once it sees this, and the proxy
	// is the one component it can ask.
	FeatureWebRelayWatch = "web-relay-watch"

	// FeatureSpeedLimits means [secret-limits.<name>] and the secrets API
	// accept a per-user speed, enforced by the proxy across every connection
	// and door of that user, and /stats reports speed_limit and throttled_ms.
	FeatureSpeedLimits = "speed-limits"

	// FeatureSpeedDirections means speed-up and speed-down (speed_up and
	// speed_down on the API) cap each direction on its own bucket, read back
	// as speed_limit_up and speed_limit_down.
	FeatureSpeedDirections = "speed-directions"

	// FeatureKick means POST /secrets/{name}/kick closes a user's live streams
	// from the named places, matched at the unit the address limit counts.
	FeatureKick = "kick"

	// FeatureClientIPActivity means connected_ips_last_seen accompanies
	// connected_ips wherever it is reported: when each address last moved a
	// byte, gated on track-client-ips exactly as the addresses are.
	FeatureClientIPActivity = "client-ip-activity"

	// FeatureQuotaCeiling means the quota is enforced on the data path -- a
	// stream ends at the byte that reaches it and a sweep closes the idle
	// ones -- rather than only refusing the next connection.
	FeatureQuotaCeiling = "quota-ceiling"

	// FeatureSecretRead means GET /secrets/{name} is served.
	FeatureSecretRead = "secret-read"
)

// supportedFeatures is the sorted capability list this build advertises. Keep it
// sorted so the response is byte-stable across restarts.
var supportedFeatures = []string{
	FeatureClientIPActivity,
	FeatureClientIPs,
	FeatureClientLimits,
	FeatureFakeTLS,
	FeatureHandshakeBudget,
	FeatureIPLimits,
	FeatureKick,
	FeatureListeners,
	FeatureQuotaCeiling,
	FeatureQuotaReset,
	FeatureSecretModes,
	FeatureSecretRead,
	FeatureSecretsAPI,
	FeatureSpeedDirections,
	FeatureSpeedLimits,
	FeatureWebRelay,
	FeatureWebRelayWatch,
}

// StatsResponse is the JSON response for the stats endpoint.
type StatsResponse struct {
	StartedAt        time.Time     `json:"started_at"`
	UptimeSeconds    int64         `json:"uptime_seconds"`
	TotalConnections int64         `json:"total_connections"`
	Features         []string      `json:"features"`
	Throttle         *ThrottleJSON `json:"throttle,omitempty"`

	// Listeners and Obfuscated describe the extra obfuscated2 entry. Both are
	// omitted when no [[listener]] is configured, so a deployment that never
	// declared one keeps a byte-identical response.
	Listeners  []ListenerJSON  `json:"listeners,omitempty"`
	Obfuscated *ObfuscatedJSON `json:"obfuscated,omitempty"`

	// FakeTLSHandshake is what the FakeTLS door decided about the hellos that
	// reached its secret scan. It is omitted until the door has counted
	// something, and it is a top-level object on purpose: nothing about the door
	// is a user, and the panel bills every key under Users as one.
	FakeTLSHandshake *FakeTLSJSON `json:"faketls_handshake,omitempty"`

	Users map[string]UserStatsJSON `json:"users"`
}

// FakeTLSJSON is the FakeTLS door's counter block on GET /stats: one number per
// way a hello past the SNI gate can end, the flag saying whether the handshake
// budget acts on a refusal, and what the budget believes a SHA-256 block costs.
// Every count is a total since the process started.
type FakeTLSJSON struct {
	Hinted            int64   `json:"hinted"`
	Scanned           int64   `json:"scanned"`
	Unmatched         int64   `json:"unmatched"`
	DeniedIP          int64   `json:"denied_ip"`
	DeniedGlobal      int64   `json:"denied_global"`
	Oversized         int64   `json:"oversized"`
	OverBudgetMatched int64   `json:"over_budget_matched"`
	Enforced          bool    `json:"enforced"`
	NsPerBlock        float64 `json:"ns_per_block"`
}

// ObfuscatedJSON is the obfuscated2 entry counter block on GET /stats. Draining
// is a live gauge, not a total: it is how many refused connections are sitting
// in a bounded drain right now.
type ObfuscatedJSON struct {
	Trials      int64 `json:"trials"`
	Misses      int64 `json:"misses"`
	Denied      int64 `json:"denied"`
	Draining    int64 `json:"draining"`
	RateLimited int64 `json:"rate_limited"`
}

// obfuscatedJSONOf snapshots the counters. It takes a pointer because
// obfuscatedCounters holds atomics and must never be copied by value.
func obfuscatedJSONOf(c *obfuscatedCounters) *ObfuscatedJSON {
	return &ObfuscatedJSON{
		Trials:      c.trials.Load(),
		Misses:      c.misses.Load(),
		Denied:      c.denied.Load(),
		Draining:    c.draining.Load(),
		RateLimited: c.rateLimited.Load(),
	}
}

// fakeTLSJSONOf snapshots the door's counters and the budget's own view of what
// a block costs. It takes pointers because fakeTLSCounters holds atomics and must
// never be copied by value; a nil budget, which is "budget off", is not enforcing
// and has no block cost to report.
func fakeTLSJSONOf(c *fakeTLSCounters, b *scanBudget) *FakeTLSJSON {
	return &FakeTLSJSON{
		Hinted:            c.hinted.Load(),
		Scanned:           c.scanned.Load(),
		Unmatched:         c.unmatched.Load(),
		DeniedIP:          c.deniedIP.Load(),
		DeniedGlobal:      c.deniedGlobal.Load(),
		Oversized:         c.oversized.Load(),
		OverBudgetMatched: c.overBudgetMatched.Load(),
		Enforced:          b.enforced(),
		NsPerBlock:        b.reportedBlockNanos(),
	}
}

// counted reports whether the door has counted anything at all. The flag and the
// block cost are not counts: a door that has been asked nothing has nothing to
// report, however it is configured.
func (j *FakeTLSJSON) counted() bool {
	return j.Hinted != 0 || j.Scanned != 0 || j.Unmatched != 0 || j.DeniedIP != 0 ||
		j.DeniedGlobal != 0 || j.Oversized != 0 || j.OverBudgetMatched != 0
}

// ThrottleJSON is the throttle portion of the stats JSON response.
type ThrottleJSON struct {
	Active bool             `json:"active"`
	Limit  int64            `json:"limit"`
	Caps   map[string]int64 `json:"caps,omitempty"`
}

// UserStatsJSON is the per-user portion of the stats JSON response. The quota
// and expiry fields describe the secret's configured limits and are filled in by
// the proxy (which holds the secret snapshot); ProxyStats itself only fills the
// runtime counters, including QuotaUsed.
type UserStatsJSON struct {
	Connections int64      `json:"connections"`
	BytesIn     int64      `json:"bytes_in"`
	BytesOut    int64      `json:"bytes_out"`
	LastSeen    *time.Time `json:"last_seen"`

	QuotaUsed      int64      `json:"quota_used"`
	Quota          int64      `json:"quota,omitempty"`
	QuotaRemaining *int64     `json:"quota_remaining,omitempty"`
	QuotaReset     string     `json:"quota_reset,omitempty"`
	ExpiresAt      *time.Time `json:"expires_at,omitempty"`
	Disabled       bool       `json:"disabled,omitempty"`

	// QuotaCutoffs counts streams ended by reaching the quota, since the
	// process started. A quota nobody reaches shows none.
	QuotaCutoffs int64 `json:"quota_cutoffs,omitempty"`

	// AdTagSkipped counts streams that carried an ad tag but took the direct
	// path anyway because their transport has no middle-proxy reframer. An
	// operator who monetises through @MTProxybot has to be able to see this: a
	// silent skip is a revenue bug nobody can diagnose.
	AdTagSkipped int64 `json:"ad_tag_skipped,omitempty"`

	// AdTagFailed counts streams that carried an ad tag, on a transport the
	// middle proxy handles, and took the direct path because the middle proxy
	// could not be reached or refused them. Unlike a skip this is not by
	// design: a proxy on a network that cannot reach core.telegram.org, or
	// whose ad tag was revoked, shows up here and nowhere else.
	AdTagFailed int64 `json:"ad_tag_failed,omitempty"`

	// SpeedLimit is the user's configured cap in bytes per second, and
	// ThrottledMillis the time their connections have spent held to it. A
	// user with a limit and no throttled time is not reaching it; one whose
	// throttled time grows by a second a second is living at it.
	SpeedLimit      int64 `json:"speed_limit,omitempty"`
	ThrottledMillis int64 `json:"throttled_ms,omitempty"`

	// SpeedLimitUp and SpeedLimitDown are the per-direction caps in bytes per
	// second, from the client's side, or absent for unlimited. ThrottledMillis
	// above counts the time held to any of the three buckets, and to the
	// per-address limiters of the addresses the user connects from.
	SpeedLimitUp   int64 `json:"speed_limit_up,omitempty"`
	SpeedLimitDown int64 `json:"speed_limit_down,omitempty"`

	// IPLimit is the user's address limit; ActiveIPs is how many distinct
	// addresses they count as being at right now, the addresses of their
	// live connections here plus any reported from elsewhere; and
	// IPLimitRefused is how many connections were turned away for arriving
	// from one address too many. The first two are absent when zero, the
	// count is never gated: how many places a user is in says nothing about
	// where.
	IPLimit        int   `json:"ip_limit,omitempty"`
	ActiveIPs      int   `json:"active_ips,omitempty"`
	IPLimitRefused int64 `json:"ip_limit_refused,omitempty"`

	// ClientConns is the per-address connection cap, read back, and
	// ClientConnsRefused is how many connections were turned away for arriving
	// from an address that already held that many. Scalars inside the user
	// object, never a key under users and never an address: both are absent
	// when zero, and neither is gated.
	ClientConns        int   `json:"client_conns,omitempty"`
	ClientConnsRefused int64 `json:"client_conns_refused,omitempty"`

	// ConnectedIPs lists the distinct client addresses holding a live
	// connection right now, sorted. LastIP is the address of the most recent
	// admitted connection, which outlives that connection. ExternalIPs are
	// the addresses a panel reported the user present at elsewhere, and
	// ExternalExpiresAt is when that report lapses unless refreshed.
	//
	// All are filled in only when the proxy is configured with
	// track-client-ips, and all are omitted when empty, so /stats on a
	// deployment that never enabled it is byte-identical to before they
	// existed. See ProxyOpts.TrackClientIPs for why that is the default.
	ConnectedIPs      []string   `json:"connected_ips,omitempty"`
	LastIP            string     `json:"last_ip,omitempty"`
	ExternalIPs       []string   `json:"external_ips,omitempty"`
	ExternalExpiresAt *time.Time `json:"external_expires_at,omitempty"`

	// ConnectedIPsLastSeen is, for each address in ConnectedIPs, the second a
	// stream from it last moved a byte: the latest across the streams sharing
	// the address. Gated and omitted exactly as ConnectedIPs is, so a panel
	// can tell a device that fell silent from one still talking.
	ConnectedIPsLastSeen map[string]time.Time `json:"connected_ips_last_seen,omitempty"`
}

// buildResponse assembles the base stats response (runtime counters and throttle
// state). Per-secret limit fields are left zero for the proxy to overlay.
func (s *ProxyStats) buildResponse() StatsResponse {
	s.mu.RLock()

	var totalConns int64

	users := make(map[string]UserStatsJSON, len(s.users))

	for name, st := range s.users {
		conns := st.connections.Load()
		totalConns += conns

		lastSeen := st.lastSeen.Load().(time.Time) //nolint: forcetypeassert
		var lastSeenPtr *time.Time
		if !lastSeen.IsZero() {
			lastSeenPtr = &lastSeen
		}

		lastIP, _ := st.lastIP.Load().(string)

		users[name] = UserStatsJSON{
			Connections:  conns,
			BytesIn:      st.bytesIn.Load(),
			BytesOut:     st.bytesOut.Load(),
			LastSeen:     lastSeenPtr,
			QuotaUsed:    st.quotaUsed.Load(),
			QuotaCutoffs: st.quotaCutoffs.Load(),
			AdTagSkipped: st.adTagSkipped.Load(),
			AdTagFailed:  st.adTagFailed.Load(),
			ThrottledMillis: (st.speed.throttledNanos.Load() + st.speedUp.throttledNanos.Load() +
				st.speedDown.throttledNanos.Load() + st.clientThrottledNanos.Load()) / int64(time.Millisecond),
			IPLimitRefused:     st.ipLimitRefused.Load(),
			ClientConnsRefused: st.clientConnsRefused.Load(),
			LastIP:             lastIP,
		}
	}
	s.mu.RUnlock()

	var throttle *ThrottleJSON
	if s.throttleLimit > 0 {
		s.throttleMu.RLock()
		active := s.throttleActive.Load()

		var capsCopy map[string]int64
		if len(s.throttleCaps) > 0 {
			capsCopy = make(map[string]int64, len(s.throttleCaps))
			maps.Copy(capsCopy, s.throttleCaps)
		}

		s.throttleMu.RUnlock()

		throttle = &ThrottleJSON{
			Active: active,
			Limit:  s.throttleLimit,
			Caps:   capsCopy,
		}
	}

	// Features is cloned so a caller cannot mutate the shared package-level list
	// through a response, and so the field is never nil: it serializes as [],
	// never null, which the panel relies on.
	return StatsResponse{
		StartedAt:        s.startedAt,
		UptimeSeconds:    int64(time.Since(s.startedAt).Seconds()),
		TotalConnections: totalConns,
		Features:         slices.Clone(supportedFeatures),
		Throttle:         throttle,
		Users:            users,
	}
}

func (s *ProxyStats) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if err := json.NewEncoder(w).Encode(s.buildResponse()); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// The management HTTP API (GET /stats, POST /reload, /secrets and /adtag
// routes) is served by (*Proxy).startAPIServer in proxy_api.go, which builds a
// mux with access to the whole proxy. reloadHandler below is shared by that
// server for the /reload route.

// reloadHandler answers POST /reload by running reload and reporting the
// outcome: 200 on success, 405 for a non-POST, 503 when the proxy has no
// reloader wired, and 500 when the reload itself fails (the previous secret
// set stays active). A nil reload is treated as unavailable.
func reloadHandler(reload func() error, logger Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			http.Error(w, "only POST is allowed", http.StatusMethodNotAllowed)

			return
		}

		if reload == nil {
			http.Error(w, "reload is not supported", http.StatusServiceUnavailable)

			return
		}

		if err := reload(); err != nil {
			logger.WarningError("secret reload failed", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)

			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}` + "\n")) //nolint: errcheck
	}
}
