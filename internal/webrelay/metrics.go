package webrelay

import (
	"sync"
	"sync/atomic"
	"time"
)

// Counters is everything one relay process knows about itself.
//
// It exists because the relay knew nothing. The proxy beside it has served
// /stats since before any of this, and the relay -- the internet-facing half,
// the one terminating sessions and carrying every byte -- answered four request
// paths and reported none of it. An operator's first sign of trouble was a user
// saying so.
//
// Every field is an atomic and every writer is on a request or relay path, so
// nothing here may take a lock: the counters must never be able to slow the
// thing they measure, and a metric that contends with traffic is worse than no
// metric.
type Counters struct {
	startedAt time.Time

	// Sessions. Created counts admissions, attached counts carriers that
	// reached the WebSocket. Created minus attached is sessions minted and
	// never used -- a client that gave up between the page and the socket.
	//
	// There is deliberately no active gauge here. A session is admitted over
	// HTTP and may never attach, and it can also be reaped by the store's own
	// expiry, so a counter incremented on admission and decremented when a
	// carrier ends would drift upwards forever. The store enforces the limit
	// and reaps the expired, so the store's count is the only one that can be
	// right -- Snapshot takes it as an argument rather than keeping a copy.
	sessionsCreated  atomic.Int64
	sessionsAttached atomic.Int64

	streamsOpened atomic.Int64
	streamsActive atomic.Int64

	// Bytes as the relay sees them: up is client to Telegram, down is Telegram
	// to client. Payload only -- frame headers and WebSocket framing are not
	// counted, so these are comparable with the proxy's own byte counters
	// rather than with anything on the wire.
	bytesUp   atomic.Int64
	bytesDown atomic.Int64

	// Why requests were refused. The breakdown is the point: when this degrades
	// at three in the morning, "coverServed climbing" (clients presenting
	// capabilities this relay does not recognise -- usually a hostname or
	// secret-set mismatch after a reload) and "sessionLimit climbing" (at
	// capacity) are completely different problems, and one number cannot tell
	// them apart.
	coverServed  atomic.Int64
	notFound     atomic.Int64
	badToken     atomic.Int64
	sessionLimit atomic.Int64

	// Reloads, so an operator can tell whether the SIGHUP they sent landed.
	reloads     atomic.Int64
	reloadFails atomic.Int64

	mu         sync.Mutex
	profiles   []string
	lastReload time.Time
}

// NewCounters starts a counter set. The clock is captured once so uptime is
// measured from the relay coming up rather than from the first scrape.
func NewCounters(now time.Time) *Counters {
	return &Counters{startedAt: now}
}

// SetProfiles records the names behind the profile numbering, so a report can
// say "alice" where it would otherwise say "profile 3".
//
// Names are optional. The relay's own matching is by capability and index and
// works without them; this is purely so the report lines up with the proxy's
// /stats, which is keyed by name. A caller that has no names passes none and
// the report falls back to indices.
func (c *Counters) SetProfiles(names []string) {
	if c == nil {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.profiles = append(c.profiles[:0], names...)
}

// OnReload records the outcome of a profile reload.
func (c *Counters) OnReload(now time.Time, err error) {
	if c == nil {
		return
	}

	if err != nil {
		c.reloadFails.Add(1)

		return
	}

	c.reloads.Add(1)

	c.mu.Lock()
	c.lastReload = now
	c.mu.Unlock()
}

// Every counter below is nil-safe. The origin can be built without a counter
// set -- most tests do -- and a nil check at the call site in the relay path
// would be noise repeated a dozen times.

func (c *Counters) onSessionCreated() {
	if c != nil {
		c.sessionsCreated.Add(1)
	}
}

func (c *Counters) onSessionAttached() {
	if c != nil {
		c.sessionsAttached.Add(1)
	}
}

func (c *Counters) onStreamOpened() {
	if c != nil {
		c.streamsOpened.Add(1)
		c.streamsActive.Add(1)
	}
}

func (c *Counters) onStreamClosed() {
	if c != nil {
		c.streamsActive.Add(-1)
	}
}

func (c *Counters) addBytesUp(n int) {
	if c != nil && n > 0 {
		c.bytesUp.Add(int64(n))
	}
}

func (c *Counters) addBytesDown(n int) {
	if c != nil && n > 0 {
		c.bytesDown.Add(int64(n))
	}
}

func (c *Counters) onCoverServed() {
	if c != nil {
		c.coverServed.Add(1)
	}
}

func (c *Counters) onNotFound() {
	if c != nil {
		c.notFound.Add(1)
	}
}

func (c *Counters) onBadToken() {
	if c != nil {
		c.badToken.Add(1)
	}
}

func (c *Counters) onSessionLimit() {
	if c != nil {
		c.sessionLimit.Add(1)
	}
}

// RelayStats is the JSON document GET /stats returns on the relay's own stats
// socket.
//
// The field names deliberately echo the proxy's /stats where they mean the same
// thing (started_at, uptime_seconds), so an operator reading both does not have
// to translate. They are a public contract for the same reason the proxy's
// capability names are: something downstream will parse this.
type RelayStats struct {
	StartedAt     time.Time `json:"started_at"`
	UptimeSeconds int64     `json:"uptime_seconds"`

	Profiles    []string   `json:"profiles"`
	Reloads     int64      `json:"reloads"`
	ReloadFails int64      `json:"reload_failures"`
	LastReload  *time.Time `json:"last_reload"`

	Sessions RelaySessionStats `json:"sessions"`
	Streams  RelayStreamStats  `json:"streams"`
	Bytes    RelayByteStats    `json:"bytes"`
	Refused  RelayRefusedStats `json:"refused"`
}

// RelaySessionStats counts carrier sessions. Active is a gauge; the rest are
// totals since start.
type RelaySessionStats struct {
	Active   int64 `json:"active"`
	Created  int64 `json:"created"`
	Attached int64 `json:"attached"`
	Max      int64 `json:"max"`
}

// RelayStreamStats counts the logical connections inside those sessions.
type RelayStreamStats struct {
	Active int64 `json:"active"`
	Opened int64 `json:"opened"`
}

// RelayByteStats is relay payload, not wire bytes: frame headers and WebSocket
// framing are excluded, so these compare with the proxy's counters.
type RelayByteStats struct {
	Up   int64 `json:"up"`
	Down int64 `json:"down"`
}

// RelayRefusedStats says why requests did not become sessions.
type RelayRefusedStats struct {
	// CoverServed counts requests answered with the cover site because nothing
	// about them was recognised. On a public hostname this is mostly the
	// internet knocking, and a normal number is not zero -- what matters is a
	// sudden climb alongside users reporting failures, which is the signature
	// of a hostname or secret-set mismatch.
	CoverServed int64 `json:"cover_served"`

	// NotFound counts authentic-but-unusable capabilities: answered locally,
	// never forwarded.
	NotFound int64 `json:"not_found"`

	// BadToken counts session or carrier requests whose bearer this relay did
	// not mint, or had already spent.
	BadToken int64 `json:"bad_token"`

	// SessionLimit counts admissions refused because the process was at
	// max-sessions. Any non-zero value here is capacity, not abuse.
	SessionLimit int64 `json:"session_limit"`
}

// Snapshot reads every counter into a document.
//
// The reads are not one atomic operation and are not meant to be: a scrape of a
// live relay is a sample, and a report that locked the relay to be internally
// consistent would be a report that periodically stops the thing it measures.
func (c *Counters) Snapshot(now time.Time, maxSessions, active int) RelayStats {
	if c == nil {
		return RelayStats{}
	}

	c.mu.Lock()
	profiles := append([]string(nil), c.profiles...)
	lastReload := c.lastReload
	c.mu.Unlock()

	var lastReloadPtr *time.Time

	if !lastReload.IsZero() {
		lastReloadPtr = &lastReload
	}

	// Never null: something downstream will index this, and an absent array is
	// a different shape from an empty one.
	if profiles == nil {
		profiles = []string{}
	}

	return RelayStats{
		StartedAt:     c.startedAt,
		UptimeSeconds: int64(now.Sub(c.startedAt).Seconds()),
		Profiles:      profiles,
		Reloads:       c.reloads.Load(),
		ReloadFails:   c.reloadFails.Load(),
		LastReload:    lastReloadPtr,
		Sessions: RelaySessionStats{
			// Taken from the store rather than from the gauge: the store is
			// what enforces the limit, so its count is the one an operator
			// comparing against Max needs to see.
			Active:   int64(active),
			Created:  c.sessionsCreated.Load(),
			Attached: c.sessionsAttached.Load(),
			Max:      int64(maxSessions),
		},
		Streams: RelayStreamStats{
			Active: c.streamsActive.Load(),
			Opened: c.streamsOpened.Load(),
		},
		Bytes: RelayByteStats{
			Up:   c.bytesUp.Load(),
			Down: c.bytesDown.Load(),
		},
		Refused: RelayRefusedStats{
			CoverServed:  c.coverServed.Load(),
			NotFound:     c.notFound.Load(),
			BadToken:     c.badToken.Load(),
			SessionLimit: c.sessionLimit.Load(),
		},
	}
}
