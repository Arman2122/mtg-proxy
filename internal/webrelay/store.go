package webrelay

import (
	"crypto/sha256"
	"crypto/subtle"
	"sync"
	"time"
)

// Lifetimes. Every one of these is the published default; none is negotiated
// with the client, which learns nothing from WELCOME.
const (
	// BootstrapTTL is how long the token embedded in one bridge page stays
	// usable. It is short because the page is loaded and used immediately: the
	// only gap it has to cover is the client's own WebView startup.
	BootstrapTTL = 2 * time.Minute

	// ReconnectGrace is how long a session with no carrier attached stays
	// resumable. An alive bridge refreshes it; a client that has gone entirely
	// silent loses the session, and the desktop MTProto layer has already reset
	// its own connections well before this expires.
	ReconnectGrace = 2 * time.Minute

	// DefaultMaxSessions bounds concurrent carrier sessions in one process.
	DefaultMaxSessions = 1024
)

// admission is the outcome of a session-creation attempt. The three values map
// exactly onto the three answers the origin may give, which is why this is an
// enum rather than an error: two of them are not failures of the request.
type admission uint8

const (
	// admitted means a session exists and its token is returned.
	admitted admission = iota

	// refused means the credential is authentic but cannot be used: expired,
	// already spent on a different body, or naming nothing. The origin answers
	// locally with a 404 and never tells the cover site about it.
	refused

	// atCapacity means the relay is full right now. The bootstrap stays
	// unconsumed, so the byte-identical request is safe to repeat.
	atCapacity
)

// bootstrap is one page's credential and the answer it produced.
//
// It is the idempotency key for session creation, which matters because the
// bridge retries an ambiguous failure with the same body: the request may have
// been applied before the response was lost, and a second session for a client
// that thinks it has one is a leak with no owner.
type bootstrap struct {
	profile int
	expires time.Time

	// spent, and what it produced. A repeat of the same body gets the same
	// answer; a different body gets nothing.
	session string
	digest  [sha256.Size]byte
	used    bool
}

// sessionEntry is one live carrier session.
type sessionEntry struct {
	profile  int
	expires  time.Time
	attached bool
	cancel   func()
}

// store holds the credentials and sessions of one relay. Everything in it is
// keyed by a token this process minted, so a lookup miss is not an error: it is
// the ordinary answer for an expired, spent or forged value.
type store struct {
	mu          sync.Mutex
	now         func() time.Time
	bootstraps  map[string]*bootstrap
	sessions    map[string]*sessionEntry
	maxSessions int
}

func newStore(maxSessions int, now func() time.Time) *store {
	if maxSessions <= 0 {
		maxSessions = DefaultMaxSessions
	}

	if now == nil {
		now = time.Now
	}

	return &store{
		now:         now,
		bootstraps:  make(map[string]*bootstrap),
		sessions:    make(map[string]*sessionEntry),
		maxSessions: maxSessions,
	}
}

// issueBootstrap records a freshly minted bootstrap against the profile whose
// capability selected the bridge.
func (s *store) issueBootstrap(token string, profile int) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.expire()

	s.bootstraps[token] = &bootstrap{profile: profile, expires: s.now().Add(BootstrapTTL)}
}

// createSession spends a bootstrap. mint is called only when a new session is
// actually needed, so a repeat does not draw a token it will throw away.
func (s *store) createSession(token string, body []byte, mint func() (string, error)) (string, admission) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.expire()

	entry, ok := s.bootstraps[token]
	if !ok || entry.expires.Before(s.now()) {
		return "", refused
	}

	digest := sha256.Sum256(body)

	if entry.used {
		// The same request again: the earlier answer, byte for byte. A
		// different body under the same bootstrap is a different request and
		// gets nothing.
		if subtle.ConstantTimeCompare(entry.digest[:], digest[:]) != 1 {
			return "", refused
		}

		if _, alive := s.sessions[entry.session]; !alive {
			return "", refused
		}

		return entry.session, admitted
	}

	if len(s.sessions) >= s.maxSessions {
		// Deliberately before the bootstrap is marked used: the client is told
		// to retry, and the retry must find the credential still valid.
		return "", atCapacity
	}

	session, err := mint()
	if err != nil {
		return "", refused
	}

	entry.used = true
	entry.session = session
	entry.digest = digest

	s.sessions[session] = &sessionEntry{
		profile: entry.profile,
		expires: s.now().Add(ReconnectGrace),
	}

	return session, admitted
}

// attach binds a carrier to a session. A second carrier for the same session is
// refused rather than accepted alongside the first: the frame stream has one
// ordering, and two sockets feeding it have none.
func (s *store) attach(token string, cancel func()) (int, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.expire()

	entry, ok := s.sessions[token]
	if !ok || entry.attached {
		return 0, false
	}

	entry.attached = true
	entry.cancel = cancel

	return entry.profile, true
}

// detach releases a carrier. The session stays for the reconnect grace, which
// is what the bridge's own retry ladder fits inside.
func (s *store) detach(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if entry, ok := s.sessions[token]; ok {
		entry.attached = false
		entry.cancel = nil
		entry.expires = s.now().Add(ReconnectGrace)
	}
}

// remove ends a session outright, cancelling its carrier. It reports whether
// anything was there, so a DELETE for a session that already went can still be
// answered as the specification requires -- idempotently, for a session this
// relay recognises.
func (s *store) remove(token string) bool {
	s.mu.Lock()

	entry, ok := s.sessions[token]
	if ok {
		delete(s.sessions, token)
	}

	s.mu.Unlock()

	if ok && entry.cancel != nil {
		entry.cancel()
	}

	return ok
}

// touch extends a live session's grace.
func (s *store) touch(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if entry, ok := s.sessions[token]; ok {
		entry.expires = s.now().Add(ReconnectGrace)
	}
}

func (s *store) countSessions() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	return len(s.sessions)
}

// expire drops what has timed out. It runs on every operation rather than on a
// timer: the map is small, the work is proportional to what is already dead,
// and a janitor goroutine would be one more thing to stop cleanly.
func (s *store) expire() {
	now := s.now()

	for token, entry := range s.bootstraps {
		// A spent bootstrap outlives its own TTL only as long as the session it
		// produced, because that is how long a retry of the creation request
		// can still arrive.
		if entry.used {
			if _, alive := s.sessions[entry.session]; !alive {
				delete(s.bootstraps, token)
			}

			continue
		}

		if entry.expires.Before(now) {
			delete(s.bootstraps, token)
		}
	}

	for token, entry := range s.sessions {
		if !entry.attached && entry.expires.Before(now) {
			delete(s.sessions, token)

			if entry.cancel != nil {
				entry.cancel()
			}
		}
	}
}
