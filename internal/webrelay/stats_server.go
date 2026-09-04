package webrelay

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"
)

// StatsPath is the only path the stats server answers.
const StatsPath = "/stats"

// ErrStatsBindNotLoopback means an operator asked for the stats socket on an
// address other people can reach.
var ErrStatsBindNotLoopback = errors.New("the WEB relay stats address must be a loopback address")

// StatsHandler serves the relay's own counters as JSON.
//
// It is a SEPARATE http.Server on a SEPARATE listener, and that is the whole
// design rather than an implementation detail. The relay's public origin lives
// behind a front proxy that publishes it to the internet, and it holds one
// invariant: anything not carrying a credential this relay minted is answered
// by the cover site, on every path. A real endpoint on that origin breaks it --
// a 401, or a JSON body, or even a distinctive response time, is a signal that
// this hostname is not the website it is pretending to be. Token-gating would
// not help; the gate itself is the fingerprint.
//
// So the counters live on a socket the front proxy does not know about, bound
// to loopback, and the public origin never learns this exists.
type StatsHandler struct {
	counters *Counters
	store    *store
	now      func() time.Time
}

// NewStatsHandler builds the handler over one relay's counters and store.
func NewStatsHandler(counters *Counters, store *store, now func() time.Time) *StatsHandler {
	if now == nil {
		now = time.Now
	}

	return &StatsHandler{counters: counters, store: store, now: now}
}

func (h *StatsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != StatsPath {
		http.NotFound(w, r)

		return
	}

	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "only GET is allowed", http.StatusMethodNotAllowed)

		return
	}

	var (
		maxSessions int
		active      int
	)

	if h.store != nil {
		maxSessions = h.store.maxSessions
		active = h.store.countSessions()
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")

	if err := json.NewEncoder(w).Encode(h.counters.Snapshot(h.now(), maxSessions, active)); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// ValidateStatsBind refuses a stats address that is not loopback.
//
// Refused rather than warned about. This socket answers, without any
// credential, how many sessions a relay is carrying and how many bytes it has
// moved -- which is exactly the traffic analysis the transport exists to deny
// anyone. An operator who typed 0.0.0.0 has published that, and would have no
// reason to look at a warning in a log to find out.
//
// An empty address means the stats server is off, which is the default.
func ValidateStatsBind(addr string) error {
	if addr == "" {
		return nil
	}

	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("cannot parse the WEB relay stats address %q: %w", addr, err)
	}

	ip := net.ParseIP(host)
	if ip == nil {
		// A name could resolve anywhere, and could resolve somewhere else
		// tomorrow. There is no reading of "localhost" this can safely accept
		// without a lookup whose answer it cannot pin.
		return fmt.Errorf("%w: %q is not an IP address", ErrStatsBindNotLoopback, addr)
	}

	if !ip.IsLoopback() {
		return fmt.Errorf("%w: %q is reachable from outside this host", ErrStatsBindNotLoopback, addr)
	}

	return nil
}
