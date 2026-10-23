package mtglib

import (
	"cmp"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"time"
)

// Per-address usage: what each source address of a shared secret has moved,
// how many connections it holds and what it is allowed, on an endpoint of its
// own, GET /secrets/{name}/clients. /stats could not carry it: the panel bills
// every key under users as a client, and one row per address there would be a
// phantom user per address. /stats carries only two counts, inside the user
// object.
//
// The list is gated exactly as connected_ips is. With track-client-ips off the
// answer is the counts alone -- how many addresses, how many connections
// overflowed -- and no address, although the table may hold entries all the
// same: a per-address control needs them to enforce, and listing them is what
// the gate is about. With it on, the addresses are listed, idle ones included:
// an entry is kept ten minutes after its address's last connection closes, so
// the list reaches further back than connected_ips, which is live connections
// only.

const (
	// defaultClientsLimit is how many addresses the list carries when the
	// request names no limit.
	defaultClientsLimit = 100

	// maxClientsLimit is the most it carries, whatever the request asks: one
	// secret holds up to maxClientsPerSecret entries, and a panel polling the
	// list must not be able to turn every poll into all of them.
	maxClientsLimit = 1000
)

// errClientsLimit is a limit the endpoint cannot read: not a whole number, or
// not above zero.
var errClientsLimit = errors.New("limit must be a whole number above zero")

// ClientUsageJSON is one address's usage on GET /secrets/{name}/clients, and
// the rest entry's: everything but the address.
//
// Connections is how many live connections the address holds right now, from
// the address ledger, which counts every stream of the address whatever entry
// it holds; for the rest entry, which has no address of its own, it is the
// streams the rest entry governs. BytesIn and BytesOut are from the client's
// side, as on the user object. ThrottledMillis is the time the address's
// streams spent held to its own limiters, absent when none. FirstSeen is when
// the entry was made and LastSeen the second the address was last seen, both
// UTC. SpeedLimit, SpeedLimitUp and SpeedLimitDown are the per-address rates in
// force, in bytes per second, absent where there is none: the combined one is
// the tighter of the address's ceiling (client-speed) and its fair share of the
// user's speed, the directional ones its fair shares of speed-up and
// speed-down. BannedUntil is when a ban on the address lapses, absent when it
// has none.
type ClientUsageJSON struct {
	Connections     int        `json:"connections"`
	BytesIn         int64      `json:"bytes_in"`
	BytesOut        int64      `json:"bytes_out"`
	ThrottledMillis int64      `json:"throttled_ms,omitempty"`
	FirstSeen       time.Time  `json:"first_seen"`
	LastSeen        time.Time  `json:"last_seen"`
	SpeedLimit      int64      `json:"speed_limit,omitempty"`
	SpeedLimitUp    int64      `json:"speed_limit_up,omitempty"`
	SpeedLimitDown  int64      `json:"speed_limit_down,omitempty"`
	BannedUntil     *time.Time `json:"banned_until,omitempty"`
}

// ClientJSON is one row of the list: an address -- an IPv4 address, or an
// IPv6 /64 in prefix form, the unit the address limit and kick count -- and
// its usage.
//
// The /64 form ("2001:db8::/64") is how the list spells the unit, not
// something kick reads back: kick takes an address, and any address inside the
// /64 -- its prefix without the "/64", say -- ends every stream of it. The bans
// routes take the /64 form as it is, as well as any address inside it.
type ClientJSON struct {
	Address string `json:"address"`

	ClientUsageJSON
}

// ClientsReport is the GET /secrets/{name}/clients body.
//
// Total is how many addresses the secret holds an entry for, the rest entry
// not counted, and Overflow how many connections were sent to the rest entry
// because the table had no room for their address; both are counts, and are
// reported whatever Tracking says. Tracking says whether the proxy lists
// addresses at all (track-client-ips). Only when it does are Rest -- the
// secret's rest entry, which every unkeyed and overflowed stream shares,
// absent when the secret has none -- and Clients -- the addresses, most bytes
// first, ties by address, at most the request's limit -- present. Clients is
// then an array, empty rather than null when there is nobody.
type ClientsReport struct {
	Total    int              `json:"total"`
	Overflow int64            `json:"overflow"`
	Tracking bool             `json:"tracking"`
	Rest     *ClientUsageJSON `json:"rest,omitempty"`
	Clients  []ClientJSON     `json:"clients,omitzero"`
}

// parseClientsLimit reads the limit query parameter: the default when it is
// absent or empty, the maximum when it is above it -- a number too large to
// read included -- and an error when it is anything but a whole number above
// zero. The API refuses a malformed request rather than guess at it, as the
// strict decoder of every request body does.
func parseClientsLimit(text string) (int, error) {
	if text == "" {
		return defaultClientsLimit, nil
	}

	// Atoi hands back the largest int with its range error for a positive
	// number too large to read, and the smallest for a negative one.
	n, err := strconv.Atoi(text)

	switch {
	case errors.Is(err, strconv.ErrRange) && n > 0:
		return maxClientsLimit, nil
	case err != nil || n <= 0:
		return 0, fmt.Errorf("%w: %q", errClientsLimit, text)
	}

	return min(n, maxClientsLimit), nil
}

// clientRow is one address entry as the report sorts it: its connection count,
// read under liveMu, and its bytes, loaded once, so the sort compares numbers
// that cannot move under it while the streams keep counting.
type clientRow struct {
	entry       *clientEntry
	connections int
	bytesIn     int64
	bytesOut    int64
}

// clientsReport is the named secret's report, at most limit addresses long.
//
// Without track-client-ips it reads the two counts and nothing else: no entry,
// no address, no ledger. With it, the entries are copied out of the table, and
// each keyed one's live connections out of the ledger, in one critical section
// -- liveMu, then the table's lock inside it, the lock order -- so the counts
// are of one moment; everything else is read from the entries' atomics after
// both locks are let go, and the answer is written after that. The rows are
// sorted once and cut to the limit after the sort, so the page is the
// addresses that moved the most whatever order the table holds them in.
func (p *Proxy) clientsReport(name string, limit int) ClientsReport {
	if !p.trackClientIPs {
		view := p.clients.view(name, false)

		return ClientsReport{Total: view.total, Overflow: view.overflow}
	}

	p.liveMu.Lock()

	view := p.clients.view(name, true)
	ledger := p.addresses[name]

	rows := make([]clientRow, len(view.entries))
	for i, entry := range view.entries {
		rows[i] = clientRow{entry: entry, connections: ledger.live(entry.key)}
	}

	p.liveMu.Unlock()

	for i := range rows {
		rows[i].bytesIn = rows[i].entry.bytesIn.Load()
		rows[i].bytesOut = rows[i].entry.bytesOut.Load()
	}

	slices.SortFunc(rows, func(a, b clientRow) int {
		if order := cmp.Compare(b.bytesIn+b.bytesOut, a.bytesIn+a.bytesOut); order != 0 {
			return order
		}

		return cmp.Compare(a.entry.key, b.entry.key)
	})

	rows = rows[:min(len(rows), limit)]

	report := ClientsReport{
		Total:    view.total,
		Overflow: view.overflow,
		Tracking: true,
		Clients:  make([]ClientJSON, len(rows)),
	}

	// The bans are read here, after liveMu was let go, under the ban list's
	// own lock alone and in one hold of it; they are not the ledger's counts,
	// and need not be of the same moment.
	bans := p.bans.untilOf(name)

	for i, row := range rows {
		report.Clients[i] = ClientJSON{
			Address:         string(row.entry.key),
			ClientUsageJSON: clientUsageOf(row.entry, row.connections, row.bytesIn, row.bytesOut),
		}

		if until, banned := bans[row.entry.key]; banned {
			until = until.UTC()
			report.Clients[i].BannedUntil = &until
		}
	}

	if view.rest != nil {
		rest := clientUsageOf(view.rest, view.restRefs, view.rest.bytesIn.Load(), view.rest.bytesOut.Load())
		report.Rest = &rest
	}

	return report
}

// clientUsageOf is an entry's usage, with the connections and bytes the caller
// already read, and the rest read from its atomics and its limiters now.
func clientUsageOf(entry *clientEntry, connections int, bytesIn, bytesOut int64) ClientUsageJSON {
	return ClientUsageJSON{
		Connections:     connections,
		BytesIn:         bytesIn,
		BytesOut:        bytesOut,
		ThrottledMillis: entry.throttledNanos.Load() / int64(time.Millisecond),
		FirstSeen:       time.Unix(entry.firstSeen.Unix(), 0).UTC(),
		LastSeen:        time.Unix(entry.lastSeen.Load(), 0).UTC(),
		SpeedLimit:      tighterRate(entry.ceiling.bytesPerSecond(), entry.fairSpeed.bytesPerSecond()),
		SpeedLimitUp:    entry.fairUp.bytesPerSecond(),
		SpeedLimitDown:  entry.fairDown.bytesPerSecond(),
	}
}

// tighterRate is the lower of two rates that both hold the same bytes, where 0
// is no limit at all.
func tighterRate(a, b int64) int64 {
	switch {
	case a == 0:
		return b
	case b == 0:
		return a
	default:
		return min(a, b)
	}
}

// handleGetClients serves GET /secrets/{name}/clients: 400 for a limit it
// cannot read, 404 for a secret the set does not have, and the report.
func (p *Proxy) handleGetClients(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")

	limit, err := parseClientsLimit(r.URL.Query().Get("limit"))
	if err != nil {
		httpError(w, http.StatusBadRequest, err)

		return
	}

	if !p.hasSecret(name) {
		httpError(w, http.StatusNotFound, fmt.Errorf("%w: %q", ErrSecretNotFound, name))

		return
	}

	writeJSON(w, http.StatusOK, p.clientsReport(name, limit))
}
