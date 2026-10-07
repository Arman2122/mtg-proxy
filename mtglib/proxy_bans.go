package mtglib

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Bans: an operator who has found an abusive address refuses it a secret for a
// while. Kick ends the streams a place already holds and the device reconnects
// at once; a ban ends them too, and refuses the place the secret until the ban
// lapses or is lifted.
//
// A ban is an operator's action, so it is held at the unit kick acts on
// (addressKey: an IPv4 address, or an IPv6 /64), whatever the automatic
// per-address controls make of the address. An address that does not stand for
// one place -- loopback, private and the like, which behind a front or a
// PROXY-protocol listener is every client at once -- is banned only when the
// request says force.
//
// Bans live in memory only, bounded and TTL-bound. They survive a reload, which
// rebuilds the secret set and not the proxy, and a re-key, which is the same
// user under a new key; they go with their secret when it is removed and with
// the process when it stops. Nothing is written to the usage-state file, where
// any key that is not a secret's would be billed as one.

const (
	// DefaultBanTTL is how long a ban lasts when the request names no ttl.
	DefaultBanTTL = time.Hour

	// MaxBanTTL bounds a ban's ttl. A ban is a short-term tool; a leaked link
	// is retired by re-keying the secret.
	MaxBanTTL = 30 * 24 * time.Hour

	// maxBans is how many bans the proxy holds across every secret. A ban is
	// an operator's action, so a full list refuses the next one loudly rather
	// than evict one the operator already made.
	maxBans = 4096
)

var (
	// ErrBanAddresses is wrapped by every validation failure of a ban
	// request, so the API can map all of them to one status.
	ErrBanAddresses = errors.New("invalid ban addresses")

	// ErrBanListFull is a ban request that would take the list past maxBans.
	ErrBanListFull = errors.New("ban list full")
)

// banList is every secret's bans: when each banned place's ban lapses. Its lock
// is banMu in the lock order, inner to liveMu: a ban is recorded under liveMu,
// so that recording it and finding the streams to close are one critical
// section against admission, and admission re-checks it under liveMu. Every
// other read takes banMu alone.
//
// Expired bans are pruned lazily: a check that finds one drops it, and every
// change and every listing prunes the whole list first, so a lapsed ban never
// holds a slot a new one needs. The list is at most maxBans long.
//
// The zero value is an empty list on the real clock, so a Proxy{} literal in a
// test has one, and with nothing banned nothing is refused.
type banList struct {
	mu sync.Mutex

	// now is the clock bans are set and lapse by, time.Now when nil; a test
	// injects its own.
	now func() time.Time

	// bans maps a secret's name to its banned places and when each ban
	// lapses. A secret with no ban has no map.
	bans map[string]map[addressKey]time.Time

	// held is how many bans the maps hold, lapsed ones not yet pruned
	// included. Written under mu; read without it as a fast path, so that a
	// proxy with no bans pays one atomic load to know a place is not banned.
	held atomic.Int64
}

// clock is the list's now.
func (l *banList) clock() time.Time {
	if l.now != nil {
		return l.now()
	}

	return time.Now()
}

// banned reports whether key's place is banned from the named secret now. A
// ban found lapsed is dropped.
func (l *banList) banned(name string, key addressKey) bool {
	if l.held.Load() == 0 {
		return false
	}

	now := l.clock()

	l.mu.Lock()
	defer l.mu.Unlock()

	until, ok := l.bans[name][key]

	switch {
	case !ok:
		return false
	case now.Before(until):
		return true
	default:
		l.deleteLocked(name, key)

		return false
	}
}

// deleteLocked drops one ban, and the secret's map with its last. Caller holds
// mu.
func (l *banList) deleteLocked(name string, key addressKey) bool {
	secret := l.bans[name]
	if _, ok := secret[key]; !ok {
		return false
	}

	delete(secret, key)

	if len(secret) == 0 {
		delete(l.bans, name)
	}

	l.held.Add(-1)

	return true
}

// pruneLocked drops every ban that has lapsed by now. Caller holds mu.
func (l *banList) pruneLocked(now time.Time) {
	for name, secret := range l.bans {
		for key, until := range secret {
			if !now.Before(until) {
				l.deleteLocked(name, key)
			}
		}
	}
}

// add bans each of keys from the named secret for ttl from now, and says how
// many places that is. It is all or nothing: a request that would take the
// list past maxBans, lapsed bans not counted, bans none of its places and
// wraps ErrBanListFull. A place banned already takes no new slot; its ban now
// lapses when this one does.
func (l *banList) add(name string, keys []addressKey, ttl time.Duration) (int, error) {
	now := l.clock()
	until := now.Add(ttl)

	l.mu.Lock()
	defer l.mu.Unlock()

	l.pruneLocked(now)

	secret := l.bans[name]
	places := make(map[addressKey]struct{}, len(keys))
	fresh := 0

	for _, key := range keys {
		if _, seen := places[key]; seen {
			continue
		}

		places[key] = struct{}{}

		if _, held := secret[key]; !held {
			fresh++
		}
	}

	if held := int(l.held.Load()); held+fresh > maxBans {
		return 0, fmt.Errorf("%w: %d bans held, %d more asked for, the most is %d",
			ErrBanListFull, held, fresh, maxBans)
	}

	if secret == nil {
		if l.bans == nil {
			l.bans = make(map[string]map[addressKey]time.Time)
		}

		secret = make(map[addressKey]time.Time, len(places))
		l.bans[name] = secret
	}

	for key := range places {
		secret[key] = until
	}

	l.held.Add(int64(fresh))

	return len(places), nil
}

// remove lifts the named secret's ban of key's place, and says whether there
// was one.
func (l *banList) remove(name string, key addressKey) bool {
	now := l.clock()

	l.mu.Lock()
	defer l.mu.Unlock()

	l.pruneLocked(now)

	return l.deleteLocked(name, key)
}

// list is the named secret's bans in force, by address.
func (l *banList) list(name string) []BanJSON {
	now := l.clock()

	l.mu.Lock()
	defer l.mu.Unlock()

	l.pruneLocked(now)

	out := make([]BanJSON, 0, len(l.bans[name]))
	for key, until := range l.bans[name] {
		out = append(out, BanJSON{Address: string(key), ExpiresAt: until.UTC()})
	}

	slices.SortFunc(out, func(a, b BanJSON) int { return strings.Compare(a.Address, b.Address) })

	return out
}

// count is how many of the named secret's bans are in force.
func (l *banList) count(name string) int {
	now := l.clock()

	l.mu.Lock()
	defer l.mu.Unlock()

	l.pruneLocked(now)

	return len(l.bans[name])
}

// untilOf is when each of the named secret's bans in force lapses, copied under
// one hold of the lock, so a caller can look up many places without holding
// it. Nil when the secret has none.
func (l *banList) untilOf(name string) map[addressKey]time.Time {
	now := l.clock()

	l.mu.Lock()
	defer l.mu.Unlock()

	l.pruneLocked(now)

	secret := l.bans[name]
	if len(secret) == 0 {
		return nil
	}

	out := make(map[addressKey]time.Time, len(secret))
	for key, until := range secret {
		out[key] = until
	}

	return out
}

// dropSecret forgets every ban of a secret that was removed. A re-keyed secret
// keeps its name, and with it its bans.
func (l *banList) dropSecret(name string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.held.Add(-int64(len(l.bans[name])))
	delete(l.bans, name)
}

// parseBanAddress reads one place a ban request names: a literal IP address
// with no zone, or an IPv6 /64 in prefix form, as GET /clients and GET /bans
// spell an IPv6 place. A prefix comes back as its first address, which is the
// same place. Any other prefix is refused: a ban is of one place, and a range
// is not one.
func parseBanAddress(text string) (netip.Addr, error) {
	if addr, err := netip.ParseAddr(text); err == nil {
		if addr.Zone() != "" {
			return netip.Addr{}, fmt.Errorf("%w: %q carries a zone", ErrBanAddresses, text)
		}

		return addr, nil
	}

	prefix, err := netip.ParsePrefix(text)
	if err != nil || !prefix.Addr().Is6() || prefix.Addr().Is4In6() || prefix.Bits() != ipv6AddressPrefixBits {
		return netip.Addr{}, fmt.Errorf("%w: %q is neither an IP address nor an IPv6 /%d",
			ErrBanAddresses, text, ipv6AddressPrefixBits)
	}

	return prefix.Masked().Addr(), nil
}

// ParseBanAddresses validates a ban request as the API receives it: at least
// one place, each a literal IP address or an IPv6 /64 (parseBanAddress); a ttl
// within (0, MaxBanTTL], with an empty one meaning DefaultBanTTL; and, unless
// force is set, no address that does not stand for one place (clientKeyed:
// loopback, private, link-local, unspecified, multicast), because behind a
// front or a PROXY-protocol listener one such address is every client. Every
// failure wraps ErrBanAddresses.
func ParseBanAddresses(ips []string, ttl string, force bool) ([]netip.Addr, time.Duration, error) {
	if len(ips) == 0 {
		return nil, 0, fmt.Errorf("%w: no addresses", ErrBanAddresses)
	}

	addrs := make([]netip.Addr, 0, len(ips))

	for _, text := range ips {
		addr, err := parseBanAddress(text)
		if err != nil {
			return nil, 0, err
		}

		if !force && !clientKeyed(net.IP(addr.AsSlice())) {
			return nil, 0, fmt.Errorf(
				"%w: %q does not stand for one place, and behind a front or a PROXY-protocol listener "+
					`it can be every client; send "force": true to ban it anyway`, ErrBanAddresses, text)
		}

		addrs = append(addrs, addr)
	}

	duration := DefaultBanTTL

	if ttl != "" {
		parsed, err := time.ParseDuration(ttl)
		if err != nil {
			return nil, 0, fmt.Errorf("%w: ttl %q: %w", ErrBanAddresses, ttl, err)
		}

		if parsed <= 0 || parsed > MaxBanTTL {
			return nil, 0, fmt.Errorf("%w: ttl %q is outside (0, %s]", ErrBanAddresses, ttl, MaxBanTTL)
		}

		duration = parsed
	}

	return addrs, duration, nil
}

// BanResult is the POST /secrets/{name}/bans answer: how many places were
// banned, how many live streams the ban closed, and -- only with
// track-client-ips, as PUT external-ips echoes what it was sent -- the places,
// in the unit they are held at, sorted.
type BanResult struct {
	Banned    int      `json:"banned"`
	Closed    int      `json:"closed"`
	Addresses []string `json:"addresses,omitempty"`
}

// Ban bans each of addrs from the named secret for ttl, closes every live
// stream the secret has at those places, and forgets the secret's hints there.
// A place is matched at the unit kick matches, so an IPv6 address bans its /64.
// The secret must exist; ttl must be within (0, MaxBanTTL].
//
// The bans are recorded and the streams found in one critical section under
// liveMu, the lock admission registers a stream under, so no stream registers
// between the ban and the kick: one that registered first is found and closed,
// and one that registers after meets the ban. The streams are closed after the
// lock is let go, as Kick closes them, because each stream's own unregister
// takes the lock too. Whether the secret exists is decided under the same lock:
// a reload swaps its set in before it takes liveMu to drop a removed secret's
// bans, so a ban recorded here for a secret the set still has is dropped by
// that reload if it removes it, and a secret already gone is not banned.
func (p *Proxy) Ban(name string, addrs []netip.Addr, ttl time.Duration) (BanResult, error) {
	if ttl <= 0 || ttl > MaxBanTTL {
		return BanResult{}, fmt.Errorf("%w: ttl %s is outside (0, %s]", ErrBanAddresses, ttl, MaxBanTTL)
	}

	keys := make([]addressKey, 0, len(addrs))
	places := make(map[addressKey]struct{}, len(addrs))

	for _, addr := range addrs {
		key := keyOfAddr(addr)
		if _, seen := places[key]; !seen {
			places[key] = struct{}{}
			keys = append(keys, key)
		}
	}

	p.liveMu.Lock()

	if _, ok := p.secrets.Load().limitsOf(name); !ok {
		p.liveMu.Unlock()

		return BanResult{}, fmt.Errorf("%w: %q", ErrSecretNotFound, name)
	}

	banned, err := p.bans.add(name, keys, ttl)
	if err != nil {
		p.liveMu.Unlock()

		return BanResult{}, err
	}

	closing := p.streamsAtLocked(name, places)

	p.liveMu.Unlock()

	for _, sc := range closing {
		sc.Close()
	}

	// A hint is an order to try a secret in, earned by a handshake that got
	// all the way through; a banned place can no longer earn one for this
	// secret, and must not be verified against it first on the strength of
	// one it earned before.
	for _, addr := range addrs {
		p.hints.forget(net.IP(addr.AsSlice()), name)
	}

	p.logger.BindStr("secret_name", name).BindInt("banned", banned).BindInt("closed", len(closing)).
		Info("addresses banned through the API")

	result := BanResult{Banned: banned, Closed: len(closing)}

	if p.trackClientIPs {
		result.Addresses = make([]string, len(keys))
		for i, key := range keys {
			result.Addresses[i] = string(key)
		}

		slices.Sort(result.Addresses)
	}

	return result, nil
}

// Unban lifts the named secret's ban of addr's place, and says whether there
// was one. The secret must exist; a place with no ban is lifted of nothing,
// which is not an error. It takes banMu alone: lifting a ban can only let a
// stream in that a ban kept out, and admission has nothing to agree on with it.
func (p *Proxy) Unban(name string, addr netip.Addr) (bool, error) {
	if _, ok := p.secrets.Load().limitsOf(name); !ok {
		return false, fmt.Errorf("%w: %q", ErrSecretNotFound, name)
	}

	removed := p.bans.remove(name, keyOfAddr(addr))
	if removed {
		p.logger.BindStr("secret_name", name).Info("ban lifted through the API")
	}

	return removed, nil
}

// BanJSON is one ban on GET /secrets/{name}/bans: the banned place, an IPv4
// address or an IPv6 /64 in prefix form, and the moment the ban lapses, UTC.
type BanJSON struct {
	Address   string    `json:"address"`
	ExpiresAt time.Time `json:"expires_at"`
}

// BansReport is the GET /secrets/{name}/bans body, gated as external_ips is:
// Total, the number of the secret's bans in force, is a count and is reported
// whatever Tracking says; Bans, by address, is present only when the proxy
// lists addresses at all (track-client-ips), and is then an array, empty
// rather than null when there are none.
type BansReport struct {
	Total    int       `json:"total"`
	Tracking bool      `json:"tracking"`
	Bans     []BanJSON `json:"bans,omitzero"`
}

// bansReport is the named secret's report.
func (p *Proxy) bansReport(name string) BansReport {
	if !p.trackClientIPs {
		return BansReport{Total: p.bans.count(name)}
	}

	bans := p.bans.list(name)

	return BansReport{Total: len(bans), Tracking: true, Bans: bans}
}

// banRequest is the POST /secrets/{name}/bans body: the places, how long, and
// whether a place that does not stand for one place may be banned all the same.
type banRequest struct {
	IPs   []string `json:"ips"`
	TTL   string   `json:"ttl,omitempty"`
	Force bool     `json:"force,omitempty"`
}

// UnbanResult is the DELETE /secrets/{name}/bans/{address...} answer: 1 when a
// ban was lifted, 0 when the place had none.
type UnbanResult struct {
	Removed int `json:"removed"`
}

// handleBan serves POST /secrets/{name}/bans: 400 for a request it cannot
// read, 404 for a secret the set does not have, 409 when the list is full.
func (p *Proxy) handleBan(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")

	var req banRequest
	if !decodeJSON(w, r, &req) {
		return
	}

	addrs, ttl, err := ParseBanAddresses(req.IPs, req.TTL, req.Force)
	if err != nil {
		httpError(w, http.StatusBadRequest, err)

		return
	}

	result, err := p.Ban(name, addrs, ttl)
	if err != nil {
		httpError(w, secretMutationStatus(err), err)

		return
	}

	writeJSON(w, http.StatusOK, result)
}

// handleGetBans serves GET /secrets/{name}/bans: 404 for a secret the set does
// not have, and the report.
func (p *Proxy) handleGetBans(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")

	if _, ok := p.secrets.Load().limitsOf(name); !ok {
		httpError(w, http.StatusNotFound, fmt.Errorf("%w: %q", ErrSecretNotFound, name))

		return
	}

	writeJSON(w, http.StatusOK, p.bansReport(name))
}

// handleUnban serves DELETE /secrets/{name}/bans/{address...}. The address is a
// wildcard segment, so the /64 form's slash needs no escaping. 400 for an
// address it cannot read, 404 for a secret the set does not have, and 200 with
// how many bans were lifted otherwise: lifting a ban that is not there is
// idempotent, as DELETE external-ips is.
func (p *Proxy) handleUnban(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")

	addr, err := parseBanAddress(r.PathValue("address"))
	if err != nil {
		httpError(w, http.StatusBadRequest, err)

		return
	}

	removed, err := p.Unban(name, addr)
	if err != nil {
		httpError(w, secretMutationStatus(err), err)

		return
	}

	result := UnbanResult{}
	if removed {
		result.Removed = 1
	}

	writeJSON(w, http.StatusOK, result)
}
