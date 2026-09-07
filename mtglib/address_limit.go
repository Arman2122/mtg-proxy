package mtglib

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"time"
)

// Address limits: how many places a user may be at once.
//
// A user's counted addresses are the union of two sets. The LOCAL set is the
// addresses holding a live connection on this proxy, refcounted per address
// so it empties the instant the last connection from a place ends. The
// EXTERNAL set is the addresses some other system -- a panel that also runs
// the user's VPN and SSH -- has reported the user present at, each entry
// carrying an expiry so a panel that dies takes its claims with it instead
// of pinning a phantom device forever.
//
// A new connection from an address already in either set is always admitted:
// a second socket from the same phone is the same device. From an address in
// neither, it is admitted only while the union is below the limit. The check
// and the registration are one critical section under Proxy.liveMu, so two
// new addresses arriving together cannot both read "one below the limit" and
// both get in; and the slot is released by the same unregisterConn that
// releases the connection, so a slot cannot leak without the connection
// leaking too.
//
// The set is pushed to the proxy, never pulled by it. No network call sits in
// the handshake, and a panel that is down degrades this to a local-only
// limit rather than to a refusal of everyone.
//
// Nothing here is logged, persisted or exported except through the API, and
// there only the counts unless the proxy was configured to report addresses
// at all (ProxyOpts.TrackClientIPs).

const (
	// ipv6AddressPrefixBits is the unit an IPv6 address is counted at. Hosts
	// rotate the low 64 bits (RFC 8981 privacy extensions), so counting each
	// address would charge one phone for a dozen devices; the /64 is the
	// network the device is on, which is what "a place" means here.
	ipv6AddressPrefixBits = 64

	// DefaultExternalAddressTTL is how long an externally reported address
	// counts when the report names no ttl. A panel is expected to refresh
	// well inside it.
	DefaultExternalAddressTTL = 2 * time.Minute

	// MaxExternalAddressTTL bounds a report's ttl, so a mistaken or hostile
	// panel cannot pin a user's slots for a day.
	MaxExternalAddressTTL = time.Hour

	// MaxExternalAddresses bounds one report, which bounds what one user's
	// ledger can hold.
	MaxExternalAddresses = 64
)

// ErrExternalAddresses is wrapped by every validation failure of an external
// address report, so the API can map all of them to one status.
var ErrExternalAddresses = errors.New("invalid external addresses")

// addressKey is the unit an address limit counts: an IPv4 address (a
// v4-mapped IPv6 address collapses to it) or an IPv6 /64.
type addressKey string

// addressKeyOf normalises an address into the unit the limit counts. It is
// false when there is no address to count -- a listener whose PROXY header
// declared no TCP source, or an embedder's conn with no IP behind it.
func addressKeyOf(ip net.IP) (addressKey, bool) {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return "", false
	}

	return keyOfAddr(addr), true
}

func keyOfAddr(addr netip.Addr) addressKey {
	addr = addr.Unmap()
	if addr.Is4() {
		return addressKey(addr.String())
	}

	// Prefix cannot fail for a valid address and a bit count within it.
	prefix, _ := addr.Prefix(ipv6AddressPrefixBits)

	return addressKey(prefix.String())
}

// externalEntry is one reported address: when it stops counting, and the
// spelling it was reported with, so a report reads back as it was written.
type externalEntry struct {
	expiresAt time.Time
	text      string
}

// addressLedger is one user's counted addresses. Every method assumes the
// caller holds Proxy.liveMu; the ledger has no lock of its own precisely so
// that admission and registration are one critical section.
type addressLedger struct {
	local    map[addressKey]int
	external map[addressKey]externalEntry
}

func newAddressLedger() *addressLedger {
	return &addressLedger{
		local:    make(map[addressKey]int),
		external: make(map[addressKey]externalEntry),
	}
}

// prune drops external entries that have expired. Expiry is evaluated here,
// lazily, on every read and admission; there is no sweeper to fall behind.
func (l *addressLedger) prune(now time.Time) {
	for key, entry := range l.external {
		if !now.Before(entry.expiresAt) {
			delete(l.external, key)
		}
	}
}

// has reports whether the address already counts, from either set.
func (l *addressLedger) has(key addressKey, now time.Time) bool {
	if l.local[key] > 0 {
		return true
	}

	entry, ok := l.external[key]

	return ok && now.Before(entry.expiresAt)
}

// counted is the size of the union: distinct addresses across both sets.
func (l *addressLedger) counted(now time.Time) int {
	l.prune(now)

	n := len(l.local)

	for key := range l.external {
		if l.local[key] == 0 {
			n++
		}
	}

	return n
}

// admit counts one more connection from key, or refuses it. A limit of zero
// is no limit, and the connection is still counted so a limit set later
// starts from the truth rather than from zero.
func (l *addressLedger) admit(key addressKey, limit int, now time.Time) bool {
	if limit > 0 && !l.has(key, now) && l.counted(now) >= limit {
		return false
	}

	l.local[key]++

	return true
}

// release undoes one admit.
func (l *addressLedger) release(key addressKey) {
	if l.local[key] <= 1 {
		delete(l.local, key)

		return
	}

	l.local[key]--
}

// setExternal replaces the external set. Every entry gets the same expiry:
// a report is one observation of where the user is, refreshed as a whole.
func (l *addressLedger) setExternal(addrs []netip.Addr, expiresAt time.Time) {
	l.external = make(map[addressKey]externalEntry, len(addrs))

	for _, addr := range addrs {
		l.external[keyOfAddr(addr)] = externalEntry{expiresAt: expiresAt, text: addr.String()}
	}
}

// idle reports whether the ledger holds nothing and can be dropped.
func (l *addressLedger) idle(now time.Time) bool {
	l.prune(now)

	return len(l.local) == 0 && len(l.external) == 0
}

// externalAddresses lists the unexpired reported addresses, sorted, with the
// single expiry they share. Nil when there are none.
func (l *addressLedger) externalAddresses(now time.Time) ([]string, time.Time) {
	l.prune(now)

	if len(l.external) == 0 {
		return nil, time.Time{}
	}

	var (
		out       = make([]string, 0, len(l.external))
		expiresAt time.Time
	)

	for _, entry := range l.external {
		out = append(out, entry.text)

		if entry.expiresAt.After(expiresAt) {
			expiresAt = entry.expiresAt
		}
	}

	sort.Strings(out)

	return out, expiresAt
}

// ledgerLocked returns the named user's ledger, creating it on first use.
// Caller holds liveMu.
func (p *Proxy) ledgerLocked(name string) *addressLedger {
	if p.addresses == nil {
		p.addresses = make(map[string]*addressLedger)
	}

	ledger := p.addresses[name]
	if ledger == nil {
		ledger = newAddressLedger()
		p.addresses[name] = ledger
	}

	return ledger
}

// dropLedgerIfIdleLocked forgets a ledger that counts nothing, so a user who
// left costs no memory and does not linger in reports. Caller holds liveMu.
func (p *Proxy) dropLedgerIfIdleLocked(name string, now time.Time) {
	if ledger := p.addresses[name]; ledger != nil && ledger.idle(now) {
		delete(p.addresses, name)
	}
}

// ParseExternalAddresses validates one report as the API receives it: at
// most MaxExternalAddresses distinct addresses, each a literal IP with no
// zone, and a ttl within (0, MaxExternalAddressTTL], with an empty ttl
// meaning DefaultExternalAddressTTL. Every failure wraps
// ErrExternalAddresses.
func ParseExternalAddresses(ips []string, ttl string) ([]netip.Addr, time.Duration, error) {
	if len(ips) > MaxExternalAddresses {
		return nil, 0, fmt.Errorf("%w: %d addresses, the most is %d",
			ErrExternalAddresses, len(ips), MaxExternalAddresses)
	}

	addrs := make([]netip.Addr, 0, len(ips))

	for _, text := range ips {
		addr, err := netip.ParseAddr(text)
		if err != nil {
			return nil, 0, fmt.Errorf("%w: %q is not an IP address", ErrExternalAddresses, text)
		}

		if addr.Zone() != "" {
			return nil, 0, fmt.Errorf("%w: %q carries a zone", ErrExternalAddresses, text)
		}

		addrs = append(addrs, addr)
	}

	duration := DefaultExternalAddressTTL

	if ttl != "" {
		parsed, err := time.ParseDuration(ttl)
		if err != nil {
			return nil, 0, fmt.Errorf("%w: ttl %q: %w", ErrExternalAddresses, ttl, err)
		}

		if parsed <= 0 || parsed > MaxExternalAddressTTL {
			return nil, 0, fmt.Errorf("%w: ttl %q is outside (0, %s]",
				ErrExternalAddresses, ttl, MaxExternalAddressTTL)
		}

		duration = parsed
	}

	return addrs, duration, nil
}

// SetExternalAddresses replaces the addresses the named user is reported to
// hold elsewhere. They count against the user's ip limit alongside the
// addresses of their live connections here, until ttl passes or the next
// report replaces them. An empty list clears the set. The secret must exist.
func (p *Proxy) SetExternalAddresses(name string, addrs []netip.Addr, ttl time.Duration) error {
	if !p.hasSecret(name) {
		return fmt.Errorf("%w: %q", ErrSecretNotFound, name)
	}

	now := time.Now()

	p.liveMu.Lock()
	defer p.liveMu.Unlock()

	p.ledgerLocked(name).setExternal(addrs, now.Add(ttl))
	p.dropLedgerIfIdleLocked(name, now)

	return nil
}

// AddressReport is the address view of one user: how many places they count
// as being in right now, and -- only when the proxy is configured to report
// addresses at all -- which. IPLimit is filled in by the caller that knows
// the secret set.
type AddressReport struct {
	Name string `json:"name"`

	// IPLimit is the configured limit, or absent for none.
	IPLimit int `json:"ip_limit,omitempty"`

	// ActiveIPs is the number of distinct addresses counted right now: those
	// holding a live connection here plus those reported from elsewhere. It
	// is a count, so it is never gated.
	ActiveIPs int `json:"active_ips,omitempty"`

	// ConnectedIPs and ExternalIPs are the addresses themselves, present
	// only with track-client-ips, for the reason ProxyOpts.TrackClientIPs
	// gives. ExternalExpiresAt is when the reported set stops counting
	// unless it is refreshed first.
	ConnectedIPs      []string   `json:"connected_ips,omitempty"`
	ExternalIPs       []string   `json:"external_ips,omitempty"`
	ExternalExpiresAt *time.Time `json:"external_expires_at,omitempty"`

	// ConnectedIPsLastSeen is when each connected address last moved a byte,
	// gated as ConnectedIPs is.
	ConnectedIPsLastSeen map[string]time.Time `json:"connected_ips_last_seen,omitempty"`
}

// addressReports snapshots every user's address view. Like connectedIPs, it
// collects under liveMu and resolves addresses outside it, because ClientIP
// takes a lock of its own and a stats scrape must not create that edge.
func (p *Proxy) addressReports() map[string]AddressReport {
	now := time.Now()

	type ledgerView struct {
		active   int
		external []string
		expires  time.Time
	}

	p.liveMu.Lock()

	contexts := make(map[string][]*streamContext, len(p.liveConns))

	for name, conns := range p.liveConns {
		list := make([]*streamContext, 0, len(conns))
		for sc := range conns {
			list = append(list, sc)
		}

		contexts[name] = list
	}

	views := make(map[string]ledgerView, len(p.addresses))

	for name, ledger := range p.addresses {
		view := ledgerView{active: ledger.counted(now)}
		view.external, view.expires = ledger.externalAddresses(now)
		views[name] = view

		p.dropLedgerIfIdleLocked(name, now)
	}

	p.liveMu.Unlock()

	rv := make(map[string]AddressReport, len(views))

	for name, view := range views {
		report := AddressReport{Name: name, ActiveIPs: view.active}

		if p.trackClientIPs {
			report.ConnectedIPs, report.ConnectedIPsLastSeen = clientAddressActivity(contexts[name])
			report.ExternalIPs = view.external

			if !view.expires.IsZero() {
				expires := view.expires
				report.ExternalExpiresAt = &expires
			}
		}

		rv[name] = report
	}

	return rv
}

// clientAddressActivity is the sorted, deduplicated address list of a set of
// streams, with the second each address last moved a byte: the latest across
// the streams sharing it, so a device that fell silent reads as silent while
// its sibling talks. Sorted because map iteration is randomised per run, and
// two scrapes of an unchanged proxy must not differ. A stream never stamped
// (one not yet admitted) lists its address with no time.
func clientAddressActivity(contexts []*streamContext) ([]string, map[string]time.Time) {
	seen := make(map[string]struct{}, len(contexts))
	addresses := make([]string, 0, len(contexts))

	var lastSeen map[string]time.Time

	for _, sc := range contexts {
		ip := sc.ClientIP()
		if ip == nil {
			continue
		}

		text := ip.String()
		if _, ok := seen[text]; !ok {
			seen[text] = struct{}{}

			addresses = append(addresses, text)
		}

		if unix := sc.lastActiveUnix.Load(); unix > 0 {
			if lastSeen == nil {
				lastSeen = make(map[string]time.Time)
			}

			if at := time.Unix(unix, 0).UTC(); at.After(lastSeen[text]) {
				lastSeen[text] = at
			}
		}
	}

	if len(addresses) == 0 {
		return nil, nil
	}

	sort.Strings(addresses)

	return addresses, lastSeen
}
