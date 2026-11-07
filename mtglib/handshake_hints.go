package mtglib

import (
	"context"
	"net"
	"net/netip"
	"slices"
	"sync"
	"time"
)

const (
	// maxScanBlocks is the largest hello, in SHA-256 blocks per candidate (see
	// fake.Parsed.Blocks), that the FakeTLS door consults hints for, and -- the
	// handshake budget's scan cap -- that it scans at all unless the budget is
	// off. 128 blocks is a record of about 8 KiB; a real client sends 0.5 to
	// 2 KiB.
	maxScanBlocks = 128

	// maxHintNames is how many secret names one address keeps, most recent
	// first, since a carrier NAT puts many users behind one address. It bounds
	// what hints can cost before the scan: at most 16 verifications of a hello
	// of at most maxScanBlocks, so 16 x 128 blocks in the worst case (192 for
	// a real client's 517-byte hello).
	maxHintNames = 16

	// maxHintAddresses bounds the addresses held across BOTH generations.
	maxHintAddresses = 32768

	// hintRotation is how often the older generation is dropped, so a hint
	// lives 30 to 60 minutes after its address last completed a handshake.
	hintRotation = 30 * time.Minute
)

// hintEntry is one address's hints: secret names, most recent first.
type hintEntry struct {
	names []string
}

// put moves name to the front, dropping the oldest name when the entry is full.
func (e *hintEntry) put(name string) {
	at := slices.Index(e.names, name)

	switch {
	case at >= 0:
	case len(e.names) < maxHintNames:
		e.names = append(e.names, "")
		at = len(e.names) - 1
	default:
		at = len(e.names) - 1
	}

	copy(e.names[1:at+1], e.names[:at])
	e.names[0] = name
}

// matchHints maps a client address to the names of the secrets that recently
// completed a FakeTLS handshake from it, so the door can verify a returning
// client's hello against those first and skip the scan. A hint is an order to
// try candidates in, never a verdict: each hinted name goes through the same
// Verify as the scan, against the candidate the name has in the snapshot the
// hello met, so a stale, removed or re-keyed name costs one verification at
// most and can never make a wrong secret match.
//
// It is written only after a handshake has fully succeeded (matched, not a
// replay, the user within its limits, admitted), so a prober can neither plant
// a hint nor read one, and recall does not refresh an entry: "last used" means
// last successfully used.
//
// Storage is two generations, like obfuscatedLimiter, with one difference that
// matters: a full cache does NOT rotate. A new address is simply not added until
// the timer drops the older generation, so someone holding a valid secret and
// many addresses can keep new hints out but never push existing ones out.
//
// Every method is safe on a nil receiver, which is "hints off".
type matchHints struct {
	mu       sync.Mutex
	current  map[netip.Addr]*hintEntry
	previous map[netip.Addr]*hintEntry
}

// newMatchHints makes a cache whose rotation runs until ctx is done.
func newMatchHints(ctx context.Context) *matchHints {
	h := &matchHints{current: make(map[netip.Addr]*hintEntry)}

	go h.run(ctx)

	return h
}

func (h *matchHints) run(ctx context.Context) {
	ticker := time.NewTicker(hintRotation)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			h.rotate()
		}
	}
}

// rotate drops the older generation and demotes the current one.
func (h *matchHints) rotate() {
	if h == nil {
		return
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	h.previous = h.current
	h.current = make(map[netip.Addr]*hintEntry)
}

// hintKey is the key an address's hints are kept under: limiterKey's (the
// address for IPv4, the /64 for IPv6, v4-mapped addresses unmapped), or false
// for an address that does not stand for one place. Loopback, private,
// link-local, unspecified and multicast are refused: behind a carrier that does
// not forward the client address every client presents the same one, and a
// shared key would hand every client every other client's hints. The class is
// read off the whole, unmapped address, before limiterKey masks an IPv6 one.
func hintKey(ip net.IP) (netip.Addr, bool) {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return netip.Addr{}, false
	}

	addr = addr.Unmap()

	if addr.IsLoopback() || addr.IsPrivate() || addr.IsLinkLocalUnicast() ||
		addr.IsUnspecified() || addr.IsMulticast() {
		return netip.Addr{}, false
	}

	return limiterKey(ip)
}

// recall returns a copy of the names ip's place matched recently, most recent
// first; nil when it has none or is unkeyed.
func (h *matchHints) recall(ip net.IP) []string {
	if h == nil {
		return nil
	}

	key, ok := hintKey(ip)
	if !ok {
		return nil
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	entry, ok := h.current[key]
	if !ok {
		entry, ok = h.previous[key]
	}

	if !ok {
		return nil
	}

	return slices.Clone(entry.names)
}

// remember records that name just completed a handshake from ip's place. An
// address already held is always updated (and moved to the current generation
// if it was in the older one); a new address is dropped when the two
// generations together hold maxHintAddresses.
func (h *matchHints) remember(ip net.IP, name string) {
	if h == nil || name == "" {
		return
	}

	key, ok := hintKey(ip)
	if !ok {
		return
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	entry, ok := h.current[key]
	if !ok {
		entry, ok = h.previous[key]

		switch {
		case ok:
			// Moved, not copied: the address is counted once either way.
			delete(h.previous, key)
		case len(h.current)+len(h.previous) >= maxHintAddresses:
			return
		default:
			entry = &hintEntry{}
		}

		h.current[key] = entry
	}

	entry.put(name)
}
