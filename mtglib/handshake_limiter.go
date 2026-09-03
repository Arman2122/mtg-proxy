package mtglib

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// maxTrackedHandshakeIPs bounds the memory one limiter may hold. It is a cap
	// per generation, so the worst case is twice this many buckets.
	maxTrackedHandshakeIPs = 65536

	// handshakeBucketRotation is how long an idle bucket may survive. Rotation
	// is what makes this an approximate LRU instead of an unbounded map.
	handshakeBucketRotation = 10 * time.Minute

	// handshakeBurstFactor is the burst allowance as a multiple of the
	// per-second refill rate.
	handshakeBurstFactor = 2

	// ipv6BucketPrefix keys IPv6 peers on their /64 -- a single host is routinely
	// handed that whole range, so a per-address bucket would be free to evade.
	ipv6BucketPrefix = 64
)

// obfuscatedCounters are the obfuscated2 entry counters. They live on Proxy
// rather than on ProxyStats because the /stats surface belongs to a separate
// change; the reporting side reads these fields with Load().
type obfuscatedCounters struct {
	trials      atomic.Int64
	misses      atomic.Int64
	denied      atomic.Int64
	draining    atomic.Int64
	rateLimited atomic.Int64
}

// OnObfuscatedTrial counts one connection that entered the trial-decryption
// loop.
func (c *obfuscatedCounters) OnObfuscatedTrial() { c.trials.Add(1) }

// OnObfuscatedMiss counts one connection no configured secret decrypted.
func (c *obfuscatedCounters) OnObfuscatedMiss() { c.misses.Add(1) }

// OnObfuscatedDenied counts one connection disposed of by denyObfuscated,
// whatever the reason -- the reasons are deliberately not separated, because
// they must not be distinguishable to the peer either.
func (c *obfuscatedCounters) OnObfuscatedDenied() { c.denied.Add(1) }

// OnObfuscatedRateLimited counts one connection refused by the per-IP failure
// budget before it reached the loop.
func (c *obfuscatedCounters) OnObfuscatedRateLimited() { c.rateLimited.Add(1) }

// OnObfuscatedDrainStart and OnObfuscatedDrainEnd maintain a gauge of the
// connections currently sitting in a bounded drain.
func (c *obfuscatedCounters) OnObfuscatedDrainStart() { c.draining.Add(1) }

// OnObfuscatedDrainEnd is the counterpart of OnObfuscatedDrainStart.
func (c *obfuscatedCounters) OnObfuscatedDrainEnd() { c.draining.Add(-1) }

// handshakeBucket is one peer's token budget. tokens is a float because the
// refill is fractional in elapsed time.
type handshakeBucket struct {
	tokens float64
	last   time.Time
}

func (b *handshakeBucket) refill(rate uint, now time.Time) {
	burst := float64(rate) * handshakeBurstFactor

	b.tokens += now.Sub(b.last).Seconds() * float64(rate)
	if b.tokens > burst {
		b.tokens = burst
	}

	b.last = now
}

// obfuscatedLimiter caps how often one client IP may fail an obfuscated2
// handshake. A refused peer never enters the trial-decryption loop, which is
// the entire cost the budget exists to bound; it is still read from exactly as
// a peer with budget is, so on a close listener the refusal is not observable.
// Skipping the READ as well was: it closed a rate-limited peer instantly with
// its frame unread, which a censor can tell apart from a no-match in one
// connection.
//
// Armed only on a listener marked public. Behind a loopback carrier every
// connection presents 127.0.0.1, so a per-IP bucket there is ONE shared bucket
// that an attacker empties for every legitimate user at once: a self-DoS with
// no compensating benefit. On loopback it stays off, by construction.
//
// Storage is two generations of a bounded map: when the live generation fills
// up it is demoted and a fresh one takes over, so lookups still find a recent
// bucket while memory can never exceed 2 x maxTrackedHandshakeIPs. That is an
// approximate LRU for a fraction of the code of a real one.
type obfuscatedLimiter struct {
	mu       sync.Mutex
	current  map[netip.Addr]*handshakeBucket
	previous map[netip.Addr]*handshakeBucket
}

func newObfuscatedLimiter(ctx context.Context) *obfuscatedLimiter {
	limiter := &obfuscatedLimiter{
		current: make(map[netip.Addr]*handshakeBucket),
	}

	go limiter.run(ctx)

	return limiter
}

// run ages buckets out so a burst of one-shot probers cannot pin memory for the
// life of the process.
func (l *obfuscatedLimiter) run(ctx context.Context) {
	ticker := time.NewTicker(handshakeBucketRotation)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			l.mu.Lock()
			l.rotateLocked()
			l.mu.Unlock()
		}
	}
}

func (l *obfuscatedLimiter) rotateLocked() {
	l.previous = l.current
	l.current = make(map[netip.Addr]*handshakeBucket)
}

// armed reports whether this policy asks for a budget at all. It is the first
// line of both entry points so the disarmed case costs a comparison and no
// allocation, no lock and no map lookup.
func (l *obfuscatedLimiter) armed(policy ListenerPolicy) bool {
	return policy.Public && policy.HandshakesPerIP > 0
}

// Allow reports whether this peer still has budget. It does NOT consume one:
// this is a budget for FAILED handshakes, so a legitimate client's successful
// connection must cost it nothing.
func (l *obfuscatedLimiter) Allow(policy ListenerPolicy, ip net.IP) bool {
	if l == nil || !l.armed(policy) {
		return true
	}

	key, ok := limiterKey(ip)
	if !ok {
		// No usable address (a net.Pipe in a test, a listener that yielded
		// something other than TCP). There is nothing to budget against, and
		// refusing here would refuse everyone.
		return true
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	bucket := l.lookupLocked(key)
	if bucket == nil {
		return true
	}

	bucket.refill(policy.HandshakesPerIP, time.Now())

	return bucket.tokens >= 1
}

// Fail charges this peer one token for a handshake that did not match.
func (l *obfuscatedLimiter) Fail(policy ListenerPolicy, ip net.IP) {
	if l == nil || !l.armed(policy) {
		return
	}

	key, ok := limiterKey(ip)
	if !ok {
		return
	}

	now := time.Now()

	l.mu.Lock()
	defer l.mu.Unlock()

	bucket := l.lookupLocked(key)
	if bucket == nil {
		if len(l.current) >= maxTrackedHandshakeIPs {
			l.rotateLocked()
		}

		bucket = &handshakeBucket{
			tokens: float64(policy.HandshakesPerIP) * handshakeBurstFactor,
			last:   now,
		}
		l.current[key] = bucket
	}

	bucket.refill(policy.HandshakesPerIP, now)

	bucket.tokens--
	if bucket.tokens < 0 {
		bucket.tokens = 0
	}
}

// lookupLocked finds a bucket in either generation, promoting a hit from the
// demoted one so an active peer is not forgotten by the next rotation.
func (l *obfuscatedLimiter) lookupLocked(key netip.Addr) *handshakeBucket {
	if bucket, ok := l.current[key]; ok {
		return bucket
	}

	bucket, ok := l.previous[key]
	if !ok {
		return nil
	}

	l.current[key] = bucket

	return bucket
}

// limiterKey turns a client address into a bucket key: the address itself for
// IPv4, the /64 for IPv6.
func limiterKey(ip net.IP) (netip.Addr, bool) {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return netip.Addr{}, false
	}

	addr = addr.Unmap()

	if addr.Is6() {
		prefix, err := addr.Prefix(ipv6BucketPrefix)
		if err != nil {
			return netip.Addr{}, false
		}

		addr = prefix.Addr()
	}

	return addr, true
}
