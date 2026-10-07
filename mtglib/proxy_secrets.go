package mtglib

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"time"

	"github.com/Arman2122/mtg-proxy/mtglib/internal/doppel"
	"github.com/Arman2122/mtg-proxy/mtglib/internal/tls/fake"
)

// The secret set: the immutable snapshot every handshake reads, how it is
// built and swapped on reload, and the per-user limits and usage that ride
// with it.

// secretSet is an immutable snapshot of the secrets a proxy serves. The proxy
// keeps it behind an atomic pointer so a running handshake always reads a
// single consistent view, and ReloadSecrets can swap the whole set in without
// locking the hot path. secrets, names and hostnames stay index-aligned:
// secrets[i] belongs to names[i]; hostnames is the deduplicated, sorted set of
// secret hosts used for SNI matching.
type secretSet struct {
	secrets   []Secret
	names     []string
	hostnames []string
	// adTags[i] is the per-secret advertising tag override for secrets[i], or
	// nil when that secret has no override; globalAdTag applies to any secret
	// without an override, or nil when no advertising is configured.
	adTags      []*[AdTagLength]byte
	globalAdTag *[AdTagLength]byte
	// limits[i] holds the governance limits (quota, expiry, disabled) for
	// secrets[i]; the zero value means the secret is unrestricted.
	limits []SecretLimits

	// hosted holds the indices of ee secrets, in name order. They are the only
	// secrets the FakeTLS door may try, and cands is built from them: a hostless
	// secret has no hostname a client could put in SNI, and admitting its key on
	// that path would let a client borrow ANOTHER secret's hostname to
	// authenticate with it.
	hosted []int

	// cands is what the FakeTLS door verifies a ClientHello against, built once
	// with the set: one Candidate per hosted secret, in name order, minus any
	// whose key an earlier hosted secret already has (the earlier one wins a
	// match, as it always did, so a repeat could never be the first to match).
	// candIdx[i] is the index into secrets, names, limits and adTags of the secret
	// cands[i] stands for -- the match position is NOT an index into secrets.
	// candByName maps names[candIdx[i]] to i; a name that is not a candidate (a
	// hostless secret, a dropped repeat) is absent, so look it up with the
	// two-value form: a missing name reads as 0, which is a position. All three
	// are nil on a set that was not built by buildSecretSet, which has no
	// candidates.
	cands      []*fake.Candidate
	candIdx    []int
	candByName map[string]int

	// frontHost is the domain-fronting fallback: the first non-empty Host in
	// name order, or "" when no ee secret is configured. It replaces
	// secrets[0].Host, which under a management panel was whichever client name
	// sorted first -- operator-uncontrolled, and now possibly hostless.
	frontHost string
}

// effectiveAdTag returns the advertising tag that applies to secrets[i]: the
// per-secret override if present, otherwise the global tag, otherwise nil (the
// direct-DC path).
func (s *secretSet) effectiveAdTag(i int) *[AdTagLength]byte {
	if i < len(s.adTags) && s.adTags[i] != nil {
		return s.adTags[i]
	}

	return s.globalAdTag
}

// limitsOf returns the named secret's limits, and false when the set does not
// hold the name. Safe on a nil set, which holds nothing. names is sorted, so
// this is a binary search and not a walk of every secret.
func (s *secretSet) limitsOf(name string) (SecretLimits, bool) {
	if s == nil {
		return SecretLimits{}, false
	}

	i, found := slices.BinarySearch(s.names, name)
	if !found {
		return SecretLimits{}, false
	}

	if i < len(s.limits) {
		return s.limits[i], true
	}

	return SecretLimits{}, true
}

// toConfig reconstructs a mutable SecretConfig from the immutable snapshot. It
// is the copy-on-write starting point for the management-API mutators, which
// apply a delta and swap the result back in.
func (s *secretSet) toConfig() SecretConfig {
	secrets := make(map[string]Secret, len(s.names))

	var perSecret map[string][AdTagLength]byte

	var limits map[string]SecretLimits

	for i, name := range s.names {
		secrets[name] = s.secrets[i]

		if s.adTags[i] != nil {
			if perSecret == nil {
				perSecret = make(map[string][AdTagLength]byte)
			}

			perSecret[name] = *s.adTags[i]
		}

		if i < len(s.limits) && !s.limits[i].IsZero() {
			if limits == nil {
				limits = make(map[string]SecretLimits)
			}

			limits[name] = s.limits[i]
		}
	}

	return SecretConfig{Secrets: secrets, SecretAdTags: perSecret, GlobalAdTag: s.globalAdTag, Limits: limits}
}

// buildSecretSet turns a name->secret map into an immutable, name-sorted
// snapshot. Sorting keeps names[i] and secrets[i] aligned and makes the
// matched index stable across processes for a given secret map. perSecret
// carries optional per-name advertising tags and global is the fallback tag;
// both may be nil. limitsMap carries optional per-name governance limits and
// may be nil.
func buildSecretSet(secretsMap map[string]Secret, perSecret map[string][AdTagLength]byte, global *[AdTagLength]byte, limitsMap map[string]SecretLimits) *secretSet {
	names := make([]string, 0, len(secretsMap))
	for name := range secretsMap {
		names = append(names, name)
	}

	sort.Strings(names)

	secretsList := make([]Secret, 0, len(secretsMap))
	adTags := make([]*[AdTagLength]byte, len(names))
	limits := make([]SecretLimits, len(names))

	for i, name := range names {
		secretsList = append(secretsList, secretsMap[name])

		if tag, ok := perSecret[name]; ok {
			t := tag
			adTags[i] = &t
		}

		if lim, ok := limitsMap[name]; ok {
			limits[i] = lim
		}
	}

	hostnameSet := make(map[string]struct{}, len(secretsList))
	hosted := make([]int, 0, len(secretsList))

	var frontHost string

	for i, s := range secretsList {
		if s.Hosted() {
			hosted = append(hosted, i)
		}

		if s.Host == "" {
			// The empty string must never become a matchable SNI: a hostless
			// secret would otherwise answer to a ClientHello carrying no
			// server_name at all.
			continue
		}

		hostnameSet[s.Host] = struct{}{}

		if frontHost == "" {
			frontHost = s.Host
		}
	}

	hostnames := make([]string, 0, len(hostnameSet))
	for h := range hostnameSet {
		hostnames = append(hostnames, h)
	}

	sort.Strings(hostnames)

	cands, candIdx, candByName := buildCandidates(secretsList, names, hosted)

	return &secretSet{
		secrets:     secretsList,
		names:       names,
		hostnames:   hostnames,
		adTags:      adTags,
		globalAdTag: global,
		limits:      limits,
		hosted:      hosted,
		cands:       cands,
		candIdx:     candIdx,
		candByName:  candByName,
		frontHost:   frontHost,
	}
}

// buildCandidates makes the FakeTLS candidates for the hosted secrets (indices
// into secrets, in name order): one Candidate each, with its key's pads hashed
// here, once per set, instead of once per handshake. A later secret whose key an
// earlier hosted one already has is left out. It could only ever match when the
// earlier one does, and the earlier one is tried first, so dropping it changes
// no answer and saves a verification per hello that reaches it. Only HOSTED
// keys count as seen: a dd secret that sorts first and shares a key with an ee
// secret does not shadow it.
func buildCandidates(secrets []Secret, names []string, hosted []int) ([]*fake.Candidate, []int, map[string]int) {
	cands := make([]*fake.Candidate, 0, len(hosted))
	candIdx := make([]int, 0, len(hosted))
	candByName := make(map[string]int, len(hosted))
	seen := make(map[[SecretKeyLength]byte]struct{}, len(hosted))

	for _, i := range hosted {
		key := secrets[i].Key

		if _, repeat := seen[key]; repeat {
			continue
		}

		seen[key] = struct{}{}

		candByName[names[i]] = len(cands)
		cands = append(cands, fake.NewCandidate(key[:]))
		candIdx = append(candIdx, i)
	}

	return cands, candIdx, candByName
}

// ReloadSecrets re-reads the secret set through the configured reloader and
// swaps it in atomically, so a client add, removal, disable or re-key takes
// effect without restarting the process. Connections whose secret disappeared
// or was re-keyed are closed; every other live stream keeps running, and the
// /stats counters carry across the swap. It returns ErrReloaderNotConfigured
// when the proxy was built without a SecretsReloader, and an error (leaving the
// current set active) when the reloader fails or yields no valid secret.
func (p *Proxy) ReloadSecrets() error {
	if p.reloader == nil {
		return ErrReloaderNotConfigured
	}

	p.reloadMu.Lock()
	defer p.reloadMu.Unlock()

	cfg, err := p.reloader()
	if err != nil {
		return fmt.Errorf("cannot reload secrets: %w", err)
	}

	return p.swapSecretConfigLocked(cfg)
}

// swapSecretConfigLocked validates cfg, builds a fresh immutable snapshot,
// swaps it in atomically, pre-registers stats for every name, and closes stale
// connections. It is the single mutation point shared by ReloadSecrets and the
// management-API mutators; the caller MUST hold reloadMu.
func (p *Proxy) swapSecretConfigLocked(cfg SecretConfig) error {
	if len(cfg.Secrets) == 0 {
		return ErrSecretInvalid
	}

	for _, s := range cfg.Secrets {
		if !s.Valid() {
			return ErrSecretInvalid
		}
	}

	// bind-to is mandatory and permanently ee-only, so every process has a
	// FakeTLS listener. A swap that leaves it no cover site is REJECTED rather
	// than applied: closing every failed ClientHello instead of fronting it is
	// exactly the distinguisher the fronting path exists to avoid, and the
	// previous set staying active is the safe outcome.
	if !SecretsCanFront(cfg.Secrets, p.domainFrontingHost) {
		return ErrSecretInvalid
	}

	newSet := buildSecretSet(cfg.Secrets, cfg.SecretAdTags, cfg.GlobalAdTag, cfg.Limits)
	oldSet := p.secrets.Swap(newSet)

	p.doppelGanger.SetCoverHosts(p.coverHosts(newSet))

	for _, name := range newSet.names {
		p.stats.PreRegister(name)
	}

	p.applyLimits(newSet)
	p.dropRemovedClients(oldSet, newSet)
	p.closeStaleConns(oldSet, newSet)
	p.closeDeniedConns()

	return nil
}

// dropRemovedClients forgets the per-address entries of every secret the swap
// removed, rest entries included. A re-keyed secret keeps its name and so
// keeps its entries: they are the same addresses.
//
// Under liveMu, so that it is one step against admission: a stream of the
// removed secret that registers concurrently either took its entry before this
// (and loses it here) or reads the new set after it (and takes none). The
// removed secret's streams are closed straight after, and give back entries
// the table no longer holds, which touches nothing.
func (p *Proxy) dropRemovedClients(oldSet, newSet *secretSet) {
	if p.clients == nil || oldSet == nil {
		return
	}

	var removed []string

	for _, name := range oldSet.names {
		if _, kept := newSet.limitsOf(name); !kept {
			removed = append(removed, name)
		}
	}

	if len(removed) == 0 {
		return
	}

	p.liveMu.Lock()
	defer p.liveMu.Unlock()

	for _, name := range removed {
		p.clients.dropSecret(name)
	}
}

// coverHosts lists the cover sites the set's ee secrets name, each once, in
// name order, with the address domain fronting would dial for it -- where the
// doppelganger measures it. A host with no fronting address is left out.
func (p *Proxy) coverHosts(set *secretSet) []doppel.CoverHost {
	seen := make(map[string]bool)

	var hosts []doppel.CoverHost

	for _, idx := range set.hosted {
		host := set.secrets[idx].Host
		if host == "" || seen[host] {
			continue
		}

		seen[host] = true

		if addr := p.domainFrontingAddressForHost(host); addr != "" {
			hosts = append(hosts, doppel.CoverHost{Host: host, Addr: addr})
		}
	}

	return hosts
}

// applyLimits installs, from the set just swapped in, the limits that are
// enforced on the data path rather than at admission: every user's speed
// bucket is re-rated and their quota ceiling is set, so a change reaches the
// connections already open without a reconnect.
// It runs on every swap -- startup, reload, the API -- so a changed limit
// reaches the user's live connections at once, and a removed one frees them
// at once. A user dropped from the set keeps their bucket, which is harmless:
// nothing draws from it, and a user re-added gets it re-rated here.
func (p *Proxy) applyLimits(set *secretSet) {
	for i, name := range set.names {
		var lim SecretLimits

		if i < len(set.limits) {
			lim = set.limits[i]
		}

		p.stats.SetSpeedLimit(name, lim.SpeedBytesPerSecond)
		p.stats.SetDirectionalSpeedLimits(name, lim.SpeedUpBytesPerSecond, lim.SpeedDownBytesPerSecond)
		p.stats.SetQuotaCeiling(name, lim.QuotaBytes)
	}

	p.backfillClients(set)
}

// backfillClients gives every live stream that has no per-address entry, of
// every secret in set that needs entries, the entry admission would have given
// it: its address's own when it is keyed, the secret's rest entry when it is
// not. A control a reload turned on must reach the connections already open --
// they live for hours -- and an unkeyed stream left without the rest entry
// would be exactly the ungoverned stream the rest entry exists to prevent.
// A stream that already has an entry keeps it, so a reload that changes
// nothing changes nothing here.
//
// Under liveMu, the same critical section admission takes its entry in, so a
// stream is either admitted before this and backfilled by it, or admitted
// after it from the set already swapped in.
func (p *Proxy) backfillClients(set *secretSet) {
	if p.clients == nil {
		return
	}

	p.liveMu.Lock()
	defer p.liveMu.Unlock()

	for i, name := range set.names {
		var lim SecretLimits

		if i < len(set.limits) {
			lim = set.limits[i]
		}

		if !p.clientEntriesWanted(lim) {
			continue
		}

		for sc := range p.liveConns[name] {
			if sc.addrEntry.Load() != nil {
				continue
			}

			sc.addrEntry.Store(p.clients.acquire(name, sc.addrKey, sc.addrKeyed, lim.IPLimit, entryInitOf(lim)))
		}
	}
}

// closeStaleConns closes every live stream whose secret was dropped from the
// new set or whose key changed since the old set (a re-key), and leaves the
// rest connected. It compares the KEY ALONE, deliberately: a Host change
// touches nothing on a live stream (the FakeTLS handshake is long finished and
// the fronting host is read only on the failure path of a NEW connection) and a
// Mode change touches nothing at all (the three modes share the key and derive
// identical ciphers), so widening the comparison would kill every live stream
// of every client on a hostname edit for no correctness gain. Streams are snapshotted under the lock and closed outside it,
// so each stream's own unregister (which also takes the lock) cannot deadlock.
func (p *Proxy) closeStaleConns(oldSet, newSet *secretSet) {
	newKeys := make(map[string][SecretKeyLength]byte, len(newSet.names))
	for i, name := range newSet.names {
		newKeys[name] = newSet.secrets[i].Key
	}

	oldKeys := make(map[string][SecretKeyLength]byte)
	if oldSet != nil {
		for i, name := range oldSet.names {
			oldKeys[name] = oldSet.secrets[i].Key
		}
	}

	var stale []*streamContext

	p.liveMu.Lock()
	for name, conns := range p.liveConns {
		if newKey, kept := newKeys[name]; kept {
			if oldKey, had := oldKeys[name]; had && oldKey == newKey {
				continue
			}
		}

		for sc := range conns {
			stale = append(stale, sc)
		}
	}
	p.liveMu.Unlock()

	for _, sc := range stale {
		sc.Close()
	}
}

// checkLimits reports whether a new connection for the named secret is allowed
// by its governance limits, combining the snapshot limit (disabled flag, expiry
// deadline, quota ceiling) with the live usage counter held in stats. The
// returned DenyReason is DenyNone when allowed.
func (p *Proxy) checkLimits(name string, lim SecretLimits) (bool, DenyReason) {
	if lim.Disabled {
		return false, DenyDisabled
	}

	if !lim.ExpiresAt.IsZero() && !time.Now().Before(lim.ExpiresAt) {
		return false, DenyExpired
	}

	if lim.QuotaBytes > 0 && p.stats.QuotaUsed(name, lim.QuotaReset) >= lim.QuotaBytes {
		return false, DenyQuota
	}

	return true, DenyNone
}

// closeDeniedConns closes every live stream whose secret is now denied: it was
// disabled, has expired, or is at its quota. It runs after every swap, so a
// change applied via a reload or the API takes effect immediately instead of
// only blocking new connections, and it runs from the maintenance loop, so a
// deadline the clock crosses takes effect on its own.
//
// Quota is included. The data path ends the stream that crosses the ceiling,
// but a stream of an exhausted user that is carrying nothing would otherwise
// sit open until the idle timeout, and a quota lowered below what is already
// used would reach nobody until they moved a byte.
func (p *Proxy) closeDeniedConns() {
	set := p.secrets.Load()

	limitByName := make(map[string]SecretLimits, len(set.names))
	for i, name := range set.names {
		limitByName[name] = set.limits[i]
	}

	var denied []*streamContext

	p.liveMu.Lock()
	for name, conns := range p.liveConns {
		lim, ok := limitByName[name]
		if !ok {
			continue
		}

		if allowed, _ := p.checkLimits(name, lim); allowed {
			continue
		}

		for sc := range conns {
			denied = append(denied, sc)
		}
	}
	p.liveMu.Unlock()

	for _, sc := range denied {
		sc.Close()
	}
}

// rolloverAllQuotas applies a monthly quota rollover to every secret whose
// policy is monthly, keeping the persisted and displayed usage fresh even for
// secrets that no client is currently hitting.
func (p *Proxy) rolloverAllQuotas() {
	set := p.secrets.Load()
	now := time.Now()

	for i, name := range set.names {
		if set.limits[i].QuotaReset == QuotaResetMonthly {
			p.stats.rollover(name, set.limits[i].QuotaReset, now)
		}
	}
}

// denySweepInterval is how often live streams are checked against the limits
// the clock alone can cross: an expiry that passes, a quota period that rolls
// over. It bounds how long a user outlives their deadline, and it is short
// because the sweep is a walk of the live registry and nothing more.
const denySweepInterval = 5 * time.Second

// startMaintenance runs, until ctx is cancelled, the work that has to happen
// on the clock rather than on an event: every sweepEvery, monthly quota
// periods roll over and streams of users who are now denied are closed;
// every flushEvery, the usage counters are written to usageStateFile if one
// is configured; every clientSweepInterval, the per-address table forgets the
// addresses that have been gone long enough.
//
// It runs whether or not there is a usage file. The sweep is what makes an
// expiry a deadline rather than a hint: without it, a user already connected
// when their expiry passed stayed connected until something else swapped the
// secret set.
func (p *Proxy) startMaintenance(ctx context.Context, sweepEvery, flushEvery time.Duration) {
	p.startMaintenanceEvery(ctx, sweepEvery, flushEvery, clientSweepInterval)
}

// startMaintenanceEvery is startMaintenance with the per-address sweep's
// interval as well, so a test need not wait a minute for it.
func (p *Proxy) startMaintenanceEvery(ctx context.Context, sweepEvery, flushEvery, clientsEvery time.Duration) {
	go func() {
		sweep := time.NewTicker(sweepEvery)
		defer sweep.Stop()

		flush := time.NewTicker(flushEvery)
		defer flush.Stop()

		clients := time.NewTicker(clientsEvery)
		defer clients.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-sweep.C:
				p.rolloverAllQuotas()
				p.closeDeniedConns()
			case <-clients.C:
				p.sweepClients()
			case <-flush.C:
				if p.usageStateFile == "" {
					continue
				}

				if err := p.stats.FlushUsage(p.usageStateFile); err != nil {
					p.logger.WarningError("cannot flush usage state", err)
				}
			}
		}
	}()
}

// sweepClients is the maintenance loop's sweep of the per-address table, at
// the table's own clock, in chunks of clientSweepChunk. It takes the table's
// lock and never liveMu, so however many entries it walks, an admission waits
// at most one chunk for it.
func (p *Proxy) sweepClients() int {
	if p.clients == nil {
		return 0
	}

	return p.clients.sweep(p.clients.clock.read(), clientSweepChunk)
}
