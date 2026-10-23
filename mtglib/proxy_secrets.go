package mtglib

import (
	"bytes"
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
	// After every primary candidate, from primaryEnd() on, come the kept ee
	// retiring keys, in retiring's order.
	// candIdx[i] is the index into secrets, names, limits and adTags of the secret
	// cands[i] stands for -- the match position is NOT an index into secrets. For
	// a retiring position it is the index of the entry's name: the name is what
	// the match bills. matchAt turns a position into what was matched.
	// candByName maps names[candIdx[i]] to i for the PRIMARY candidates only; a
	// name that is not a candidate (a hostless secret, a dropped repeat) is
	// absent, so look it up with the two-value form: a missing name reads as 0,
	// which is a position. A name's retiring positions are in retiringCands. All
	// three are nil on a set that was not built by buildSecretSet, which has no
	// candidates.
	cands      []*fake.Candidate
	candIdx    []int
	candByName map[string]int

	// frontHost is the domain-fronting fallback: the first non-empty Host in
	// name order, or "" when no ee secret is configured. It replaces
	// secrets[0].Host, which under a management panel was whichever client name
	// sorted first -- operator-uncontrolled, and now possibly hostless. It is
	// the primaries' alone: a retiring key's host never fronts, so a set whose
	// only ee key is retiring has none, as SecretsCanFront says.
	frontHost string

	// clientControl says whether any secret in the set has a per-address
	// control (SecretLimits.hasClientControl), worked out once when the set is
	// built. With it false and track-client-ips off no secret needs an entry
	// in the per-address table, and admission knows that without looking the
	// secret up.
	clientControl bool

	// The retiring keys the set keeps: old keys of a name, still accepted
	// until their own until after the name was given a new primary key
	// (RetiringSecret). EVERY ONE of these fields is nil or zero when the set
	// keeps no retiring entry, and the set is then field for field the set
	// buildSecretSet made before rotation existed.
	//
	// retiring is sorted by (nameIdx, until descending, key bytes); every
	// value in it is Valid(), no two entries share a key, and none has a
	// primary's key. retiringOf maps a
	// name's index to its entries' indices in retiring, in that order.
	// primaryCands is how many of cands are primaries when there are retiring
	// entries, and 0 otherwise -- so it is never a bound on its own:
	// primaryEnd() is the boundary. candRetiring[pos-primaryEnd()] is the
	// index into retiring of the retiring candidate at pos, and
	// retiringCands[name] the name's retiring candidate positions, in
	// retiring's order, whether or not its primary is a candidate.
	// retiringNext is the earliest until in retiring.
	retiring      []retiringEntry  // {nameIdx int; secret Secret; until time.Time}, sorted by (nameIdx, until desc, key bytes)
	retiringOf    map[int][]int    // nameIdx -> indices into retiring
	primaryCands  int              // how many of cands are primaries when there are retiring entries, else 0: never a bound, use primaryEnd()
	candRetiring  []int            // candRetiring[pos-primaryEnd()] = index into retiring
	retiringCands map[string][]int // name -> its retiring candidate positions, same order
	retiringNext  time.Time        // earliest until in retiring; zero when none
}

// anyClientControl reports whether any secret in the set has a per-address
// control. False on a nil set, which holds nothing.
func (s *secretSet) anyClientControl() bool {
	return s != nil && s.clientControl
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

// accepts says whether the set lets a stream of the named secret go on with
// key, the key the stream matched: true when key is the name's key in this set,
// or the key of one of the name's retiring entries while now is before its
// until. False on a nil set, which holds nothing, for a name the set does not
// hold, and for any other key, a nil or partial one included. now is when the
// question is asked; a name's own key is accepted at any time, and a retiring
// key is refused from its until on. Registration asks it of the set in force
// (tryRegisterConn), so a stream that matched a key a swap has since taken
// away is refused rather than registered. names is sorted, so this is a binary
// search and not a walk of every secret.
func (s *secretSet) accepts(name string, key []byte, now time.Time) bool {
	if s == nil {
		return false
	}

	i, found := slices.BinarySearch(s.names, name)
	if !found || i >= len(s.secrets) {
		return false
	}

	if bytes.Equal(s.secrets[i].Key[:], key) {
		return true
	}

	for _, r := range s.retiringOf[i] {
		if entry := &s.retiring[r]; now.Before(entry.until) && bytes.Equal(entry.secret.Key[:], key) {
			return true
		}
	}

	return false
}

// toConfig reconstructs a mutable SecretConfig from the immutable snapshot. It
// is the copy-on-write starting point for the management-API mutators, which
// apply a delta and swap the result back in. Retiring is every entry the set
// keeps, in its order, and nil when it keeps none.
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

	var retiring []RetiringSecret

	if len(s.retiring) > 0 {
		retiring = make([]RetiringSecret, 0, len(s.retiring))

		for _, entry := range s.retiring {
			retiring = append(retiring, RetiringSecret{Name: s.names[entry.nameIdx], Secret: entry.secret, Until: entry.until})
		}
	}

	return SecretConfig{
		Secrets:      secrets,
		SecretAdTags: perSecret,
		GlobalAdTag:  s.globalAdTag,
		Limits:       limits,
		Retiring:     retiring,
	}
}

// buildSecretSet turns a name->secret map into an immutable, name-sorted
// snapshot. Sorting keeps names[i] and secrets[i] aligned and makes the
// matched index stable across processes for a given secret map. perSecret
// carries optional per-name advertising tags and global is the fallback tag;
// both may be nil. limitsMap carries optional per-name governance limits and
// may be nil. It is buildSecretSetAt with no retiring entry, so the set it
// makes holds none.
func buildSecretSet(secretsMap map[string]Secret, perSecret map[string][AdTagLength]byte, global *[AdTagLength]byte, limitsMap map[string]SecretLimits) *secretSet {
	set, _ := buildSecretSetAt(secretsMap, perSecret, global, limitsMap, nil, time.Time{})

	return set
}

// buildSecretSetAt is buildSecretSet with retiring keys: the primaries are
// built exactly as buildSecretSet always built them, and then retiring, the
// complete list of entries the set is to hold (nil is none), is classified at
// now: an invalid value (Secret.Valid()) first, then the §1.3 rules 2, 3, 5,
// 6, 7 and 8 (buildRetiring). The caller's slice is only read. The kept entries
// come after every primary: their hosts join hostnames (the SNI gate) when
// they are ee, their ee keys are candidates after every primary candidate, and
// nothing else a primary decides -- hosted, frontHost, candByName -- changes.
// The entries it does not keep are returned, in input order, for the log;
// none is an error. A set that keeps no entry has every retiring field nil or
// zero.
func buildSecretSetAt(secretsMap map[string]Secret, perSecret map[string][AdTagLength]byte, global *[AdTagLength]byte,
	limitsMap map[string]SecretLimits, retiring []RetiringSecret, now time.Time,
) (*secretSet, []retiringDrop) {
	names := make([]string, 0, len(secretsMap))
	for name := range secretsMap {
		names = append(names, name)
	}

	sort.Strings(names)

	secretsList := make([]Secret, 0, len(secretsMap))
	adTags := make([]*[AdTagLength]byte, len(names))
	limits := make([]SecretLimits, len(names))
	clientControl := false

	for i, name := range names {
		secretsList = append(secretsList, secretsMap[name])

		if tag, ok := perSecret[name]; ok {
			t := tag
			adTags[i] = &t
		}

		if lim, ok := limitsMap[name]; ok {
			limits[i] = lim
			clientControl = clientControl || lim.hasClientControl()
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

	kept, drops := buildRetiring(names, secretsList, retiring, now)

	// A kept ee entry's host passes the SNI gate until the entry leaves the
	// set: a rotation that also moves the fronting domain must not cut the old
	// link's clients at the gate. It never becomes frontHost.
	for r := range kept {
		if entry := &kept[r]; entry.secret.Hosted() && entry.secret.Host != "" {
			hostnameSet[entry.secret.Host] = struct{}{}
		}
	}

	hostnames := make([]string, 0, len(hostnameSet))
	for h := range hostnameSet {
		hostnames = append(hostnames, h)
	}

	sort.Strings(hostnames)

	cands, candIdx, candByName := buildCandidates(secretsList, names, hosted)

	set := &secretSet{
		secrets:       secretsList,
		names:         names,
		hostnames:     hostnames,
		adTags:        adTags,
		globalAdTag:   global,
		limits:        limits,
		hosted:        hosted,
		cands:         cands,
		candIdx:       candIdx,
		candByName:    candByName,
		frontHost:     frontHost,
		clientControl: clientControl,
	}

	set.addRetiring(kept)

	return set, drops
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

// swapSecretConfigLocked validates cfg, then applies it
// (applySecretConfigLocked). It is the single mutation point shared by
// ReloadSecrets and the management-API mutators, every one of which brings a
// configuration in; the caller MUST hold reloadMu, taken before liveMu (and
// liveMu before the table's lock), never under it.
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

	p.applySecretConfigLocked(cfg)

	return nil
}

// applySecretConfigLocked is the swap itself, with none of
// swapSecretConfigLocked's input checks: it builds a fresh immutable snapshot
// from cfg, swaps it in atomically, pre-registers stats for every name, and
// closes stale connections. It cannot fail. Only two callers reach it: the
// checked swap, and the expiry sweep, whose cfg is the set in force rebuilt --
// it brings in nothing the checks exist to stop, and it must end an overlap
// whatever they would say of a set NewProxy never checked. The caller MUST hold
// reloadMu, as for swapSecretConfigLocked.
func (p *Proxy) applySecretConfigLocked(cfg SecretConfig) {
	// The one read of the clock for the whole swap: the build judges every
	// retiring entry by it, and whatever else the swap judges against the clock
	// must take this same instant rather than read its own.
	now := p.rotation.Now()

	newSet, drops := buildSecretSetAt(cfg.Secrets, cfg.SecretAdTags, cfg.GlobalAdTag, cfg.Limits, cfg.Retiring, now)

	// BEFORE the Swap, not after it: once the new set is stored a stream on a new
	// old link can register and stamp retiring_last_seen, and a reset that ran
	// then would wipe it. reloadMu is held, so the set in force is the one being
	// replaced.
	p.resetRetiringSeen(p.secrets.Load(), newSet, now)

	oldSet := p.secrets.Swap(newSet)

	afterSecretStoreHook(newSet)

	p.logRetiringDrops(drops)
	p.doppelGanger.SetCoverHosts(p.coverHosts(newSet))

	for _, name := range newSet.names {
		p.stats.PreRegister(name)
	}

	p.applyLimits(newSet)
	p.dropRemovedSecrets(oldSet, newSet)

	closed := p.closeStaleConns(oldSet, newSet, now)
	p.logRetiringChanges(oldSet, newSet, now, closed)

	p.closeDeniedConns()
}

// afterSecretStoreHook runs in applySecretConfigLocked right after the new set
// is stored and before anything in the swap takes liveMu: the window in which
// a registration already reads the new set and the swap's walk has not run. A
// no-op in production. A test uses it to register a stream in that window
// (beforeRegisterLockHook cannot place one there: it runs a whole swap before
// the stream locks). A variable so it can be replaced; a test that does must
// restore it and must not run in parallel.
var afterSecretStoreHook = func(*secretSet) {}

// expireRetiring is the maintenance sweep's end of an overlap (spec §4.2):
// once the clock reaches the earliest until the set in force holds, it swaps
// in that same set rebuilt at the clock's instant. The build drops every entry
// that has expired by then, the keys it held leave the set, and closeStaleConns
// closes their streams by the held-key judgment it gives every swap. It closes
// nothing itself. A set with no retiring entry costs one load and one compare.
//
// It takes reloadMu with TryLock, never Lock. A reload or an API mutation holds
// that lock across a file read or a request, and waiting behind one would hold
// up the rest of the maintenance tick -- closeDeniedConns, the quota rollover,
// the usage flush -- on the same goroutine. A tick that loses the lock retries
// on the next: a holder that swaps rebuilds at its own instant and does this
// sweep's work, and one that fails leaves it to the next tick. Admission stays
// exact meanwhile, because the doors and registration judge until themselves.
//
// The swap rebuilds from the set in force as it is once the lock is held -- not
// the set loaded to decide, which a mutation may have replaced since -- so the
// API's mutations survive it and nothing they removed comes back. It applies
// the rebuild without a swap's input checks (applySecretConfigLocked), so it
// cannot be refused: its primaries are those the set already holds, it brings
// nothing in, and a set the checks would refuse -- a library caller's initial
// set that cannot front, which NewProxy does not check -- still has its
// overlaps ended and their streams closed.
func (p *Proxy) expireRetiring() {
	set := p.secrets.Load()
	if set.retiringNext.IsZero() {
		return
	}

	now := p.rotation.Now()
	if now.Before(set.retiringNext) {
		return
	}

	if !p.reloadMu.TryLock() {
		return
	}
	defer p.reloadMu.Unlock()

	set = p.secrets.Load()
	if set.retiringNext.IsZero() || now.Before(set.retiringNext) {
		return
	}

	p.applySecretConfigLocked(set.toConfig())
}

// logRetiringDrops writes one line for each retiring entry a build did not keep:
// the secret's name and the reason, and nothing else. A retiring key is a
// credential, and the line is written from a retiringDrop, which holds none.
// Three reasons are routine and logged at Info -- the entry repeats a key the
// name already accepts (same_as_primary, duplicate), or its overlap ended
// between the reader and the build (expired). The rest say the entries handed in
// are not what their author meant, and are Warnings: invalid, dangling,
// key_of_other_secret and over_cap.
//
// It touches the logger only when there is a line to write: a Proxy{} literal
// in a test has none.
func (p *Proxy) logRetiringDrops(drops []retiringDrop) {
	for _, drop := range drops {
		line := p.logger.BindStr("secret_name", drop.name).BindStr("reason", drop.reason)

		switch drop.reason {
		case retiringSameAsPrimary, retiringDuplicate, retiringExpired:
			line.Info("a retiring key was ignored")
		default:
			line.Warning("a retiring key was ignored")
		}
	}
}

// The rotation change log's lines (spec §6.2) and the one reason a removal
// gives.
const (
	retiringAddedLine     = "secret accepts a previous key until its overlap ends"
	retiringEndedLine     = "previous key of the secret is no longer accepted: overlap ended"
	retiringRemovedLine   = "previous key of the secret is no longer accepted"
	retiringReturnedLine  = "previous key of the secret is the primary again"
	retiringRemovedReason = "removed"
)

// retiringID is a retiring entry as the change log matches it across two sets:
// its name and its key. It is a map key and nothing else; it is never written
// anywhere.
type retiringID struct {
	name string
	key  [SecretKeyLength]byte
}

// retiringIDs is every entry set keeps, by name and key, and nil for a set
// that keeps none, a nil set included.
func retiringIDs(set *secretSet) map[retiringID]struct{} {
	if set == nil || len(set.retiring) == 0 {
		return nil
	}

	ids := make(map[retiringID]struct{}, len(set.retiring))

	for r := range set.retiring {
		entry := &set.retiring[r]
		ids[retiringID{name: set.names[entry.nameIdx], key: entry.secret.Key}] = struct{}{}
	}

	return ids
}

// logUntil is how a change line writes an until: UTC, to the second, as
// rotate-secret writes it into the file.
func logUntil(until time.Time) string {
	return until.UTC().Format(time.RFC3339)
}

// logRetiringChanges is the rotation change log of one swap (spec §6.3): it
// diffs oldSet's retiring entries with newSet's, matching them by name and key,
// and writes a line for each difference, naming the secret and never the key.
//   - An entry of oldSet that newSet lacks left. When its key is the name's
//     primary in newSet it was reverted -- made the primary again, through
//     POST /secrets for one -- and the line is "the primary again", at
//     Warning, whatever its until: the key is still accepted, so neither
//     other line is true of it. Otherwise the line is "overlap ended", with
//     its until, when its until is not after now -- the swap's own instant,
//     the one its build and closeStaleConns judged by -- and "no longer
//     accepted" with reason=removed when it is. All three carry closed, the
//     streams of the name the swap closed (closeStaleConns' count). The
//     engine's own expired drop plays no part: on a reload after until the
//     config layer has already left the entry out, and only this diff sees
//     it go.
//   - An entry of newSet that oldSet lacks is new: "accepts a previous key",
//     with its until.
//
// Departures come first, each list in its set's order. A swap that changes
// nothing about rotation writes nothing; nor does one whose only change is an
// entry's until. NewProxy calls it with a nil oldSet once the proxy exists, so
// the start writes a line for each entry the first set keeps. Like
// logRetiringDrops it touches the logger only when it has a line to write: a
// Proxy{} literal in a test has none.
func (p *Proxy) logRetiringChanges(oldSet, newSet *secretSet, now time.Time, closed map[string]int) {
	before, after := retiringIDs(oldSet), retiringIDs(newSet)
	if before == nil && after == nil {
		return
	}

	if before != nil {
		for r := range oldSet.retiring {
			entry := &oldSet.retiring[r]
			name := oldSet.names[entry.nameIdx]

			if _, kept := after[retiringID{name: name, key: entry.secret.Key}]; kept {
				continue
			}

			line := p.logger.BindStr("secret_name", name)

			switch i, held := newSet.indexOf(name); {
			case held && newSet.secrets[i].Key == entry.secret.Key:
				line.BindInt("closed", closed[name]).Warning(retiringReturnedLine)
			case now.Before(entry.until):
				line.BindStr("reason", retiringRemovedReason).BindInt("closed", closed[name]).Info(retiringRemovedLine)
			default:
				line.BindStr("until", logUntil(entry.until)).BindInt("closed", closed[name]).Info(retiringEndedLine)
			}
		}
	}

	for r := range newSet.retiring {
		entry := &newSet.retiring[r]
		name := newSet.names[entry.nameIdx]

		if _, held := before[retiringID{name: name, key: entry.secret.Key}]; held {
			continue
		}

		p.logger.BindStr("secret_name", name).BindStr("until", logUntil(entry.until)).Info(retiringAddedLine)
	}
}

// dropRemovedSecrets forgets what the proxy holds per address for every secret
// the swap removed: its per-address entries, rest entries included, and its
// bans. A re-keyed secret keeps its name and so keeps both: they are the same
// addresses, and the same user.
//
// Under liveMu, so that it is one step against admission and against a ban: a
// stream of the removed secret that registers concurrently either took its
// entry before this (and loses it here) or reads the new set after it (and
// takes none), and a ban recorded concurrently either came first (and is
// dropped here) or found the secret gone. The removed secret's streams are
// closed straight after, and give back entries the table no longer holds,
// which touches nothing.
func (p *Proxy) dropRemovedSecrets(oldSet, newSet *secretSet) {
	if oldSet == nil {
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
		p.bans.dropSecret(name)
	}
}

// coverHosts lists the cover sites the set's ee secrets name, each once, in
// name order, with the address domain fronting would dial for it -- where the
// doppelganger measures it. A host with no fronting address is left out. The
// hosts of the set's kept ee retiring keys follow every primary's, in the
// set's order, so a client of an old link gets the server flight sizing it got
// before its secret was rotated.
func (p *Proxy) coverHosts(set *secretSet) []doppel.CoverHost {
	seen := make(map[string]bool)

	var hosts []doppel.CoverHost

	add := func(host string) {
		if host == "" || seen[host] {
			return
		}

		seen[host] = true

		if addr := p.domainFrontingAddressForHost(host); addr != "" {
			hosts = append(hosts, doppel.CoverHost{Host: host, Addr: addr})
		}
	}

	for _, idx := range set.hosted {
		add(set.secrets[idx].Host)
	}

	for r := range set.retiring {
		if entry := &set.retiring[r]; entry.secret.Hosted() {
			add(entry.secret.Host)
		}
	}

	return hosts
}

// applyLimits installs, from the set just swapped in, the limits that are
// enforced on the data path rather than at admission: every user's speed
// bucket is re-rated and their quota ceiling is set, and every address's
// ceiling and fair limiters are moved, so a change reaches the connections
// already open without a reconnect.
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

	p.applyClientLimits(set)
}

// applyClientLimits is applyLimits for the per-address table, in one critical
// section under liveMu, the lock admission takes an entry under: every entry's
// ceiling is moved to its secret's client-speed and its fair limiters to what
// the secret's fair share divides, and then every live stream that has no
// entry and now needs one is given it, made from the set just swapped in.
//
// The limiters are moved whatever the set says about entries. A reload that
// takes away the last per-address control leaves a set that wants no entries
// at all, and the backfill skips its walk then; the entries made while the
// control was there are still held by the streams that were open, and their
// ceilings and fair shares have to come off all the same.
func (p *Proxy) applyClientLimits(set *secretSet) {
	if p.clients == nil {
		return
	}

	p.liveMu.Lock()
	defer p.liveMu.Unlock()

	p.clients.applyCeilings(func(name string) (int64, bool) {
		lim, kept := set.limitsOf(name)

		return lim.ClientSpeedBytesPerSecond, kept
	})

	p.clients.applyFair(func(name string) (fairTotals, bool) {
		lim, kept := set.limitsOf(name)

		return lim.fairTotals(), kept
	})

	p.backfillClientsLocked(set)
}

// backfillClientsLocked gives every live stream that has no per-address entry,
// of every secret in set that needs entries, the entry admission would have
// given it: its address's own when it is keyed, the secret's rest entry when it
// is not. A control a reload turned on must reach the connections already open
// -- they live for hours -- and an unkeyed stream left without the rest entry
// would be exactly the ungoverned stream the rest entry exists to prevent. A
// stream that already has an entry keeps it, so a reload that changes nothing
// changes nothing here.
//
// The caller holds liveMu, the same critical section admission takes its entry
// in, so a stream is either admitted before this and backfilled by it, or
// admitted after it from the set already swapped in. A set none of whose
// secrets wants entries (clientEntriesWantedBy) needs none for anyone, and the
// walk is skipped.
func (p *Proxy) backfillClientsLocked(set *secretSet) {
	if p.clients == nil || !p.clientEntriesWantedBy(set) {
		return
	}

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

			sc.addrEntry.Store(p.clients.acquire(name, sc.addrKey, sc.addrKeyed, entryInitOf(lim)))
		}
	}
}

// closeStaleConns closes every live stream whose key newSet no longer accepts
// at now, the swap's own instant, leaves the rest connected, and returns how
// many it closed per name (nil when it closed none). It decides stream by
// stream (D15), for each name in the registry:
//   - a name newSet does not have accepts no key: every stream of it is closed;
//   - a name whose keys the two sets HOLD alike (sameHeldKeys) is skipped
//     whole, the fast path, and staleSkipHook hears of it;
//   - otherwise each stream is closed unless newSet accepts the key it matched
//     (matchedSecretKey) at now.
//
// The fast path compares what the sets hold -- the primary and every retiring
// key, expired or not -- and never what they accept at now. Judged at now,
// the expiry swap's two sets accept the same keys once an overlap has ended,
// the name would be skipped, and the old key's streams would stay open for
// good: no later swap looks at a name whose set holds no retiring key (B1). A
// name the old set lacks holds nothing there, so it never takes the fast path.
// The judgment against newSet at now is belt and braces: a set this swap built
// at now holds no key that has expired by it.
//
// It compares KEYS ALONE, deliberately: a Host change touches nothing on a live
// stream (the FakeTLS handshake is long finished and the fronting host is read
// only on the failure path of a NEW connection) and a Mode change touches
// nothing at all (the three modes share the key and derive identical ciphers),
// so widening the comparison would kill every live stream of every client on a
// hostname edit for no correctness gain.
//
// Streams are snapshotted under liveMu and closed outside it, so each stream's
// own unregister (which also takes the lock) cannot deadlock. staleSkipHook
// runs under liveMu and must not take it.
func (p *Proxy) closeStaleConns(oldSet, newSet *secretSet, now time.Time) map[string]int {
	var (
		stale  []*streamContext
		closed map[string]int
	)

	p.liveMu.Lock()

	for name, conns := range p.liveConns {
		_, kept := newSet.indexOf(name)

		if kept && sameHeldKeys(oldSet, newSet, name) {
			if p.staleSkipHook != nil {
				p.staleSkipHook(name)
			}

			continue
		}

		for sc := range conns {
			if kept && newSet.accepts(name, sc.matchedSecretKey, now) {
				continue
			}

			if closed == nil {
				closed = make(map[string]int)
			}

			closed[name]++

			stale = append(stale, sc)
		}
	}

	p.liveMu.Unlock()

	for _, sc := range stale {
		sc.Close()
	}

	return closed
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
// over, a retiring key's until. It bounds how long a user, or an old key,
// outlives their deadline, and it is short because the sweep is a walk of the
// live registry and nothing more -- unless an overlap has ended, which costs
// one swap.
const denySweepInterval = 5 * time.Second

// startMaintenance runs, until ctx is cancelled, the work that has to happen
// on the clock rather than on an event: every sweepEvery, monthly quota
// periods roll over, overlaps the clock has ended are ended (expireRetiring)
// and streams of users who are now denied are closed;
// every flushEvery, the usage counters are written to usageStateFile if one
// is configured; every clientSweepInterval, the per-address table forgets the
// addresses that have been gone long enough; and every fairTickInterval, fair
// share divides each fair secret's speed among its addresses again.
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
//
// Fair share's ticker is a goroutine of its own. The loop below closes denied
// streams under liveMu and writes the usage file, and a tick held up behind
// either would measure a second that is not one.
func (p *Proxy) startMaintenanceEvery(ctx context.Context, sweepEvery, flushEvery, clientsEvery time.Duration) {
	p.startFairShare(ctx, fairTickInterval)

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
				p.expireRetiring()
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

// startFairShare runs fair share's ticker until ctx is cancelled: one pass
// (tickFairShare) every period. It is one goroutine, and the only one that
// ticks: a tick takes the blocked trackers' windows with it, so a second tick
// beside it would measure next to nothing. Shutdown waits for it.
func (p *Proxy) startFairShare(ctx context.Context, every time.Duration) {
	p.fairWaitGroup.Add(1)

	go func() {
		defer p.fairWaitGroup.Done()

		ticker := time.NewTicker(every)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				p.tickFairShare()
			}
		}
	}()
}

// tickFairShare is one pass of fair share's ticker: every secret of the set as
// it is now whose fair share divides a speed is ticked, each at the table's
// clock as it reads when the secret's turn comes, the clock the data path
// stamps the blocked trackers by. A secret whose fair share is off is not
// ticked at all; a reload that turns it on again makes its next tick a
// baseline.
//
// It takes nothing the tick does not -- the table's lock and the leaf locks
// after it -- so never liveMu or reloadMu: a pass never holds up an admission
// or a reload behind it. It reads the set without a lock, so a pass may tick a
// secret with totals a concurrent reload is replacing, and that is harmless
// either way. A tick with the old totals whose first hold of the table comes
// after the reload's applyFair finds lastTick zeroed, and only takes a
// baseline. A tick whose two holds straddle applyFair publishes nothing: the
// epoch moved. A tick with the new totals that finishes between the set's swap
// and applyFair publishes onto the old limiters, which applyFair then re-rates
// or replaces, forgetting the level of every bucket whose total changed. No
// tick leaves a level for totals that are no longer the secret's.
func (p *Proxy) tickFairShare() {
	if p.clients != nil {
		if set := p.secrets.Load(); set != nil {
			for i, name := range set.names {
				if i >= len(set.limits) {
					break
				}

				if totals := set.limits[i].fairTotals(); totals != (fairTotals{}) {
					p.clients.tick(p.clients.clock.read(), fairSecret{name: name, totals: totals})
				}
			}
		}
	}

	if p.afterFairPass != nil {
		p.afterFairPass()
	}
}
