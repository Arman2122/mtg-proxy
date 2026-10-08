package mtglib

import (
	"bytes"
	"cmp"
	"slices"
	"time"

	"github.com/Arman2122/mtg-proxy/mtglib/internal/tls/fake"
)

// Rotation of a secret with an overlap: the retiring keys a secret set holds
// beside its primaries, how buildSecretSetAt decides which of the entries it is
// handed it keeps, and the helpers the doors and the swap read them through.
//
// A retiring key's value is a credential. Nothing here formats a Secret, a
// RetiringSecret or a retiringEntry, and a retiringDrop holds no key: Secret's
// String() IS the value.

// RetiringSecret is a key a secret name still accepts until Until, after the name was
// given a new primary key. Its traffic is the name's: same quota, limits, bans, stats.
type RetiringSecret struct {
	Name   string
	Secret Secret
	Until  time.Time
}

const (
	// MaxRetiringOverlap is the longest overlap a config should grant: an entry
	// whose Until is further than this from the load is warned about by the
	// config layer, refused by run --check and never written by rotate-secret.
	// The engine does not apply it: such an entry is still bounded by its own
	// Until, and dropping it now would accept it again once now has grown.
	MaxRetiringOverlap = 720 * time.Hour

	// MaxRetiringPerSecret is how many retiring keys one name keeps: the ones
	// with the latest Until.
	MaxRetiringPerSecret = 4

	// MaxRetiringSecrets is how many retiring keys a set keeps in all, after
	// the per-name cap: the ones with the latest Until, ties broken by name and
	// then by key bytes.
	MaxRetiringSecrets = 4096
)

// retiringEntry is one retiring key a set keeps: the index of its name in the
// set's names (and secrets, limits, adTags), the old value and when it stops
// being accepted.
type retiringEntry struct {
	nameIdx int
	secret  Secret
	until   time.Time
}

// retiringDrop is a handed entry buildSecretSetAt did not keep, and why, for the
// log. It never holds a key: name and until are not credentials.
type retiringDrop struct {
	name   string
	until  time.Time
	reason string
}

// The seven reasons a retiringDrop gives, in the order the engine applies
// them: first whether the value is one at all (Secret.Valid()), then the §1.3
// rules 2, 3, 5, 6, 7 and 8.
const (
	// retiringInvalid is a value Secret.Valid() refuses: an all-zero key, in
	// any mode, or an ee value with no host -- a library caller that forgot
	// the Secret, say. It is no key a client could hold, and an all-zero key
	// kept as a candidate would let anyone in as the name. It is the config
	// layer's rule 1 at engine level; the engine drops it, never refuses the
	// swap for it.
	retiringInvalid = "invalid"

	// retiringExpired is rule 2: Until is not after now.
	retiringExpired = "expired"

	// retiringDangling is rule 3: the name is not one of the set's secrets.
	retiringDangling = "dangling"

	// retiringKeyOfOtherSecret is rule 5: the key is another name's primary
	// key, or the key of another name's handed entry, expired or dangling
	// included. Every colliding entry is dropped; a primary never is.
	//
	// G101: a log reason, not a credential. gosec matches the identifier, not
	// the value.
	retiringKeyOfOtherSecret = "key_of_other_secret" //nolint:gosec

	// retiringSameAsPrimary is rule 6: the key is the name's own primary key,
	// which accepts it already.
	retiringSameAsPrimary = "same_as_primary"

	// retiringDuplicate is rule 7: the name has another unexpired entry with
	// the same key and a later Until.
	retiringDuplicate = "duplicate"

	// retiringOverCap is rule 8: past MaxRetiringPerSecret for the name, or
	// past MaxRetiringSecrets in all.
	retiringOverCap = "over_cap"
)

// secretMatch is what a door matched: the index of the name it bills
// (names, secrets, limits, adTags), the key the client holds, pointing into
// the set's own arrays, and the index into set.retiring of the entry that key
// belongs to, or -1 for the name's primary.
type secretMatch struct {
	idx      int
	key      *[SecretKeyLength]byte
	retiring int
}

// primaryEnd is where the primaries' candidates end in cands: positions below
// it are primaries, positions from it on are retiring ee keys. It is the
// boundary to use, not primaryCands, which is 0 on a set without retiring
// entries.
func (s *secretSet) primaryEnd() int {
	return len(s.cands) - len(s.candRetiring)
}

// primaryMatch is the match of names[i]'s primary key.
func (s *secretSet) primaryMatch(i int) secretMatch {
	return secretMatch{idx: i, key: &s.secrets[i].Key, retiring: -1}
}

// retiringMatch is the match of retiring[r]'s key, billed to its name.
func (s *secretSet) retiringMatch(r int) secretMatch {
	entry := &s.retiring[r]

	return secretMatch{idx: entry.nameIdx, key: &entry.secret.Key, retiring: r}
}

// matchAt is the match of the candidate at pos in cands.
func (s *secretSet) matchAt(pos int) secretMatch {
	if end := s.primaryEnd(); pos >= end {
		return s.retiringMatch(s.candRetiring[pos-end])
	}

	return s.primaryMatch(s.candIdx[pos])
}

// indexOf is name's index in the set, and false when the set does not hold
// it. A nil set holds nothing.
func (s *secretSet) indexOf(name string) (int, bool) {
	if s == nil {
		return 0, false
	}

	i, found := slices.BinarySearch(s.names, name)
	if !found || i >= len(s.secrets) {
		return 0, false
	}

	return i, true
}

// holdsKey reports whether key is one names[i] holds: its primary, or one of
// its retiring keys, expired or not. It reads no clock.
func (s *secretSet) holdsKey(i int, key [SecretKeyLength]byte) bool {
	if s.secrets[i].Key == key {
		return true
	}

	for _, r := range s.retiringOf[i] {
		if s.retiring[r].secret.Key == key {
			return true
		}
	}

	return false
}

// heldIn reports whether every key s holds for names[i] is held by other for
// its names[j].
func (s *secretSet) heldIn(i int, other *secretSet, j int) bool {
	if !other.holdsKey(j, s.secrets[i].Key) {
		return false
	}

	for _, r := range s.retiringOf[i] {
		if !other.holdsKey(j, s.retiring[r].secret.Key) {
			return false
		}
	}

	return true
}

// sameHeldKeys reports whether oldSet and newSet hold the same keys for name,
// compared as sets: its primary plus every retiring key each set holds,
// expired or not. It reads no clock, on purpose (D15): two sets judged at a
// swap's now would both drop a just-expired key and look alike, and the
// streams on that key would never be closed.
//
// A set that lacks the name holds nothing for it, and a nil set lacks every
// name. Nothing held matches nothing, so the answer is true only when both
// sets hold the name.
func sameHeldKeys(oldSet, newSet *secretSet, name string) bool {
	oldIdx, inOld := oldSet.indexOf(name)
	newIdx, inNew := newSet.indexOf(name)

	if !inOld || !inNew {
		return false
	}

	return oldSet.heldIn(oldIdx, newSet, newIdx) && newSet.heldIn(newIdx, oldSet, oldIdx)
}

// addRetiring puts kept, the retiring entries buildRetiring kept, in the set's
// order, into the set: retiring and retiringOf, the candidates of the ee ones
// appended after every primary candidate, and retiringNext. It does nothing
// when kept is empty, which leaves every one of those fields nil or zero.
func (s *secretSet) addRetiring(kept []retiringEntry) {
	if len(kept) == 0 {
		return
	}

	s.retiring = kept
	s.retiringOf = make(map[int][]int)
	s.primaryCands = len(s.cands)
	s.retiringNext = kept[0].until

	for r := range kept {
		entry := &kept[r]

		s.retiringOf[entry.nameIdx] = append(s.retiringOf[entry.nameIdx], r)

		if entry.until.Before(s.retiringNext) {
			s.retiringNext = entry.until
		}

		// Only an ee key is a FakeTLS candidate, as for a primary. No retiring
		// key equals a primary key (rules 5 and 6) or another kept retiring key
		// (rules 5 and 7), so nothing needs buildCandidates' repeat check.
		if !entry.secret.Hosted() {
			continue
		}

		if s.retiringCands == nil {
			s.retiringCands = make(map[string][]int)
		}

		name := s.names[entry.nameIdx]
		s.retiringCands[name] = append(s.retiringCands[name], len(s.cands))
		s.cands = append(s.cands, fake.NewCandidate(entry.secret.Key[:]))
		s.candIdx = append(s.candIdx, entry.nameIdx)
		s.candRetiring = append(s.candRetiring, r)
	}
}

// keyOwner is who claims a key, for rule 5: the first name seen with it, and
// whether any other name claims it too.
type keyOwner struct {
	name string
	many bool
}

// buildRetiring is the retiring half of buildSecretSetAt. It classifies each
// handed entry against the set's primaries (names sorted, secrets aligned with
// them) at now: first whether its value is valid at all (Secret.Valid()),
// then by the §1.3 rules 2, 3, 5, 6, 7 and 8, in that order, the first that
// applies deciding -- seven reasons in all. It returns the kept entries in the
// set's order (name, then until descending, then key bytes) and the drops in
// input order. Both are nil when nothing is handed, and the kept ones are nil
// when every entry is dropped.
//
// Rule 5 is judged against every valid handed entry, expired and dangling ones
// included, and every primary: a collision that went away when the other
// entry expired would accept again a key it once dropped. The engine applies
// of rule 1 only what Secret.Valid() checks (the rest is the config layer's,
// which parses the value), and not rule 4 (MaxRetiringOverlap).
func buildRetiring(names []string, secrets []Secret, handed []RetiringSecret, now time.Time) ([]retiringEntry, []retiringDrop) {
	if len(handed) == 0 {
		return nil, nil
	}

	owners := make(map[[SecretKeyLength]byte]keyOwner, len(secrets)+len(handed))

	claim := func(name string, key [SecretKeyLength]byte) {
		owner, seen := owners[key]

		switch {
		case !seen:
			owners[key] = keyOwner{name: name}
		case owner.name != name:
			owner.many = true
			owners[key] = owner
		}
	}

	for i := range secrets {
		claim(names[i], secrets[i].Key)
	}

	// An invalid value claims no key. It is no key a client could present (the
	// config layer counts only syntactically valid entries in rule 5 for the
	// same reason), and as a claimant it would drop a valid entry of another
	// name that happens to share its bytes, an ee value with no host, say. It
	// is dropped as invalid below whatever else it is, so leaving it out
	// changes no answer about it, and it is a pure function of the input, so
	// no later now can bring a dropped entry back.
	for j := range handed {
		if handed[j].Secret.Valid() {
			claim(handed[j].Name, handed[j].Secret.Key)
		}
	}

	reasons := make([]string, len(handed))
	nameIdx := make([]int, len(handed))

	var survivors []int

	for j := range handed {
		entry := &handed[j]
		i, found := slices.BinarySearch(names, entry.Name)

		switch {
		case !entry.Secret.Valid():
			reasons[j] = retiringInvalid
		case !now.Before(entry.Until):
			reasons[j] = retiringExpired
		case !found:
			reasons[j] = retiringDangling
		case owners[entry.Secret.Key].many:
			reasons[j] = retiringKeyOfOtherSecret
		case entry.Secret.Key == secrets[i].Key:
			reasons[j] = retiringSameAsPrimary
		default:
			nameIdx[j] = i
			survivors = append(survivors, j)
		}
	}

	survivors = collapseDuplicates(handed, nameIdx, survivors, reasons)
	survivors = capRetiring(handed, nameIdx, survivors, reasons)

	var kept []retiringEntry

	for _, j := range survivors {
		kept = append(kept, retiringEntry{nameIdx: nameIdx[j], secret: handed[j].Secret, until: handed[j].Until})
	}

	var drops []retiringDrop

	for j, reason := range reasons {
		if reason != "" {
			drops = append(drops, retiringDrop{name: handed[j].Name, until: handed[j].Until, reason: reason})
		}
	}

	return kept, drops
}

// collapseDuplicates is rule 7: of one name's surviving entries with one key,
// the one with the later Until stays, and the rest are marked duplicates in
// reasons. Two with one Until differ only in mode or host; the earlier mode
// (ee first), then the lower host, stays, so the order the entries came in
// decides nothing. It returns the survivors left, in their order.
func collapseDuplicates(handed []RetiringSecret, nameIdx, survivors []int, reasons []string) []int {
	type nameKey struct {
		nameIdx int
		key     [SecretKeyLength]byte
	}

	best := make(map[nameKey]int, len(survivors))

	for _, j := range survivors {
		at := nameKey{nameIdx: nameIdx[j], key: handed[j].Secret.Key}

		other, seen := best[at]

		switch {
		case !seen:
			best[at] = j
		case duplicateOutranks(&handed[j], &handed[other]):
			reasons[other] = retiringDuplicate
			best[at] = j
		default:
			reasons[j] = retiringDuplicate
		}
	}

	return slices.DeleteFunc(survivors, func(j int) bool { return reasons[j] != "" })
}

// duplicateOutranks reports whether a is the one of two entries with one name
// and one key that rule 7 keeps over b.
func duplicateOutranks(a, b *RetiringSecret) bool {
	if c := a.Until.Compare(b.Until); c != 0 {
		return c > 0
	}

	if a.Secret.Mode != b.Secret.Mode {
		return a.Secret.Mode < b.Secret.Mode
	}

	return a.Secret.Host < b.Secret.Host
}

// capRetiring is rule 8. It sorts survivors into the set's order (name, then
// Until descending, then key bytes), keeps MaxRetiringPerSecret of each name,
// the first in that order, then MaxRetiringSecrets of all, ranked by Until
// descending, then name, then key bytes, and marks the rest over the cap in
// reasons. The order is fixed by the entries alone, so the entries it drops
// are the ones that expire first, whatever order they came in. It returns the
// survivors left, in the set's order.
func capRetiring(handed []RetiringSecret, nameIdx, survivors []int, reasons []string) []int {
	keyOf := func(j int) []byte { return handed[j].Secret.Key[:] }

	slices.SortFunc(survivors, func(a, b int) int {
		if c := cmp.Compare(nameIdx[a], nameIdx[b]); c != 0 {
			return c
		}

		if c := handed[b].Until.Compare(handed[a].Until); c != 0 {
			return c
		}

		return bytes.Compare(keyOf(a), keyOf(b))
	})

	ofName, name := 0, -1

	for _, j := range survivors {
		if nameIdx[j] != name {
			ofName, name = 0, nameIdx[j]
		}

		ofName++

		if ofName > MaxRetiringPerSecret {
			reasons[j] = retiringOverCap
		}
	}

	survivors = slices.DeleteFunc(survivors, func(j int) bool { return reasons[j] != "" })

	if len(survivors) <= MaxRetiringSecrets {
		return survivors
	}

	ranked := slices.Clone(survivors)

	slices.SortFunc(ranked, func(a, b int) int {
		if c := handed[b].Until.Compare(handed[a].Until); c != 0 {
			return c
		}

		if c := cmp.Compare(nameIdx[a], nameIdx[b]); c != 0 {
			return c
		}

		return bytes.Compare(keyOf(a), keyOf(b))
	})

	for _, j := range ranked[MaxRetiringSecrets:] {
		reasons[j] = retiringOverCap
	}

	return slices.DeleteFunc(survivors, func(j int) bool { return reasons[j] != "" })
}
