package mtglib

import (
	"fmt"
	"maps"
	"math/rand/v2"
	"slices"
	"testing"
	"time"

	"github.com/Arman2122/mtg-proxy/mtglib/internal/doppel"
	"github.com/Arman2122/mtg-proxy/mtglib/internal/tls/fake"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The secret set with retiring keys: how buildSecretSetAt classifies the
// entries it is handed, where the kept ones sit in the set, and the helpers
// the doors and the swap read them through.

// rotationNow is the instant these tests build their sets at. It is a fixed
// date and never time.Now(), so no monotonic reading rides on a time a test
// compares.
var rotationNow = time.Date(2026, 10, 8, 9, 30, 0, 0, time.UTC)

// rotationAt is rotationNow moved by d.
func rotationAt(d time.Duration) time.Time {
	return rotationNow.Add(d)
}

func retire(name string, secret Secret, until time.Time) RetiringSecret {
	return RetiringSecret{Name: name, Secret: secret, Until: until}
}

func dropOf(name string, until time.Time, reason string) retiringDrop {
	return retiringDrop{name: name, until: until, reason: reason}
}

// keptEntries is what a set kept, in the set's own order, spelled as the
// entries a caller hands in. nil when it kept none.
func keptEntries(set *secretSet) []RetiringSecret {
	var out []RetiringSecret

	for _, e := range set.retiring {
		out = append(out, retire(set.names[e.nameIdx], e.secret, e.until))
	}

	return out
}

// rotationPrimaries is alice (ee), bob (dd) and carol (ee), on keys 10, 40 and
// 70. The entries below use keys from 100 up unless a row means to collide.
func rotationPrimaries() map[string]Secret {
	return map[string]Secret{
		"alice": eeSecretOf(keyFilledFrom(10), candidatesCover),
		"bob":   ddSecretOf(keyFilledFrom(40)),
		"carol": eeSecretOf(keyFilledFrom(70), candidatesCover),
	}
}

// numberedKey is key number n (n < 65536) with marker in every byte after
// the number, so a test can mint thousands of keys that never meet each other
// or a keyFilledFrom key, are never all-zero, and order by bytes as by n.
func numberedKey(marker byte, n int) [SecretKeyLength]byte {
	var key [SecretKeyLength]byte

	key[0], key[1] = byte(n>>8), byte(n)

	for i := 2; i < len(key); i++ {
		key[i] = marker
	}

	return key
}

func adTagFilled(b byte) [AdTagLength]byte {
	var tag [AdTagLength]byte

	for i := range tag {
		tag[i] = b
	}

	return tag
}

// TestTheEngineAppliesTheRetiringRules is E1: the seven drop reasons at engine
// level -- invalid (Secret.Valid() fails), then the §1.3 rules 2, 3, 5, 6, 7
// and 8, in that order -- one row per reason, per invalid shape and per
// precedence.
func TestTheEngineAppliesTheRetiringRules(t *testing.T) {
	t.Parallel()

	k := keyFilledFrom
	ee := func(first byte) Secret { return eeSecretOf(k(first), candidatesCover) }
	dd := func(first byte) Secret { return ddSecretOf(k(first)) }
	hours := func(n int) time.Time { return rotationAt(time.Duration(n) * time.Hour) }

	for _, tc := range []struct {
		name     string
		retiring []RetiringSecret
		kept     []RetiringSecret
		drops    []retiringDrop
	}{
		{
			name:     "an unexpired entry of a configured name is kept",
			retiring: []RetiringSecret{retire("alice", ee(100), hours(1))},
			kept:     []RetiringSecret{retire("alice", ee(100), hours(1))},
		},
		{
			name:     "rule 2: until equal to now is expired",
			retiring: []RetiringSecret{retire("alice", ee(100), rotationNow)},
			drops:    []retiringDrop{dropOf("alice", rotationNow, retiringExpired)},
		},
		{
			name:     "rule 2: until before now is expired",
			retiring: []RetiringSecret{retire("alice", ee(100), hours(-1))},
			drops:    []retiringDrop{dropOf("alice", hours(-1), retiringExpired)},
		},
		{
			name:     "rule 3: a name the set does not hold dangles",
			retiring: []RetiringSecret{retire("ghost", ee(100), hours(1))},
			drops:    []retiringDrop{dropOf("ghost", hours(1), retiringDangling)},
		},
		{
			name:     "rule 5: the key of another name's primary, whatever its mode",
			retiring: []RetiringSecret{retire("alice", ee(40), hours(1))},
			drops:    []retiringDrop{dropOf("alice", hours(1), retiringKeyOfOtherSecret)},
		},
		{
			name:     "rule 5: two names' entries with one key are both dropped",
			retiring: []RetiringSecret{retire("alice", ee(100), hours(1)), retire("carol", dd(100), hours(2))},
			drops: []retiringDrop{
				dropOf("alice", hours(1), retiringKeyOfOtherSecret),
				dropOf("carol", hours(2), retiringKeyOfOtherSecret),
			},
		},
		{
			name:     "rule 5: an expired entry still collides",
			retiring: []RetiringSecret{retire("alice", ee(100), hours(1)), retire("carol", ee(100), hours(-1))},
			drops: []retiringDrop{
				dropOf("alice", hours(1), retiringKeyOfOtherSecret),
				dropOf("carol", hours(-1), retiringExpired),
			},
		},
		{
			name:     "rule 5: a dangling entry still collides",
			retiring: []RetiringSecret{retire("ghost", ee(100), hours(1)), retire("alice", ee(100), hours(1))},
			drops: []retiringDrop{
				dropOf("ghost", hours(1), retiringDangling),
				dropOf("alice", hours(1), retiringKeyOfOtherSecret),
			},
		},
		{
			name:     "rule 5 comes before rule 6",
			retiring: []RetiringSecret{retire("alice", ee(10), hours(1)), retire("bob", dd(10), hours(1))},
			drops: []retiringDrop{
				dropOf("alice", hours(1), retiringKeyOfOtherSecret),
				dropOf("bob", hours(1), retiringKeyOfOtherSecret),
			},
		},
		{
			name:     "rule 6: its own primary's key, whatever its mode",
			retiring: []RetiringSecret{retire("alice", dd(10), hours(1))},
			drops:    []retiringDrop{dropOf("alice", hours(1), retiringSameAsPrimary)},
		},
		{
			name:     "rule 7: a duplicate keeps the later until",
			retiring: []RetiringSecret{retire("alice", ee(100), hours(1)), retire("alice", ee(100), hours(3))},
			kept:     []RetiringSecret{retire("alice", ee(100), hours(3))},
			drops:    []retiringDrop{dropOf("alice", hours(1), retiringDuplicate)},
		},
		{
			name:     "rule 7: whichever of the two comes first",
			retiring: []RetiringSecret{retire("alice", ee(100), hours(3)), retire("alice", dd(100), hours(1))},
			kept:     []RetiringSecret{retire("alice", ee(100), hours(3))},
			drops:    []retiringDrop{dropOf("alice", hours(1), retiringDuplicate)},
		},
		{
			name:     "rule 7 is among unexpired entries only",
			retiring: []RetiringSecret{retire("alice", ee(100), hours(-1)), retire("alice", ee(100), hours(1))},
			kept:     []RetiringSecret{retire("alice", ee(100), hours(1))},
			drops:    []retiringDrop{dropOf("alice", hours(-1), retiringExpired)},
		},
		{
			name: "rule 8: past four for one name, the earliest go",
			retiring: []RetiringSecret{
				retire("alice", ee(100), hours(1)),
				retire("alice", ee(101), hours(5)),
				retire("alice", ee(102), hours(3)),
				retire("alice", ee(103), hours(2)),
				retire("alice", ee(104), hours(4)),
			},
			kept: []RetiringSecret{
				retire("alice", ee(101), hours(5)),
				retire("alice", ee(104), hours(4)),
				retire("alice", ee(102), hours(3)),
				retire("alice", ee(103), hours(2)),
			},
			drops: []retiringDrop{dropOf("alice", hours(1), retiringOverCap)},
		},
		{
			name:     "rule 4 is not the engine's: an until past 720h is kept",
			retiring: []RetiringSecret{retire("alice", ee(100), rotationAt(MaxRetiringOverlap+time.Hour))},
			kept:     []RetiringSecret{retire("alice", ee(100), rotationAt(MaxRetiringOverlap+time.Hour))},
		},
		{
			name:     "expired and dangling is expired",
			retiring: []RetiringSecret{retire("ghost", ee(100), hours(-1))},
			drops:    []retiringDrop{dropOf("ghost", hours(-1), retiringExpired)},
		},
		{
			name:     "dangling and on another name's key is dangling",
			retiring: []RetiringSecret{retire("ghost", ee(10), hours(1))},
			drops:    []retiringDrop{dropOf("ghost", hours(1), retiringDangling)},
		},
		{
			name:     "expired and on another name's key is expired",
			retiring: []RetiringSecret{retire("alice", ee(70), hours(-1))},
			drops:    []retiringDrop{dropOf("alice", hours(-1), retiringExpired)},
		},
		{
			name:     "invalid: the zero Secret, a caller that forgot it",
			retiring: []RetiringSecret{retire("alice", Secret{}, hours(1))},
			drops:    []retiringDrop{dropOf("alice", hours(1), retiringInvalid)},
		},
		{
			name:     "invalid: an all-zero key on an ee value with a host",
			retiring: []RetiringSecret{retire("alice", eeSecretOf([SecretKeyLength]byte{}, candidatesCover), hours(1))},
			drops:    []retiringDrop{dropOf("alice", hours(1), retiringInvalid)},
		},
		{
			name:     "invalid: an all-zero key on a dd value",
			retiring: []RetiringSecret{retire("bob", ddSecretOf([SecretKeyLength]byte{}), hours(1))},
			drops:    []retiringDrop{dropOf("bob", hours(1), retiringInvalid)},
		},
		{
			name:     "invalid: an all-zero key on a plain value",
			retiring: []RetiringSecret{retire("carol", plainSecretOf([SecretKeyLength]byte{}), hours(1))},
			drops:    []retiringDrop{dropOf("carol", hours(1), retiringInvalid)},
		},
		{
			name:     "invalid: an ee value with no host",
			retiring: []RetiringSecret{retire("alice", eeSecretOf(k(100), ""), hours(1))},
			drops:    []retiringDrop{dropOf("alice", hours(1), retiringInvalid)},
		},
		{
			name:     "invalid comes before expired",
			retiring: []RetiringSecret{retire("alice", Secret{}, hours(-1))},
			drops:    []retiringDrop{dropOf("alice", hours(-1), retiringInvalid)},
		},
		{
			name:     "invalid comes before dangling",
			retiring: []RetiringSecret{retire("ghost", eeSecretOf(k(100), ""), hours(1))},
			drops:    []retiringDrop{dropOf("ghost", hours(1), retiringInvalid)},
		},
		{
			name:     "invalid comes before its own primary's key",
			retiring: []RetiringSecret{retire("alice", eeSecretOf(k(10), ""), hours(1))},
			drops:    []retiringDrop{dropOf("alice", hours(1), retiringInvalid)},
		},
		{
			name: "an invalid entry is no duplicate of a valid one with its key",
			retiring: []RetiringSecret{
				retire("alice", eeSecretOf(k(100), ""), hours(3)),
				retire("alice", ee(100), hours(1)),
			},
			kept:  []RetiringSecret{retire("alice", ee(100), hours(1))},
			drops: []retiringDrop{dropOf("alice", hours(3), retiringInvalid)},
		},
		{
			name: "an invalid entry takes no part in rule 5",
			retiring: []RetiringSecret{
				retire("carol", eeSecretOf(k(100), ""), hours(1)),
				retire("alice", ee(100), hours(1)),
				retire("ghost", eeSecretOf(k(101), ""), hours(-1)),
				retire("bob", dd(101), hours(2)),
			},
			kept: []RetiringSecret{
				retire("alice", ee(100), hours(1)),
				retire("bob", dd(101), hours(2)),
			},
			drops: []retiringDrop{
				dropOf("carol", hours(1), retiringInvalid),
				dropOf("ghost", hours(-1), retiringInvalid),
			},
		},
		{
			name: "drops come in input order, the kept in the set's",
			retiring: []RetiringSecret{
				retire("carol", ee(110), hours(1)),
				retire("ghost", ee(111), hours(1)),
				retire("alice", ee(112), hours(1)),
				retire("alice", ee(113), hours(2)),
				retire("bob", dd(114), hours(1)),
				retire("alice", ee(115), hours(-1)),
			},
			kept: []RetiringSecret{
				retire("alice", ee(113), hours(2)),
				retire("alice", ee(112), hours(1)),
				retire("bob", dd(114), hours(1)),
				retire("carol", ee(110), hours(1)),
			},
			drops: []retiringDrop{
				dropOf("ghost", hours(1), retiringDangling),
				dropOf("alice", hours(-1), retiringExpired),
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			handed := tc.retiring
			before := slices.Clone(handed)

			set, drops := buildSecretSetAt(rotationPrimaries(), nil, nil, nil, handed, rotationNow)

			assert.Equal(t, tc.kept, keptEntries(set), "the entries kept, in the set's order")
			assert.Equal(t, tc.drops, drops, "the drops, in input order")
			assert.Equal(t, before, handed, "the caller's slice is not rewritten by the build")

			// A primary is never touched, whatever its entries do.
			today := frozenBuildSecretSet(rotationPrimaries(), nil, nil, nil)
			assert.Equal(t, today.names, set.names)
			assert.Equal(t, today.secrets, set.secrets)
			assert.Equal(t, today.cands, set.cands[:set.primaryEnd()])
			assert.Equal(t, today.candByName, set.candByName)
			assert.Equal(t, today.frontHost, set.frontHost)
		})
	}
}

func TestRetiringEntriesAreOrderedDeterministically(t *testing.T) {
	t.Parallel()

	k := keyFilledFrom
	hours := func(n int) time.Time { return rotationAt(time.Duration(n) * time.Hour) }

	entries := []RetiringSecret{
		retire("carol", eeSecretOf(k(120), candidatesCover), hours(2)),
		retire("alice", eeSecretOf(k(101), candidatesCover), hours(2)),
		retire("alice", eeSecretOf(k(100), candidatesCover), hours(2)),
		retire("alice", ddSecretOf(k(102)), hours(3)),
		retire("bob", eeSecretOf(k(110), "b.example.org"), hours(1)),
		retire("bob", plainSecretOf(k(111)), hours(1)),
		// One key twice for alice at one until, under two hosts: the value
		// decides which stays, not which came first.
		retire("alice", eeSecretOf(k(103), "b.example.org"), hours(4)),
		retire("alice", eeSecretOf(k(103), "a.example.org"), hours(4)),
		// Six more for carol, all at one until: the four lowest keys stay.
		retire("carol", eeSecretOf(k(125), candidatesCover), hours(5)),
		retire("carol", eeSecretOf(k(121), candidatesCover), hours(5)),
		retire("carol", eeSecretOf(k(124), candidatesCover), hours(5)),
		retire("carol", eeSecretOf(k(122), candidatesCover), hours(5)),
		retire("carol", eeSecretOf(k(126), candidatesCover), hours(5)),
		retire("carol", eeSecretOf(k(123), candidatesCover), hours(5)),
	}

	build := func(in []RetiringSecret) *secretSet {
		set, _ := buildSecretSetAt(rotationPrimaries(), nil, nil, nil, in, rotationNow)

		return set
	}

	ref := build(entries)

	require.Equal(t, []RetiringSecret{
		retire("alice", eeSecretOf(k(103), "a.example.org"), hours(4)),
		retire("alice", ddSecretOf(k(102)), hours(3)),
		retire("alice", eeSecretOf(k(100), candidatesCover), hours(2)),
		retire("alice", eeSecretOf(k(101), candidatesCover), hours(2)),
		retire("bob", eeSecretOf(k(110), "b.example.org"), hours(1)),
		retire("bob", plainSecretOf(k(111)), hours(1)),
		retire("carol", eeSecretOf(k(121), candidatesCover), hours(5)),
		retire("carol", eeSecretOf(k(122), candidatesCover), hours(5)),
		retire("carol", eeSecretOf(k(123), candidatesCover), hours(5)),
		retire("carol", eeSecretOf(k(124), candidatesCover), hours(5)),
	}, keptEntries(ref), "by name, then until descending, then key bytes")

	reversed := slices.Clone(entries)
	slices.Reverse(reversed)

	orders := [][]RetiringSecret{reversed}
	rng := rand.New(rand.NewPCG(2026, 1008))

	for range 16 {
		shuffled := slices.Clone(entries)
		rng.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })
		orders = append(orders, shuffled)
	}

	for i, order := range orders {
		got := build(order)

		assert.Equal(t, ref.retiring, got.retiring, "retiring, input order %d", i)
		assert.Equal(t, ref.retiringOf, got.retiringOf, "retiringOf, input order %d", i)
		assert.Equal(t, ref.cands, got.cands, "cands, input order %d", i)
		assert.Equal(t, ref.candIdx, got.candIdx, "candIdx, input order %d", i)
		assert.Equal(t, ref.candRetiring, got.candRetiring, "candRetiring, input order %d", i)
		assert.Equal(t, ref.retiringCands, got.retiringCands, "retiringCands, input order %d", i)
		assert.Equal(t, ref.hostnames, got.hostnames, "hostnames, input order %d", i)
	}
}

func TestRetiringCandidatesFollowEveryPrimary(t *testing.T) {
	t.Parallel()

	k := keyFilledFrom
	shared := k(7)
	hours := func(n int) time.Time { return rotationAt(time.Duration(n) * time.Hour) }

	// ccc repeats bbb's key, so it is no candidate of its own; aaa is dd, so
	// its primary is none either.
	primaries := map[string]Secret{
		"aaa": ddSecretOf(k(30)),
		"bbb": eeSecretOf(shared, candidatesCover),
		"ccc": eeSecretOf(shared, "other.example.org"),
		"ddd": plainSecretOf(k(60)),
		"eee": eeSecretOf(k(90), candidatesCover),
	}

	set, drops := buildSecretSetAt(primaries, nil, nil, nil, []RetiringSecret{
		retire("eee", eeSecretOf(k(200), candidatesCover), hours(1)),
		retire("aaa", eeSecretOf(k(201), candidatesCover), hours(2)),
		retire("bbb", ddSecretOf(k(202)), hours(3)),
		retire("eee", plainSecretOf(k(203)), hours(4)),
		retire("eee", eeSecretOf(k(204), candidatesCover), hours(5)),
		retire("bbb", eeSecretOf(k(205), candidatesCover), hours(1)),
		retire("ccc", eeSecretOf(k(206), "other.example.org"), hours(1)),
	}, rotationNow)
	require.Empty(t, drops)

	// The set's order: aaa 201; bbb 202 (dd), 205; ccc 206; eee 204, 203
	// (plain), 200. The ee ones are 0, 2, 3, 4 and 6.
	require.Len(t, set.retiring, 7)

	today := frozenBuildSecretSet(primaries, nil, nil, nil)
	end := set.primaryEnd()

	assert.Equal(t, len(today.cands), end, "the boundary is after today's candidates")
	assert.Equal(t, end, set.primaryCands, "and primaryCands says so on a set with entries")
	assert.Equal(t, today.cands, set.cands[:end], "every primary candidate first, as today")
	assert.Equal(t, today.candIdx, set.candIdx[:end])
	assert.Equal(t, today.candByName, set.candByName, "candByName still means the primary's position")

	assert.Equal(t, []int{0, 2, 3, 4, 6}, set.candRetiring, "only ee entries become candidates, in the set's order")
	require.Len(t, set.cands, end+5)
	require.Len(t, set.candIdx, end+5)

	for j, r := range set.candRetiring {
		pos := end + j
		entry := set.retiring[r]

		assert.Equal(t, entry.nameIdx, set.candIdx[pos], "the candIdx of retiring position %d is its name's index", pos)
		assert.Equal(t, fake.NewCandidate(entry.secret.Key[:]), set.cands[pos], "the candidate at %d is its entry's key", pos)
	}

	assert.Equal(t, map[string][]int{
		"aaa": {end},
		"bbb": {end + 1},
		"ccc": {end + 2},
		"eee": {end + 3, end + 4},
	}, set.retiringCands, "each name's retiring positions, in the set's order, whether or not its primary is a candidate")

	assert.Equal(t, map[int][]int{0: {0}, 1: {1, 2}, 2: {3}, 4: {4, 5, 6}}, set.retiringOf)
}

func TestRetiringHostsJoinTheGateAndTheCoverHostsButNeverFront(t *testing.T) {
	t.Parallel()

	const (
		hostA = "a.example.org"
		hostB = "b.example.org"
		hostC = "c.example.org"
		hostD = "d.example.org"
		hostE = "e.example.org"
	)

	k := keyFilledFrom
	hours := func(n int) time.Time { return rotationAt(time.Duration(n) * time.Hour) }
	p := &Proxy{domainFrontingPort: 443}
	cover := func(host string) doppel.CoverHost { return doppel.CoverHost{Host: host, Addr: host + ":443"} }

	t.Run("beside an ee primary", func(t *testing.T) {
		t.Parallel()

		primaries := map[string]Secret{
			"alice": eeSecretOf(k(10), hostC),
			"bob":   ddSecretOf(k(40)),
		}

		// A dd value that carries a host: only a library caller can make one,
		// and it is valid, so it is kept. It is no ee value, so its host is in
		// neither the gate nor the cover hosts.
		ddCarrying := ddSecretOf(k(106))
		ddCarrying.Host = hostD

		set, drops := buildSecretSetAt(primaries, nil, nil, nil, []RetiringSecret{
			retire("bob", eeSecretOf(k(100), hostA), hours(1)),
			retire("alice", eeSecretOf(k(101), hostB), hours(1)),
			retire("bob", eeSecretOf(k(102), hostC), hours(2)),    // alice's host again
			retire("bob", ddSecretOf(k(103)), hours(1)),           // no host
			retire("alice", eeSecretOf(k(104), hostD), hours(-1)), // expired: its host stays out
			retire("ghost", eeSecretOf(k(105), hostE), hours(1)),  // dangling: so does its
			retire("bob", ddCarrying, hours(1)),                   // kept, and its host stays out
		}, rotationNow)
		require.Len(t, drops, 2, "the expired and the dangling one")
		require.Contains(t, keptEntries(set), retire("bob", ddCarrying, hours(1)))

		today := frozenBuildSecretSet(primaries, nil, nil, nil)

		assert.Equal(t, []string{hostA, hostB, hostC}, set.hostnames, "sorted, each once, the kept ee entries' hosts with the primaries'")
		assert.NotContains(t, set.hostnames, hostD, "a kept dd value's host is not an SNI the gate passes")
		assert.Equal(t, hostC, set.frontHost, "the primaries' front host, as without the entries")
		assert.Equal(t, today.hosted, set.hosted, "hosted is the primaries'")

		// The primaries' hosts in name order, then the entries' in the set's
		// order (alice 101; bob 102, 100, 103, 106), each once, ee ones only.
		assert.Equal(t, []doppel.CoverHost{cover(hostC), cover(hostB), cover(hostA)}, p.coverHosts(set))
		assert.NotContains(t, p.coverHosts(set), cover(hostD), "nor a cover site the doppelganger measures")
	})

	t.Run("a set whose only ee key is retiring", func(t *testing.T) {
		t.Parallel()

		primaries := map[string]Secret{"alice": ddSecretOf(k(10))}

		set, drops := buildSecretSetAt(primaries, nil, nil, nil, []RetiringSecret{
			retire("alice", eeSecretOf(k(100), hostA), hours(1)),
		}, rotationNow)
		require.Empty(t, drops)

		assert.Equal(t, []string{hostA}, set.hostnames, "the gate passes the old link's host while the entry is kept")
		assert.Empty(t, set.frontHost, "a retiring host never fronts")
		assert.Equal(t, SecretsCanFront(primaries, ""), SecretsCanFront(set.toConfig().Secrets, ""),
			"and never lets a set front that could not before")
		assert.False(t, SecretsCanFront(set.toConfig().Secrets, ""))
		assert.Equal(t, []doppel.CoverHost{cover(hostA)}, p.coverHosts(set), "the doppelganger still measures it")
	})
}

func TestRetiringNextIsTheEarliestKeptUntil(t *testing.T) {
	t.Parallel()

	k := keyFilledFrom
	ee := func(first byte) Secret { return eeSecretOf(k(first), candidatesCover) }

	set, _ := buildSecretSetAt(rotationPrimaries(), nil, nil, nil, []RetiringSecret{
		retire("alice", ee(100), rotationAt(3*time.Hour)),
		retire("alice", ee(100), rotationAt(time.Hour)),            // a duplicate: the later until stays
		retire("ghost", ee(101), rotationAt(30*time.Minute)),       // dangling
		retire("carol", ee(102), rotationAt(-time.Hour)),           // expired
		retire("bob", ddSecretOf(k(103)), rotationAt(2*time.Hour)), // the earliest kept
		retire("carol", ee(104), rotationAt(4*time.Hour)),
		retire("bob", ddSecretOf(k(40)), rotationAt(15*time.Minute)), // bob's own primary
	}, rotationNow)

	require.Len(t, set.retiring, 3)
	assert.Equal(t, rotationAt(2*time.Hour), set.retiringNext, "the earliest until among the entries kept, not the entries handed")

	none, drops := buildSecretSetAt(rotationPrimaries(), nil, nil, nil, []RetiringSecret{
		retire("ghost", ee(101), rotationAt(time.Hour)),
	}, rotationNow)
	require.Len(t, drops, 1)
	assert.Zero(t, none.retiringNext, "no entry kept, no next expiry")

	assert.Zero(t, buildSecretSet(rotationPrimaries(), nil, nil, nil).retiringNext)
}

func TestTheOverCapOrderIsFixed(t *testing.T) {
	t.Parallel()

	until := rotationAt(time.Hour)

	// build makes one primary per name and counts[i] entries for names[i],
	// every one at until, with keys numbered upwards in name order, and hands
	// them in shuffled: the order they arrive in must decide nothing.
	build := func(t *testing.T, names []string, counts []int) (*secretSet, []retiringDrop) {
		t.Helper()

		primaries := make(map[string]Secret, len(names))

		var entries []RetiringSecret

		n := 0

		for i, name := range names {
			primaries[name] = plainSecretOf(numberedKey(0x5a, i))

			for range counts[i] {
				entries = append(entries, retire(name, ddSecretOf(numberedKey(0xa5, n)), until))
				n++
			}
		}

		rng := rand.New(rand.NewPCG(4097, 4096))
		rng.Shuffle(len(entries), func(i, j int) { entries[i], entries[j] = entries[j], entries[i] })

		return buildSecretSetAt(primaries, nil, nil, nil, entries, rotationNow)
	}

	// keysOf is the key numbers a set kept for the name at nameIdx.
	keysOf := func(set *secretSet, nameIdx int) []int {
		var out []int

		for _, r := range set.retiringOf[nameIdx] {
			key := set.retiring[r].secret.Key
			out = append(out, int(key[0])<<8|int(key[1]))
		}

		return out
	}

	t.Run("the cut falls between names", func(t *testing.T) {
		t.Parallel()

		// 1,024 names of four make 4,096; zzz holds the 4,097th, and sorts last.
		names := make([]string, 0, 1025)
		counts := make([]int, 0, 1025)

		for i := range 1024 {
			names = append(names, fmt.Sprintf("n%04d", i))
			counts = append(counts, MaxRetiringPerSecret)
		}

		names = append(names, "zzz")
		counts = append(counts, 1)

		set, drops := build(t, names, counts)

		assert.Equal(t, []retiringDrop{dropOf("zzz", until, retiringOverCap)}, drops)
		assert.Len(t, set.retiring, MaxRetiringSecrets)
		assert.Empty(t, keysOf(set, 1024), "zzz kept nothing")
		assert.Equal(t, []int{0, 1, 2, 3}, keysOf(set, 0))
	})

	t.Run("the cut falls inside a name: its highest key goes", func(t *testing.T) {
		t.Parallel()

		// 1,023 names of four and one of one make 4,093; zzz's four make 4,097.
		names := make([]string, 0, 1025)
		counts := make([]int, 0, 1025)

		for i := range 1023 {
			names = append(names, fmt.Sprintf("n%04d", i))
			counts = append(counts, MaxRetiringPerSecret)
		}

		names = append(names, "n1023", "zzz")
		counts = append(counts, 1, MaxRetiringPerSecret)

		set, drops := build(t, names, counts)

		assert.Equal(t, []retiringDrop{dropOf("zzz", until, retiringOverCap)}, drops)
		assert.Len(t, set.retiring, MaxRetiringSecrets)
		assert.Equal(t, []int{4093, 4094, 4095}, keysOf(set, 1024), "zzz keeps its three lowest keys")
		assert.Equal(t, []int{4092}, keysOf(set, 1023))
	})

	t.Run("one name keeps its four latest", func(t *testing.T) {
		t.Parallel()

		hours := func(n int) time.Time { return rotationAt(time.Duration(n) * time.Hour) }
		key := func(n int) Secret { return ddSecretOf(numberedKey(0xa5, n)) }

		set, drops := buildSecretSetAt(rotationPrimaries(), nil, nil, nil, []RetiringSecret{
			retire("alice", key(1), hours(6)),
			retire("alice", key(2), hours(1)),
			retire("alice", key(3), hours(5)),
			retire("alice", key(4), hours(2)),
			retire("alice", key(5), hours(4)),
			retire("alice", key(6), hours(3)),
		}, rotationNow)

		assert.Equal(t, []retiringDrop{
			dropOf("alice", hours(1), retiringOverCap),
			dropOf("alice", hours(2), retiringOverCap),
		}, drops)
		assert.Equal(t, []RetiringSecret{
			retire("alice", key(1), hours(6)),
			retire("alice", key(3), hours(5)),
			retire("alice", key(5), hours(4)),
			retire("alice", key(6), hours(3)),
		}, keptEntries(set))
	})

	t.Run("one name at one until keeps its four lowest keys", func(t *testing.T) {
		t.Parallel()

		set, drops := build(t, []string{"alice", "bob"}, []int{MaxRetiringPerSecret + 1, 1})

		assert.Equal(t, []retiringDrop{dropOf("alice", until, retiringOverCap)}, drops)
		assert.Equal(t, []int{0, 1, 2, 3}, keysOf(set, 0))
		assert.Equal(t, []int{5}, keysOf(set, 1), "the per-name cap is per name")
	})
}

// assertTodaysSet compares got, a set built with no retiring entry kept, with
// want, what today's builder made of the same input: every field today's set
// has, and every field rotation added nil or zero.
func assertTodaysSet(t *testing.T, want, got *secretSet) {
	t.Helper()

	assert.Equal(t, want.names, got.names, "names")
	assert.Equal(t, want.secrets, got.secrets, "secrets")
	assert.Equal(t, want.hostnames, got.hostnames, "hostnames")
	assert.Equal(t, want.cands, got.cands, "cands, compared by value")
	assert.Equal(t, want.candIdx, got.candIdx, "candIdx")
	assert.Equal(t, want.candByName, got.candByName, "candByName")
	assert.Equal(t, want.hosted, got.hosted, "hosted")
	assert.Equal(t, want.frontHost, got.frontHost, "frontHost")
	assert.Equal(t, want.adTags, got.adTags, "adTags")
	assert.Equal(t, want.globalAdTag, got.globalAdTag, "globalAdTag")
	assert.Equal(t, want.limits, got.limits, "limits")
	assert.Equal(t, want.clientControl, got.clientControl, "clientControl")

	assert.Nil(t, got.retiring, "retiring")
	assert.Nil(t, got.retiringOf, "retiringOf")
	assert.Zero(t, got.primaryCands, "primaryCands")
	assert.Nil(t, got.candRetiring, "candRetiring")
	assert.Nil(t, got.retiringCands, "retiringCands")
	assert.Zero(t, got.retiringNext, "retiringNext")

	assert.Equal(t, want, got, "and no other field differs")
}

// TestASetWithoutRetiringIsTodaysSet is E2: a set that keeps no retiring
// entry is, field for field, what the builder made before rotation existed,
// over the candidate fixtures plus ad tags and limits.
func TestASetWithoutRetiringIsTodaysSet(t *testing.T) {
	t.Parallel()

	k := keyFilledFrom
	shared := k(5)
	global := adTagFilled(0x99)

	carrying := ddSecretOf(k(3))
	carrying.Host = candidatesCover

	fixtures := []struct {
		name      string
		secrets   map[string]Secret
		perSecret map[string][AdTagLength]byte
		global    *[AdTagLength]byte
		limits    map[string]SecretLimits
	}{
		{
			name: "the hosted secrets in name order",
			secrets: map[string]Secret{
				"zzz": eeSecretOf(k(1), candidatesCover),
				"aaa": ddSecretOf(k(20)),
				"mmm": eeSecretOf(k(40), candidatesCover),
				"bbb": plainSecretOf(k(60)),
				"ccc": eeSecretOf(k(80), candidatesCover),
			},
			perSecret: map[string][AdTagLength]byte{"mmm": adTagFilled(1)},
			global:    &global,
			limits:    map[string]SecretLimits{"ccc": {QuotaBytes: 1 << 20}, "zzz": {IPLimit: 2}},
		},
		{
			name: "two names, one key",
			secrets: map[string]Secret{
				"alice": eeSecretOf(shared, candidatesCover),
				"bob":   eeSecretOf(shared, "other.example.org"),
			},
			limits: map[string]SecretLimits{"bob": {ClientConns: 3}},
		},
		{
			name: "a repeat among other keys",
			secrets: map[string]Secret{
				"a": eeSecretOf(shared, candidatesCover),
				"b": eeSecretOf(k(50), candidatesCover),
				"c": eeSecretOf(k(90), candidatesCover),
				"d": eeSecretOf(shared, candidatesCover),
			},
			perSecret: map[string][AdTagLength]byte{"d": adTagFilled(2)},
		},
		{
			name: "a hostless secret does not shadow an ee secret with its key",
			secrets: map[string]Secret{
				"aaa": ddSecretOf(shared),
				"zzz": eeSecretOf(shared, candidatesCover),
			},
		},
		{
			name: "names to positions",
			secrets: map[string]Secret{
				"aaa": ddSecretOf(k(30)),
				"bbb": eeSecretOf(shared, candidatesCover),
				"ccc": eeSecretOf(shared, "other.example.org"),
				"ddd": plainSecretOf(k(60)),
				"eee": eeSecretOf(k(90), candidatesCover),
				"fff": eeSecretOf(k(120), candidatesCover),
			},
			perSecret: map[string][AdTagLength]byte{"bbb": adTagFilled(3), "fff": adTagFilled(4)},
			global:    &global,
			limits:    map[string]SecretLimits{"eee": {ClientFair: true, SpeedBytesPerSecond: 1 << 20}},
		},
		{
			name:    "no hosted secret",
			secrets: map[string]Secret{"aaa": ddSecretOf(k(3)), "bbb": plainSecretOf(k(33))},
		},
		{
			name:    "a dd secret carrying a host",
			secrets: map[string]Secret{"aaa": carrying},
		},
		{
			name: "hosts whose name order is not their sorted order",
			secrets: map[string]Secret{
				"a": eeSecretOf(k(10), "zeta.example.org"),
				"b": eeSecretOf(k(50), "alpha.example.org"),
				"c": eeSecretOf(k(90), "mu.example.org"),
				"d": eeSecretOf(k(130), "alpha.example.org"),
			},
			global: &global,
			limits: map[string]SecretLimits{"b": {Disabled: true}, "c": {ClientSpeedBytesPerSecond: 4096}},
		},
	}

	for _, fx := range fixtures {
		t.Run(fx.name, func(t *testing.T) {
			t.Parallel()

			want := frozenBuildSecretSet(fx.secrets, fx.perSecret, fx.global, fx.limits)

			t.Run("buildSecretSet", func(t *testing.T) {
				t.Parallel()

				assertTodaysSet(t, want, buildSecretSet(fx.secrets, fx.perSecret, fx.global, fx.limits))
			})

			t.Run("buildSecretSetAt with no entry", func(t *testing.T) {
				t.Parallel()

				for _, none := range [][]RetiringSecret{nil, {}} {
					got, drops := buildSecretSetAt(fx.secrets, fx.perSecret, fx.global, fx.limits, none, rotationNow)

					assert.Nil(t, drops)
					assertTodaysSet(t, want, got)
				}
			})

			t.Run("buildSecretSetAt with every entry dropped", func(t *testing.T) {
				t.Parallel()

				first := slices.Sorted(maps.Keys(fx.secrets))[0]

				got, drops := buildSecretSetAt(fx.secrets, fx.perSecret, fx.global, fx.limits, []RetiringSecret{
					retire("not-a-secret", eeSecretOf(k(240), candidatesCover), rotationAt(time.Hour)),
					retire(first, eeSecretOf(k(241), candidatesCover), rotationNow),
					retire(first, fx.secrets[first], rotationAt(time.Hour)),
				}, rotationNow)

				require.Len(t, drops, 3)
				assertTodaysSet(t, want, got)
			})
		})
	}
}

// TestToConfigRoundTripsRetiringEntries is E3.
func TestToConfigRoundTripsRetiringEntries(t *testing.T) {
	t.Parallel()

	k := keyFilledFrom
	global := adTagFilled(0x77)
	perSecret := map[string][AdTagLength]byte{"bob": adTagFilled(0x11)}
	limits := map[string]SecretLimits{"carol": {QuotaBytes: 1 << 30, ClientConns: 2}}

	handed := []RetiringSecret{
		retire("carol", plainSecretOf(k(100)), rotationAt(time.Hour)),
		retire("alice", eeSecretOf(k(101), "old.example.org"), rotationAt(2*time.Hour)),
		retire("bob", ddSecretOf(k(102)), rotationAt(3*time.Hour)),
		retire("alice", ddSecretOf(k(103)), rotationAt(MaxRetiringOverlap+time.Hour)),
		retire("ghost", ddSecretOf(k(104)), rotationAt(time.Hour)),
	}
	before := slices.Clone(handed)

	set, drops := buildSecretSetAt(rotationPrimaries(), perSecret, &global, limits, handed, rotationNow)
	require.Len(t, drops, 1, "the dangling one")
	assert.Equal(t, before, handed, "the caller's slice is not rewritten by the build")

	cfg := set.toConfig()

	assert.Equal(t, keptEntries(set), cfg.Retiring, "every kept entry, in the set's order")

	beforeAgain := slices.Clone(cfg.Retiring)

	again, drops := buildSecretSetAt(cfg.Secrets, cfg.SecretAdTags, cfg.GlobalAdTag, cfg.Limits, cfg.Retiring, rotationNow)
	assert.Empty(t, drops, "a set's own entries are all kept again")
	assert.Equal(t, set, again, "and make the same set")
	assert.Equal(t, beforeAgain, cfg.Retiring, "nor is toConfig's")

	assert.Nil(t, buildSecretSet(rotationPrimaries(), nil, nil, nil).toConfig().Retiring, "nil when there are none")
}

// TestForgetDropsTheNamesRetiringEntries is E4.
func TestForgetDropsTheNamesRetiringEntries(t *testing.T) {
	t.Parallel()

	k := keyFilledFrom

	set, _ := buildSecretSetAt(rotationPrimaries(), nil, nil, nil, []RetiringSecret{
		retire("alice", eeSecretOf(k(100), candidatesCover), rotationAt(time.Hour)),
		retire("bob", ddSecretOf(k(101)), rotationAt(2*time.Hour)),
		retire("alice", ddSecretOf(k(102)), rotationAt(3*time.Hour)),
		retire("carol", plainSecretOf(k(103)), rotationAt(time.Hour)),
	}, rotationNow)

	cfg := set.toConfig()
	require.Len(t, cfg.Retiring, 4)

	cfg.forget("alice")

	assert.NotContains(t, cfg.Secrets, "alice")
	assert.Equal(t, []RetiringSecret{
		retire("bob", ddSecretOf(k(101)), rotationAt(2*time.Hour)),
		retire("carol", plainSecretOf(k(103)), rotationAt(time.Hour)),
	}, cfg.Retiring, "the other names' entries stay, in their order")

	cfg.forget("bob")
	cfg.forget("carol")

	assert.Nil(t, cfg.Retiring, "none left is nil, which is what none means")

	// The caller's slice is not rewritten under it.
	handed := []RetiringSecret{
		retire("alice", ddSecretOf(k(100)), rotationAt(time.Hour)),
		retire("bob", ddSecretOf(k(101)), rotationAt(time.Hour)),
	}
	before := slices.Clone(handed)
	own := SecretConfig{Secrets: rotationPrimaries(), Retiring: handed}

	own.forget("alice")

	assert.Equal(t, before, handed)
	assert.Equal(t, before[1:], own.Retiring)
}

func TestMatchesPointIntoTheSet(t *testing.T) {
	t.Parallel()

	k := keyFilledFrom
	shared := k(7)

	// ccc repeats bbb's key, so the candidate positions are not the secrets'
	// indices: aaa (dd) is no candidate either.
	primaries := map[string]Secret{
		"aaa": ddSecretOf(k(30)),
		"bbb": eeSecretOf(shared, candidatesCover),
		"ccc": eeSecretOf(shared, "other.example.org"),
		"ddd": eeSecretOf(k(90), candidatesCover),
	}

	assertPrimaries := func(t *testing.T, set *secretSet) {
		t.Helper()

		for i := range set.secrets {
			m := set.primaryMatch(i)

			assert.Equal(t, i, m.idx)
			assert.Same(t, &set.secrets[i].Key, m.key, "the primary's own key array")
			assert.Equal(t, -1, m.retiring)
		}

		require.Equal(t, []int{1, 3}, set.candIdx[:set.primaryEnd()])

		for pos := range set.primaryEnd() {
			idx := set.candIdx[pos]
			m := set.matchAt(pos)

			assert.Equal(t, idx, m.idx, "position %d", pos)
			assert.Same(t, &set.secrets[idx].Key, m.key, "position %d", pos)
			assert.Equal(t, -1, m.retiring, "position %d", pos)
		}
	}

	t.Run("without retiring entries", func(t *testing.T) {
		t.Parallel()

		set := buildSecretSet(primaries, nil, nil, nil)

		require.Zero(t, set.primaryCands)
		require.Equal(t, len(set.cands), set.primaryEnd())

		assertPrimaries(t, set)
	})

	t.Run("with retiring entries", func(t *testing.T) {
		t.Parallel()

		set, drops := buildSecretSetAt(primaries, nil, nil, nil, []RetiringSecret{
			retire("aaa", eeSecretOf(k(200), candidatesCover), rotationAt(time.Hour)),
			retire("ccc", ddSecretOf(k(201)), rotationAt(2*time.Hour)),
			retire("ccc", eeSecretOf(k(202), candidatesCover), rotationAt(time.Hour)),
		}, rotationNow)
		require.Empty(t, drops)

		require.Equal(t, set.primaryCands, set.primaryEnd())
		require.Equal(t, []int{0, 2}, set.candRetiring)

		assertPrimaries(t, set)

		for r := range set.retiring {
			m := set.retiringMatch(r)

			assert.Equal(t, set.retiring[r].nameIdx, m.idx, "entry %d", r)
			assert.Same(t, &set.retiring[r].secret.Key, m.key, "entry %d: its own key array", r)
			assert.Equal(t, r, m.retiring)
		}

		assert.Equal(t, 2, set.retiringMatch(1).idx, "ccc's dd entry is billed to ccc")

		for j, r := range set.candRetiring {
			pos := set.primaryEnd() + j
			m := set.matchAt(pos)

			assert.Equal(t, set.retiring[r].nameIdx, m.idx, "position %d", pos)
			assert.Same(t, &set.retiring[r].secret.Key, m.key, "position %d", pos)
			assert.Equal(t, r, m.retiring, "position %d", pos)
		}
	})
}

func TestAcceptsJudgesRetiringKeysAtNow(t *testing.T) {
	t.Parallel()

	k := keyFilledFrom
	until := rotationAt(time.Hour)

	set, drops := buildSecretSetAt(rotationPrimaries(), nil, nil, nil, []RetiringSecret{
		retire("alice", eeSecretOf(k(100), candidatesCover), until),
		retire("alice", ddSecretOf(k(101)), rotationAt(2*time.Hour)),
		retire("bob", plainSecretOf(k(102)), until),
	}, rotationNow)
	require.Empty(t, drops)

	primary, old, later, bobs := k(10), k(100), k(101), k(102)

	assert.True(t, set.accepts("alice", old[:], rotationNow))
	assert.True(t, set.accepts("alice", old[:], until.Add(-time.Nanosecond)), "up to the last instant before until")
	assert.False(t, set.accepts("alice", old[:], until), "now == until refuses")
	assert.False(t, set.accepts("alice", old[:], until.Add(time.Hour)))

	assert.True(t, set.accepts("alice", later[:], until), "each entry by its own until")
	assert.True(t, set.accepts("alice", primary[:], until.Add(1000*time.Hour)), "the primary at any time")

	assert.True(t, set.accepts("bob", bobs[:], rotationNow))
	assert.False(t, set.accepts("alice", bobs[:], rotationNow), "bob's old key is not alice's")
	assert.False(t, set.accepts("carol", old[:], rotationNow))
	assert.False(t, set.accepts("ghost", old[:], rotationNow))
	assert.False(t, set.accepts("alice", old[:8], rotationNow), "a partial key")
	assert.False(t, set.accepts("alice", nil, rotationNow))
	assert.False(t, (*secretSet)(nil).accepts("alice", old[:], rotationNow))
}

func TestHeldKeysIgnoreTheClock(t *testing.T) {
	t.Parallel()

	k := keyFilledFrom

	// Every until here is long past on any wall clock, and every set is built
	// at an even earlier now, so it keeps its entries. Held keys are what a set
	// holds: a check that read the clock would see none of them on either side.
	built := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	past := func(n int) time.Time { return built.Add(time.Duration(n) * time.Hour) }

	build := func(t *testing.T, primaries map[string]Secret, entries ...RetiringSecret) *secretSet {
		t.Helper()

		set, drops := buildSecretSetAt(primaries, nil, nil, nil, entries, built)
		require.Empty(t, drops)

		return set
	}

	old, older := k(100), k(101)

	rotated := build(t, rotationPrimaries(),
		retire("alice", eeSecretOf(old, candidatesCover), past(1)),
		retire("alice", ddSecretOf(older), past(2)))
	otherUntils := build(t, rotationPrimaries(),
		retire("alice", ddSecretOf(older), past(5)),
		retire("alice", eeSecretOf(old, "elsewhere.example.org"), past(9)))
	oneRemoved := build(t, rotationPrimaries(),
		retire("alice", ddSecretOf(older), past(2)))
	plain := build(t, rotationPrimaries())

	rekeyedPrimaries := rotationPrimaries()
	rekeyedPrimaries["alice"] = eeSecretOf(k(11), candidatesCover)
	rekeyed := build(t, rekeyedPrimaries)

	withoutAlice := rotationPrimaries()
	delete(withoutAlice, "alice")
	removed := build(t, withoutAlice)

	assert.True(t, sameHeldKeys(rotated, otherUntils, "alice"), "the same keys under other untils, and other modes")
	assert.True(t, sameHeldKeys(rotated, rotated, "alice"))
	assert.True(t, sameHeldKeys(plain, rotated, "bob"), "a name no entry touches")

	assert.False(t, sameHeldKeys(rotated, oneRemoved, "alice"), "a retiring key removed")
	assert.False(t, sameHeldKeys(oneRemoved, rotated, "alice"), "a retiring key added")
	assert.False(t, sameHeldKeys(oneRemoved, plain, "alice"),
		"the last one removed, as the expiry swap does, long after its until")
	assert.False(t, sameHeldKeys(plain, rekeyed, "alice"), "a re-key")

	assert.False(t, sameHeldKeys(plain, removed, "alice"), "a name absent from the new set")
	assert.False(t, sameHeldKeys(removed, plain, "alice"), "a name absent from the old set")
	assert.False(t, sameHeldKeys(plain, plain, "ghost"), "absent from both: nothing held matches nothing")
	assert.False(t, sameHeldKeys(nil, plain, "alice"), "a nil set lacks every name")
	assert.False(t, sameHeldKeys(plain, nil, "alice"))
	assert.False(t, sameHeldKeys(nil, nil, "alice"))
}
