package mtglib

import (
	"sort"

	"github.com/Arman2122/mtg-proxy/mtglib/internal/tls/fake"
)

// FROZEN. frozenBuildSecretSet and frozenBuildCandidates are buildSecretSet and
// buildCandidates as they stood before secret rotation, copied from
// `git show 8577930:mtglib/proxy_secrets.go` (identical at 47d2ebf, the commit
// rotation's set building started from). They are verbatim except the two
// function names and the one call inside frozenBuildSecretSet, which calls the
// frozen frozenBuildCandidates: calling the live buildCandidates would make
// TestASetWithoutRetiringIsTodaysSet blind to a change there.
//
// They are what a set holding no retiring key must still be, field for field.
// Never regenerate them from the live code, never edit them to follow it: a
// difference between the two is the finding the test exists to report.

// buildSecretSet turns a name->secret map into an immutable, name-sorted
// snapshot. Sorting keeps names[i] and secrets[i] aligned and makes the
// matched index stable across processes for a given secret map. perSecret
// carries optional per-name advertising tags and global is the fallback tag;
// both may be nil. limitsMap carries optional per-name governance limits and
// may be nil.
func frozenBuildSecretSet(secretsMap map[string]Secret, perSecret map[string][AdTagLength]byte, global *[AdTagLength]byte, limitsMap map[string]SecretLimits) *secretSet {
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

	hostnames := make([]string, 0, len(hostnameSet))
	for h := range hostnameSet {
		hostnames = append(hostnames, h)
	}

	sort.Strings(hostnames)

	cands, candIdx, candByName := frozenBuildCandidates(secretsList, names, hosted)

	return &secretSet{
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
}

// buildCandidates makes the FakeTLS candidates for the hosted secrets (indices
// into secrets, in name order): one Candidate each, with its key's pads hashed
// here, once per set, instead of once per handshake. A later secret whose key an
// earlier hosted one already has is left out. It could only ever match when the
// earlier one does, and the earlier one is tried first, so dropping it changes
// no answer and saves a verification per hello that reaches it. Only HOSTED
// keys count as seen: a dd secret that sorts first and shares a key with an ee
// secret does not shadow it.
func frozenBuildCandidates(secrets []Secret, names []string, hosted []int) ([]*fake.Candidate, []int, map[string]int) {
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
