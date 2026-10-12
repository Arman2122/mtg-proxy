package config

import (
	"bytes"
	"cmp"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/Arman2122/mtg-proxy/mtglib"
)

// [[retiring-secret]] is the previous key of a secret, still accepted until an
// absolute until after the secret was given a new key. The file is the only
// source of these grants, and losing one only ever kills an old key early,
// never revives one (R0). So a problem in an entry drops that entry and never
// refuses the load: GetRetiringSecrets reports it, run logs it at Warning, and
// run --check refuses the file.
//
// A retiring value is a credential, and nothing here formats one. Every
// reason is a fixed phrase. Secret.Set's error text is discarded: it is not the
// place that decides what a log line may carry. A line carries the entry's
// position, its name and, for over-long entries, the fact that until is far
// away, and never its value. Two kinds of name are not echoed either: a name
// of the wrong type (an array or an inline table can hold a pasted value; a
// TOML date-time is a wrong type in name and secret), and a string name that
// reads as a value (readsAsAValue).

// The wrong-type marks of a ConfigRetiringSecret, one bit per field: the TOML
// value was not a string, or, for until, neither a string nor an offset
// date-time.
const (
	retiringNameWrongType uint8 = 1 << iota
	retiringSecretWrongType
	retiringUntilWrongType
)

// The reasons a problem line gives, in the order rule 1 checks the fields,
// then rules 3, 5 and 8.
const (
	retiringNameMissing   = "name is missing or empty"
	retiringNameNotString = "name is not a string"

	retiringSecretMissing   = "secret is missing or empty"
	retiringSecretNotString = "secret is not a string"
	retiringSecretInvalid   = "secret is not a valid secret value (hex or base64url, in the ee, dd or plain form)"
	retiringSecretZeroKey   = "secret has an all-zero key"

	retiringUntilMissing = "until is missing or empty"
	retiringUntilInvalid = "until is not an RFC 3339 date-time with an offset, such as 2026-10-09T09:30:00Z"

	retiringDangling        = "name is not a configured secret"
	retiringDanglingDefault = `name "default" is the top-level secret, which is not served while [secrets] is present`

	retiringPrimaryOfOther = "the key is another secret's primary key"
	retiringKeyOfOther     = "the key is also the key of a retiring-secret entry of another name"
)

// The rest of each line, after its label. The 720h is spelled out: the
// constant formats as 720h0m0s.
const (
	retiringProblemTail = "; the entry is ignored and its key is not accepted"
	retiringOverLong    = ": until is more than 720h away; it is honoured, but an overlap is a " +
		"migration window, not a second key: shorten it (run --check refuses this file)"
	retiringOwnPrimaryNote = ": the key is the secret's own primary; the entry changes nothing"
	retiringDuplicateNote  = ": the same key as another entry of this name; the later until is kept"
)

// retiringMisplacedUser is the line for a [secrets] user named retiring-secret
// (misplacedRetiringUser), which is never served. It names the mis-edit and the
// right syntax, and never the value.
const retiringMisplacedUser = `a [secrets] user named "retiring-secret" is ignored: ` +
	`[[retiring-secret]] blocks go in their own table, above or between the other tables, one per old key`

// The per-name and overall caps of rule 8, as their lines say them.
var (
	retiringOverCapName = fmt.Sprintf(
		"more than %d unexpired entries for this name; only the %d with the latest until are kept",
		mtglib.MaxRetiringPerSecret, mtglib.MaxRetiringPerSecret)
	retiringOverCapAll = fmt.Sprintf(
		"more than %d unexpired entries in all; only the %d with the latest until are kept",
		mtglib.MaxRetiringSecrets, mtglib.MaxRetiringSecrets)
)

// RetiringReport is what GetRetiringSecrets makes of the [[retiring-secret]]
// table at one instant.
//
// Never format a RetiringReport, or an element of Usable, with %v, %s or %+v:
// a Secret's String() is its value.
type RetiringReport struct {
	// Usable is what the engine is handed, in file order. A rule-4 entry
	// (until more than 720h away) is in it: it is warned about, not dropped.
	Usable []mtglib.RetiringSecret

	// Lines has one line per problem or warning, in file order, after a first
	// line for a [secrets] user named retiring-secret when the file has one
	// (the mis-edit GetSecrets never serves). run and the reloader log each at
	// Warning; run --check refuses the file for any.
	Lines []string

	// Expired counts the entries rule 2 made inert: until is not after now.
	// They are named nowhere else; the count is the Info summary, doctor's
	// count and the --prune hint.
	Expired int

	// Notes are Info lines, in file order, for entries that change nothing:
	// rule 6 (the secret's own primary key) and rule 7 (a duplicate).
	Notes []string
}

// retiringVerdict is what the rules made of one entry.
type retiringVerdict uint8

const (
	// retiringKept: the entry survives every rule, and is usable.
	retiringKept retiringVerdict = iota
	// retiringProblem: rules 1, 3, 5 or 8 dropped it, with a line.
	retiringProblem
	// retiringInert: rule 2, until is not after now. No line.
	retiringInert
	// retiringOwnPrimary: rule 6, a note.
	retiringOwnPrimary
	// retiringDuplicate: rule 7, a note.
	retiringDuplicate
)

// judgedRetiring is one entry as the rules see it.
type judgedRetiring struct {
	label   string // "retiring-secret #<n>", with ` (name "<name>")` when the name may be shown
	name    string
	secret  mtglib.Secret
	until   time.Time
	verdict retiringVerdict
	reason  string // a problem's reason
}

func (e *judgedRetiring) drop(reason string) {
	e.verdict, e.reason = retiringProblem, reason
}

// GetRetiringSecrets judges the [[retiring-secret]] table at now, by §1.3's
// rules, in order, the first that applies deciding for each entry:
//
//  1. name, secret or until missing, of the wrong type or malformed, or an
//     all-zero key: a problem;
//  2. until is not after now: inert (expired), counted;
//  3. name is not a configured secret: a problem ("default" is one only
//     while [secrets] is empty, as in GetSecrets);
//  4. until is more than 720h after now: a warning, and the entry goes on
//     through rules 5 to 8, which may still drop it;
//  5. the key is another name's primary key, or the key of an entry of
//     another name that passes rule 1, expired and dangling ones included:
//     a problem, for every such entry (a primary is never touched);
//  6. the key is the name's own primary key: a note;
//  7. two unexpired entries of one name share a key: the later until is
//     kept, the other is a note;
//  8. past MaxRetiringPerSecret unexpired entries for a name, or
//     MaxRetiringSecrets in all: the latest until are kept (ties broken by
//     name, then key bytes), the rest are problems.
//
// Before the entries it reports a [secrets] user named retiring-secret, which
// GetSecrets never serves, as a problem line of its own (§1.1, revision 4).
//
// It is pure -- no log, no state, no clock but now -- and Validate never calls
// it: a problem drops its entry under run and never refuses the file. Two
// properties hold for an unchanged file and a later now: what has no line at
// now has no line later (P1), and a key not in Usable at now is not in it later
// (P2, R0). Rule 5 is judged on the text alone, against expired and dangling
// entries too, and rule 8's order is fixed by the entries alone, for P2; rule 4
// is a warning, not a drop, for the same reason.
func (c *Config) GetRetiringSecrets(now time.Time) RetiringReport {
	var report RetiringReport

	// Not an entry, and so not numbered: the old link retired by a line written
	// below [secrets], which GetSecrets drops. A function of the text alone.
	if _, misplaced := c.Secrets[misplacedRetiringUser]; misplaced {
		report.Lines = append(report.Lines, retiringMisplacedUser)
	}

	if len(c.RetiringSecrets) == 0 {
		return report
	}

	primaries := c.GetSecrets()
	entries := make([]judgedRetiring, len(c.RetiringSecrets))

	for i := range c.RetiringSecrets {
		entries[i] = judgeRetiringShape(i+1, &c.RetiringSecrets[i])
	}

	primaryOwners, allOwners := retiringKeyOwners(primaries, entries)

	var survivors []int

	for i := range entries {
		entry := &entries[i]
		if entry.verdict == retiringProblem {
			continue
		}

		primary, configured := primaries[entry.name]

		switch {
		case !now.Before(entry.until):
			entry.verdict = retiringInert
			report.Expired++
		case !configured:
			entry.drop(c.danglingReason(entry.name))
		case allOwners[entry.secret.Key].many:
			reason := retiringKeyOfOther
			if owner, found := primaryOwners[entry.secret.Key]; found && (owner.many || owner.name != entry.name) {
				reason = retiringPrimaryOfOther
			}

			entry.drop(reason)
		case entry.secret.Key == primary.Key:
			entry.verdict = retiringOwnPrimary
		default:
			survivors = append(survivors, i)
		}
	}

	survivors = collapseRetiringDuplicates(entries, survivors)
	capRetiringEntries(entries, survivors)

	overLongAfter := now.Add(mtglib.MaxRetiringOverlap)

	for i := range entries {
		entry := &entries[i]

		switch entry.verdict {
		case retiringKept:
			report.Usable = append(report.Usable, mtglib.RetiringSecret{
				Name:   entry.name,
				Secret: entry.secret,
				Until:  entry.until,
			})

			if entry.until.After(overLongAfter) {
				report.Lines = append(report.Lines, entry.label+retiringOverLong)
			}
		case retiringProblem:
			report.Lines = append(report.Lines, entry.label+": "+entry.reason+retiringProblemTail)
		case retiringOwnPrimary:
			report.Notes = append(report.Notes, entry.label+retiringOwnPrimaryNote)
		case retiringDuplicate:
			report.Notes = append(report.Notes, entry.label+retiringDuplicateNote)
		case retiringInert:
		}
	}

	return report
}

// judgeRetiringShape is rule 1 for the n-th entry: every field present, of
// its type and well formed. It returns the entry with its parsed secret and
// until, or dropped with the first field's reason.
func judgeRetiringShape(n int, raw *ConfigRetiringSecret) judgedRetiring {
	entry := judgedRetiring{label: fmt.Sprintf("retiring-secret #%d", n), name: raw.Name}

	switch {
	case raw.wrongType&retiringNameWrongType != 0:
		entry.drop(retiringNameNotString)

		return entry
	case raw.Name == "":
		entry.drop(retiringNameMissing)

		return entry
	}

	if !readsAsAValue(raw.Name) {
		entry.label = fmt.Sprintf("retiring-secret #%d (name %q)", n, raw.Name)
	}

	switch {
	case raw.wrongType&retiringSecretWrongType != 0:
		entry.drop(retiringSecretNotString)

		return entry
	case raw.Secret == "":
		entry.drop(retiringSecretMissing)

		return entry
	}

	// The error's text is discarded, never shown: the reason is a fixed phrase.
	secret, err := mtglib.ParseSecret(raw.Secret)

	switch {
	case errors.Is(err, mtglib.ErrSecretInvalid):
		entry.drop(retiringSecretZeroKey)

		return entry
	case err != nil || !secret.Valid():
		entry.drop(retiringSecretInvalid)

		return entry
	}

	switch {
	case raw.wrongType&retiringUntilWrongType != 0:
		entry.drop(retiringUntilInvalid)

		return entry
	case raw.Until == "":
		entry.drop(retiringUntilMissing)

		return entry
	}

	until, err := time.Parse(time.RFC3339Nano, raw.Until)
	if err != nil {
		entry.drop(retiringUntilInvalid)

		return entry
	}

	entry.secret, entry.until = secret, until

	return entry
}

// readsAsAValue reports whether text, shown as a name or an until, could be a
// secret value pasted into the wrong field, whole or in part:
//   - it decodes, as hex or as base64 in either alphabet, padded or not, to at
//     least a key's 16 bytes. That covers every text mtglib.ParseSecret
//     accepts, and also the spellings no link uses (standard base64, a wrong
//     prefix, an all-zero key);
//   - or it holds a run that could spell one (holdsAValue, parse_error.go's
//     rule): a value with a space pasted after it, or between other words,
//     decodes as nothing (Task 10's review, M-7).
//
// Either is at least 22 characters of one encoding's alphabet, so a real name
// -- and the help its label gives with a typo -- is not affected. It is a
// display rule only: the entry is judged by its name as written.
func readsAsAValue(text string) bool {
	for _, decode := range []func(string) ([]byte, error){
		hex.DecodeString,
		base64.RawURLEncoding.DecodeString,
		base64.URLEncoding.DecodeString,
		base64.RawStdEncoding.DecodeString,
		base64.StdEncoding.DecodeString,
	} {
		if raw, err := decode(text); err == nil && len(raw) >= mtglib.SecretKeyLength {
			return true
		}
	}

	return holdsAValue(text)
}

// ReadsAsAValue is readsAsAValue for the CLI and internal/rotation, which show
// a name by the same display rule: such a name is never shown.
func ReadsAsAValue(text string) bool { return readsAsAValue(text) }

// danglingReason is rule 3's reason for name: "default" names the top-level
// secret, which GetSecrets serves only while [secrets] is empty.
func (c *Config) danglingReason(name string) string {
	if name == "default" && len(c.Secrets) > 0 {
		return retiringDanglingDefault
	}

	return retiringDangling
}

// retiringOwner is who claims a key, for rule 5: the first name seen with
// it, and whether another name claims it too. Which name is first depends on
// map order, but many does not, and name is read only when many is false.
type retiringOwner struct {
	name string
	many bool
}

type retiringOwners map[[mtglib.SecretKeyLength]byte]retiringOwner

func (o retiringOwners) claim(name string, key [mtglib.SecretKeyLength]byte) {
	owner, seen := o[key]

	switch {
	case !seen:
		o[key] = retiringOwner{name: name}
	case owner.name != name:
		owner.many = true
		o[key] = owner
	}
}

// retiringKeyOwners is rule 5's population: the primaries' claims alone, and
// those of the primaries and of every entry that passes rule 1 -- expired,
// dangling and every other verdict included, so the answer is a function of
// the file's text and no later now can bring a dropped key back. An entry
// that fails rule 1 claims nothing: it is no key a client could hold.
func retiringKeyOwners(primaries map[string]mtglib.Secret, entries []judgedRetiring) (retiringOwners, retiringOwners) {
	primaryOwners := make(retiringOwners, len(primaries))
	allOwners := make(retiringOwners, len(primaries)+len(entries))

	for name, secret := range primaries {
		primaryOwners.claim(name, secret.Key)
		allOwners.claim(name, secret.Key)
	}

	for i := range entries {
		if entries[i].verdict != retiringProblem {
			allOwners.claim(entries[i].name, entries[i].secret.Key)
		}
	}

	return primaryOwners, allOwners
}

// collapseRetiringDuplicates is rule 7: of one name's surviving entries with
// one key, the one with the later until stays and the rest become notes. On a
// tie the earlier mode (ee first), then the lower host, then the earlier entry
// in the file stays, as the engine decides. It returns the survivors left, in
// file order.
func collapseRetiringDuplicates(entries []judgedRetiring, survivors []int) []int {
	type nameKey struct {
		name string
		key  [mtglib.SecretKeyLength]byte
	}

	best := make(map[nameKey]int, len(survivors))

	for _, i := range survivors {
		at := nameKey{name: entries[i].name, key: entries[i].secret.Key}

		other, seen := best[at]

		switch {
		case !seen:
			best[at] = i
		case retiringOutranks(&entries[i], &entries[other]):
			entries[other].verdict = retiringDuplicate
			best[at] = i
		default:
			entries[i].verdict = retiringDuplicate
		}
	}

	return slices.DeleteFunc(survivors, func(i int) bool { return entries[i].verdict != retiringKept })
}

// retiringOutranks reports whether a, of two entries with one name and one
// key, is the one rule 7 keeps over b.
func retiringOutranks(a, b *judgedRetiring) bool {
	if c := a.until.Compare(b.until); c != 0 {
		return c > 0
	}

	if a.secret.Mode != b.secret.Mode {
		return a.secret.Mode < b.secret.Mode
	}

	return a.secret.Host < b.secret.Host
}

// capRetiringEntries is rule 8 over the survivors of rules 1 to 7, which hold
// one key per name. It keeps MaxRetiringPerSecret of each name, ranked by until
// descending then key bytes, then MaxRetiringSecrets of all, ranked by until
// descending, then name, then key bytes, and drops the rest. Both orders are
// fixed by the entries alone -- never by now, never by the file's order -- so
// the entries dropped are the ones that expire first, and every entry ranked
// above a dropped one stays unexpired, and above it, for as long as the
// dropped one does.
func capRetiringEntries(entries []judgedRetiring, survivors []int) {
	keyOf := func(i int) []byte { return entries[i].secret.Key[:] }

	ranked := slices.Clone(survivors)

	slices.SortFunc(ranked, func(a, b int) int {
		if c := cmp.Compare(entries[a].name, entries[b].name); c != 0 {
			return c
		}

		if c := entries[b].until.Compare(entries[a].until); c != 0 {
			return c
		}

		return bytes.Compare(keyOf(a), keyOf(b))
	})

	ofName := 0

	for at, i := range ranked {
		if at == 0 || entries[i].name != entries[ranked[at-1]].name {
			ofName = 0
		}

		ofName++

		if ofName > mtglib.MaxRetiringPerSecret {
			entries[i].drop(retiringOverCapName)
		}
	}

	ranked = slices.DeleteFunc(ranked, func(i int) bool { return entries[i].verdict != retiringKept })
	if len(ranked) <= mtglib.MaxRetiringSecrets {
		return
	}

	slices.SortFunc(ranked, func(a, b int) int {
		if c := entries[b].until.Compare(entries[a].until); c != 0 {
			return c
		}

		if c := cmp.Compare(entries[a].name, entries[b].name); c != 0 {
			return c
		}

		return bytes.Compare(keyOf(a), keyOf(b))
	})

	for _, i := range ranked[mtglib.MaxRetiringSecrets:] {
		entries[i].drop(retiringOverCapAll)
	}
}
