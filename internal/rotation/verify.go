package rotation

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"maps"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/Arman2122/mtg-proxy/internal/config"
	"github.com/Arman2122/mtg-proxy/mtglib"
)

// verify is step 5 of spec §7.3, the safety net: the edited document is
// parsed again with config.Parse, not utils.ParseConfig, whose environment
// overlay and validation would hide or fail the difference, and it must equal
// the old parse in every field but two:
//   - the name's primary, which must be newPrimary after a rotation and be
//     unchanged otherwise;
//   - the retiring entries, which must be the old ones minus the removed ones
//     plus the new one, in the edited file's order, compared whole.
//
// UnknownKeys is compared too, with the keys the document has once the
// removed blocks alone are cut (expectedUnknownKeys): a misspelt field of a
// removed block goes with it, and nothing else may come or go. Validate must
// still pass, the edited file may have no problem line the old one did not
// have, and after a rotation the old key may be accepted only by the new
// block, until exactly the until asked. All of that is ErrEditVerification.
//
// Last, R0 for the tool's own edit: no key may become usable that nothing
// accepts now (revived), which is ErrKeyRevived, named for the block that
// would come back.
func (p *Prepared) verify(out []byte, newPrimary mtglib.Secret) error {
	edited, err := config.Parse(out)
	if err != nil || edited.Validate() != nil {
		return ErrEditVerification
	}

	want := *p.conf
	want.RetiringSecrets = p.expected
	want.UnknownKeys = p.unknownKeys

	if p.req.Rotate {
		p.setPrimary(&want, newPrimary)
	}

	if !reflect.DeepEqual(want, *edited) {
		return ErrEditVerification
	}

	report := edited.GetRetiringSecrets(p.req.Now)

	if len(newLines(p.report.Lines, report.Lines)) > 0 {
		return ErrEditVerification
	}

	if label, revived := p.revived(report, edited.GetSecrets(), newPrimary); revived {
		return revivalError(label)
	}

	if p.req.Rotate {
		if _, _, held := p.keyStillHeld(report); held || (p.addBlock && !p.grantMade(report)) {
			return ErrEditVerification
		}
	}

	return nil
}

// revived finds a key the edit would make usable that nothing accepts now,
// and labels the block it would come back by: its position in the file as it
// is, and its name unless that reads as a value. The keys usable now are the
// primaries and GetRetiringSecrets' usable entries at the run's instant;
// after the edit they must be a subset of those, except for a rotation's new
// primary (the old primary, which the new block holds, is a key usable now).
// Removing one block of a colliding pair (rule 5), or freeing room under a
// cap (rule 8), is what would bring a key back. Keys are compared by their
// bytes, as sets: an edit that takes one key away and brings another back is
// caught although as many keys are usable as before.
func (p *Prepared) revived(after config.RetiringReport, primaries map[string]mtglib.Secret,
	newPrimary mtglib.Secret,
) (string, bool) {
	before := map[[mtglib.SecretKeyLength]byte]bool{}

	for _, secret := range p.conf.GetSecrets() {
		before[secret.Key] = true
	}

	for _, entry := range p.report.Usable {
		before[entry.Secret.Key] = true
	}

	allowed := func(key [mtglib.SecretKeyLength]byte) bool {
		return before[key] || (p.req.Rotate && key == newPrimary.Key)
	}

	for _, entry := range after.Usable {
		if !allowed(entry.Secret.Key) {
			return p.labelFor(entry.Name, entry.Secret.Key, entry.Until), true
		}
	}

	for _, name := range slices.Sorted(maps.Keys(primaries)) {
		if !allowed(primaries[name].Key) {
			return "the primary key of " + shown(name), true
		}
	}

	return "", false
}

// revivalError is ErrKeyRevived for the block labelled so that would come
// back.
func revivalError(label string) error {
	return fmt.Errorf("%w (%s would come back); remove or change that block first", ErrKeyRevived, label)
}

// setPrimary puts s in c as the name's primary, on a copy of the map.
func (p *Prepared) setPrimary(c *config.Config, s mtglib.Secret) {
	if !p.inTable {
		c.Secret = s

		return
	}

	c.Secrets = maps.Clone(c.Secrets)
	c.Secrets[p.req.Name] = s
}

// keyStillHeld finds an entry that would accept the name's current key after
// the rotation other than the new block itself: an older block of the name
// holding it until later (rule 7 keeps the later until), or another name's
// block that only a collision with the primary had silenced. Either would keep
// the key accepted beyond the until asked, or after an overlap of 0.
func (p *Prepared) keyStillHeld(report config.RetiringReport) (string, time.Time, bool) {
	for _, entry := range report.Usable {
		if entry.Secret.Key != p.primary.Key {
			continue
		}

		if p.addBlock && entry.Name == p.req.Name && entry.Until.Equal(p.until) {
			continue
		}

		return entry.Name, entry.Until, true
	}

	return "", time.Time{}, false
}

// grantMade reports whether the new block is honoured: the old key accepted
// for the name until exactly the until written.
func (p *Prepared) grantMade(report config.RetiringReport) bool {
	for _, entry := range report.Usable {
		if entry.Secret.Key == p.primary.Key && entry.Name == p.req.Name && entry.Until.Equal(p.until) {
			return true
		}
	}

	return false
}

// expectedUnknownKeys are the unknown keys the edited file must have: the old
// file's, or, when blocks are removed, those of the document with only the
// removed blocks cut, so that a removed block's misspelt field may go and
// nothing else. The new value and the new block carry no unknown key.
func (p *Prepared) expectedUnknownKeys() ([]string, bool) {
	if len(p.cuts) == 0 {
		return p.conf.UnknownKeys, true
	}

	cut, ok := assemble(p.doc, slices.Clone(p.cuts))
	if !ok {
		return nil, false
	}

	conf, err := config.Parse(cut)
	if err != nil {
		return nil, false
	}

	return conf.UnknownKeys, true
}

// newLines are the problem and warning lines of edited that old does not
// have. A line names its entry by its position in the file, which a removal
// above it, or a block inserted above it, changes; so lines are compared
// without the position, as a multiset: a second copy of a line the file had
// once is a new one.
func newLines(old, edited []string) []string {
	counts := make(map[string]int, len(old))
	for _, line := range old {
		counts[withoutPosition(line)]++
	}

	var added []string

	for _, line := range edited {
		key := withoutPosition(line)
		if counts[key] > 0 {
			counts[key]--

			continue
		}

		added = append(added, line)
	}

	return added
}

// withoutPosition is a line with the n of its "retiring-secret #<n>" label
// taken out.
func withoutPosition(line string) string {
	const label = retiringTable + " #"

	if !strings.HasPrefix(line, label) {
		return line
	}

	end := len(label)
	for end < len(line) && line[end] >= '0' && line[end] <= '9' {
		end++
	}

	return label + line[end:]
}

// readsAsAValue reports whether text could be a secret value: it decodes as
// hex or as base64 in either alphabet, padded or not, to at least a key's 16
// bytes. It is the config package's display rule for a retiring entry's name,
// kept here as a copy because that one is not exported: such a name is never
// shown.
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

	return false
}
