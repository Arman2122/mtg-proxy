// Package rotation is the edit mtg-proxy rotate-secret makes to an
// operator's config file (spec §7.3), as pure functions over bytes: no
// filesystem, no network, no clock -- the run's one instant is a field of the
// request.
//
// The file is edited surgically, never re-marshalled, so its comments, order,
// quoting and line endings survive: go-toml's unstable parser locates byte
// ranges and the original bytes are spliced. The edit then proves itself by
// parsing the result again: everything but what it meant to change must be
// equal, or nothing is returned.
//
// No value of a retiring key is ever formatted here: a refusal, a warning and
// a Summary carry names, instants and fixed phrases only. A Secret's String()
// is its value, so none is formatted with %v or %s, and a parser error is
// passed on in its Error() form only, flattened, so that no caller can reach
// the DecodeError and its String(), which quotes the document.
package rotation

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/Arman2122/mtg-proxy/internal/config"
	"github.com/Arman2122/mtg-proxy/mtglib"
)

// Request is one run of rotate-secret.
type Request struct {
	// Name is the secret rotated or whose overlap ends: a name in [secrets],
	// or "default" for the single top-level secret. Empty for --prune alone.
	Name string

	// Rotate gives Name a new key. With a non-zero Until the current key is
	// kept, in a new [[retiring-secret]] block, until Until (written in UTC to
	// the second); a zero Until is --overlap 0, and adds no block.
	Rotate bool
	Until  time.Time

	// EndOverlap removes every block of Name, expired or not; Prune removes
	// every expired block, of any name: one whose until is an instant not
	// after Now.
	EndOverlap, Prune bool

	// Now is the run's one instant: what expiry is judged at, and the time in
	// the new block's comment.
	Now time.Time
}

// Summary is what a run does, for people: never a value.
type Summary struct {
	Name string

	// Until is the instant the new block keeps the current key until, as
	// written; zero when no block is added.
	Until time.Time

	// Removed are the blocks removed, in file order.
	Removed []Removed

	// NoOp is a run that changes nothing: --prune with nothing to prune, or
	// --end-overlap for a name without blocks.
	NoOp bool
}

// Removed is one block a run removes. Name is empty when the block's name is
// missing, not a string, or reads as a secret value; Until is empty when it
// is not an RFC 3339 instant. Neither is ever a value.
type Removed struct {
	Name  string
	Until string
}

// ErrEditVerification is an edit whose re-parse shows a change it did not
// mean to make. Nothing is returned to write.
var ErrEditVerification = errors.New("internal error: the edit changed more than it meant to; nothing was written")

// ErrKeyRevived is an edit that would make a key usable that nothing accepts
// now. The error returned wraps it and names the block that would come back.
var ErrKeyRevived = errors.New("removing these blocks would make a key usable again that is not accepted now")

// Prepared is a request judged against a document: located, checked, and
// ready to Apply.
type Prepared struct {
	doc    []byte
	req    Request
	conf   *config.Config
	report config.RetiringReport
	loc    *layout

	primary  mtglib.Secret // the name's primary, before the edit
	inTable  bool          // it is a [secrets] entry, not the top-level secret
	hexValue bool          // its text decodes as hex

	addBlock bool      // a rotation with an overlap
	until    time.Time // the new block's until, as written
	insertAt int       // where the new block goes; -1 for the end of the file

	removed  []int  // the removed blocks, as indices of conf.RetiringSecrets
	cuts     []span // the byte ranges that remove them
	cutToEnd bool   // a cut reaches the end of the document

	expected     []config.ConfigRetiringSecret // the retiring entries after the edit, in file order
	expectedFrom []int                         // each one's index in conf.RetiringSecrets; -1 for the new block
	unknownKeys  []string                      // the unknown keys after the edit
	summary      Summary
}

// Prepare is step 1 of spec §7.3: it reads doc and judges req against it.
//
// It refuses a file config.Parse refuses or Validate fails, with the error's
// Error() form only (a UTF-8 byte-order mark and the scalar
// retiring-secret = "…" are both parse errors); a name that is not served,
// "default" while [secrets] is present, a multi-line string value, retiring
// entries written other than as blocks, and a 5th unexpired entry for the
// name. It locates the primary's string node and every block.
//
// Problems the file already has never refuse it -- an urgent rotation is not
// blocked by an old typo -- and Warnings returns them. Only what the edit
// would add refuses: a problem line the file does not have; a key usable again
// that nothing accepts now (ErrKeyRevived: removing one block of a colliding
// pair, or freeing room under a cap, would bring another back -- R0 holds for
// the tool's own edits too); or the current key still accepted after the
// rotation by a block other than the new one. Nothing is generated here.
func Prepare(doc []byte, req Request) (*Prepared, error) {
	if err := checkRequest(req); err != nil {
		return nil, err
	}

	conf, err := config.Parse(doc)
	if err != nil {
		return nil, errors.New("the config does not load: " + err.Error())
	}

	if err := conf.Validate(); err != nil {
		return nil, errors.New("the config is not valid: " + err.Error())
	}

	p := &Prepared{
		doc:    bytes.Clone(doc),
		req:    req,
		conf:   conf,
		report: conf.GetRetiringSecrets(req.Now),
	}

	var target []string

	if req.Name != "" {
		if target, err = p.resolveName(); err != nil {
			return nil, err
		}
	}

	if p.loc, err = locate(p.doc, target); err != nil {
		return nil, err
	}

	if len(p.loc.blocks) != len(conf.RetiringSecrets) {
		return nil, errors.New("the file's retiring-secret entries are not all [[retiring-secret]] blocks " +
			"(an inline array of tables?); rotate-secret edits only blocks: rewrite them as blocks and retry")
	}

	if err := p.locatePrimary(); err != nil {
		return nil, err
	}

	p.chooseRemovals()

	var cutsParse bool
	if p.unknownKeys, cutsParse = p.expectedUnknownKeys(); !cutsParse {
		return nil, ErrEditVerification
	}

	if err := p.checkNewBlock(); err != nil {
		return nil, err
	}

	p.expected, p.expectedFrom = p.expectedEntries()

	if err := p.simulate(); err != nil {
		return nil, err
	}

	p.summary = p.summarise()

	return p, nil
}

// checkRequest refuses a request that is not one of the command's forms.
func checkRequest(req Request) error {
	switch {
	case req.Now.IsZero():
		return errors.New("the run's instant is not set")
	case req.Rotate && req.EndOverlap:
		return errors.New("a rotation and --end-overlap cannot be asked at once")
	case !req.Rotate && !req.EndOverlap && !req.Prune:
		return errors.New("nothing to do: ask for a rotation, --end-overlap or --prune")
	case (req.Rotate || req.EndOverlap) && req.Name == "":
		return errors.New("a rotation or --end-overlap needs a name")
	case !req.Rotate && !req.EndOverlap && req.Name != "":
		return errors.New("--prune alone takes no name")
	case !req.Rotate && !req.Until.IsZero():
		return errors.New("an until is given without a rotation")
	default:
		return nil
	}
}

// resolveName finds the name's primary and the path of its value: in
// [secrets], or the top-level secret for "default" when that is what
// GetSecrets serves.
func (p *Prepared) resolveName() ([]string, error) {
	primary, served := p.conf.GetSecrets()[p.req.Name]

	switch {
	case served:
	case p.req.Name == "default" && len(p.conf.Secrets) > 0:
		return nil, errors.New(`"default" is not served while [secrets] is present; rotate a name from [secrets]`)
	case readsAsAValue(p.req.Name):
		return nil, errors.New("there is no secret by that name (it is not shown: it reads as a secret value)")
	default:
		return nil, fmt.Errorf("there is no secret named %q", p.req.Name)
	}

	p.primary = primary

	if _, p.inTable = p.conf.Secrets[p.req.Name]; p.inTable {
		return []string{"secrets", p.req.Name}, nil
	}

	return []string{"secret"}, nil
}

// locatePrimary checks the primary's string node, which a rotation splices:
// it must be found, and be a one-line string.
func (p *Prepared) locatePrimary() error {
	value := p.loc.target
	p.hexValue = value.found && !value.notString && isHex(value.text)

	if !p.req.Rotate {
		return nil
	}

	if !value.found || value.notString {
		return fmt.Errorf("the value of %q cannot be found in the file for editing; edit it by hand", p.req.Name)
	}

	if raw := p.doc[value.start:value.end]; bytes.HasPrefix(raw, []byte(`"""`)) || bytes.HasPrefix(raw, []byte(`'''`)) {
		return fmt.Errorf("the value of %q is a multi-line string, which rotate-secret does not edit: "+
			`write it on one line, between "" or '', and retry`, p.req.Name)
	}

	return nil
}

// isHex reports whether text decodes as hex, the first spelling
// mtglib.Secret.Set tries.
func isHex(text string) bool {
	_, err := hex.DecodeString(text)

	return err == nil
}

// chooseRemovals picks the blocks the run removes and the byte ranges that
// remove them.
func (p *Prepared) chooseRemovals() {
	var blocks []block

	for i, b := range p.loc.blocks {
		entry := p.conf.RetiringSecrets[i]
		remove := p.req.EndOverlap && entry.Name == p.req.Name

		if p.req.Prune {
			if until, err := time.Parse(time.RFC3339Nano, entry.Until); err == nil && !p.req.Now.Before(until) {
				remove = true
			}
		}

		if remove {
			p.removed = append(p.removed, i)
			blocks = append(blocks, b)
		}
	}

	p.cuts = p.loc.cuts(blocks)
	p.cutToEnd = len(p.cuts) > 0 && p.cuts[len(p.cuts)-1].end == len(p.doc)
}

// checkNewBlock judges the block a rotation with an overlap adds: its until,
// the name's cap, and a single-table block it cannot sit beside.
func (p *Prepared) checkNewBlock() error {
	p.insertAt = p.loc.insertionPoint()
	p.addBlock = p.req.Rotate && !p.req.Until.IsZero()

	if !p.addBlock {
		return nil
	}

	p.until = p.req.Until.UTC().Truncate(time.Second)

	switch {
	case !p.until.After(p.req.Now):
		return fmt.Errorf("until %s is not after now (%s)",
			p.until.Format(time.RFC3339), p.req.Now.UTC().Format(time.RFC3339))
	case p.until.After(p.req.Now.Add(mtglib.MaxRetiringOverlap)):
		return fmt.Errorf("until %s is more than 720h after now (%s)",
			p.until.Format(time.RFC3339), p.req.Now.UTC().Format(time.RFC3339))
	}

	for i, b := range p.loc.blocks {
		if b.single && !slices.Contains(p.removed, i) {
			return errors.New("the file has a [retiring-secret] table with one pair of brackets, and a " +
				"[[retiring-secret]] block cannot be added beside it: write its header as [[retiring-secret]] and retry")
		}
	}

	held := 0

	for _, entry := range p.report.Usable {
		if entry.Name == p.req.Name {
			held++
		}
	}

	if held >= mtglib.MaxRetiringPerSecret {
		return fmt.Errorf("%q already has %d unexpired previous keys, the most one secret can have: "+
			"end them with --end-overlap, or wait for one to expire, and retry", p.req.Name, held)
	}

	return nil
}

// expectedEntries are the retiring entries the edited file must parse to:
// the old ones the run keeps and the new block's, in the edited file's order,
// nil for none; and, for each, its index in the old file's entries, -1 for
// the new block's.
func (p *Prepared) expectedEntries() ([]config.ConfigRetiringSecret, []int) {
	type placed struct {
		at    int
		from  int
		entry config.ConfigRetiringSecret
	}

	var all []placed

	for i, b := range p.loc.blocks {
		if !slices.Contains(p.removed, i) {
			all = append(all, placed{at: b.start, from: i, entry: p.conf.RetiringSecrets[i]})
		}
	}

	if p.addBlock {
		at := p.insertAt
		if at < 0 {
			at = len(p.doc) + 1
		}

		all = append(all, placed{at: at, from: -1, entry: config.ConfigRetiringSecret{
			Name:   p.req.Name,
			Secret: p.loc.target.text,
			Until:  p.until.Format(time.RFC3339),
		}})
	}

	slices.SortStableFunc(all, func(a, b placed) int { return a.at - b.at })

	var (
		entries []config.ConfigRetiringSecret
		from    []int
	)

	for _, item := range all {
		entries = append(entries, item.entry)
		from = append(from, item.from)
	}

	return entries, from
}

// simulate judges the edited file before there is one: the expected entries,
// with a placeholder key no entry holds as the name's new primary. A problem
// line the file does not have, a key usable again that nothing accepts now,
// or the current key still accepted by a block other than the new one,
// refuses the run here, in words, instead of in Apply.
func (p *Prepared) simulate() error {
	sim := *p.conf
	sim.RetiringSecrets = p.expected

	var placeholder mtglib.Secret

	if p.req.Rotate {
		placeholder = p.placeholder()
		p.setPrimary(&sim, placeholder)
	}

	report := sim.GetRetiringSecrets(p.req.Now)

	if added := newLines(p.report.Lines, report.Lines); len(added) > 0 {
		return errors.New("the edit would add a problem the file does not have: " + strings.Join(added, "; and "))
	}

	if name, revived := p.revived(report, sim.GetSecrets(), placeholder); revived {
		return revivalError(name)
	}

	if !p.req.Rotate {
		return nil
	}

	if holder, until, held := p.keyStillHeld(report); held {
		return fmt.Errorf("the current key of %q would still be accepted until %s by %s; "+
			"remove that block with --end-overlap or --prune, or edit it, then rotate",
			p.req.Name, until.UTC().Format(time.RFC3339), p.holderLabel(holder, until))
	}

	return nil
}

// holderLabel names, as the config layer labels its entries, the block of the
// file that keyStillHeld found holding the current key: its position in the
// file and, unless it reads as a value, its name.
func (p *Prepared) holderLabel(name string, until time.Time) string {
	for i, entry := range p.expected {
		if p.expectedFrom[i] < 0 || entry.Name != name {
			continue
		}

		secret, secretErr := mtglib.ParseSecret(entry.Secret)
		at, untilErr := time.Parse(time.RFC3339Nano, entry.Until)

		if secretErr == nil && untilErr == nil && secret.Key == p.primary.Key && at.Equal(until) {
			return entryLabel(p.expectedFrom[i]+1, name)
		}
	}

	return entryLabel(0, name)
}

// entryLabel is the config layer's label for the n-th entry of the file:
// retiring-secret #<n> (name "<name>"), without the name when it reads as a
// value, and without the position when it is not known (n = 0).
func entryLabel(n int, name string) string {
	label := "a retiring-secret block"
	if n > 0 {
		label = fmt.Sprintf("retiring-secret #%d", n)
	}

	if !readsAsAValue(name) {
		label += fmt.Sprintf(" (name %q)", name)
	}

	return label
}

// placeholder is a stand-in for the new primary: the current one's mode and
// host, and a key that no primary and no entry of the file holds.
func (p *Prepared) placeholder() mtglib.Secret {
	taken := map[[mtglib.SecretKeyLength]byte]bool{}

	for _, secret := range p.conf.GetSecrets() {
		taken[secret.Key] = true
	}

	for _, entry := range p.conf.RetiringSecrets {
		if secret, err := mtglib.ParseSecret(entry.Secret); err == nil {
			taken[secret.Key] = true
		}
	}

	key := [mtglib.SecretKeyLength]byte{0x5a, 0xa5, 0x5a, 0xa5, 0x5a, 0xa5, 0x5a, 0xa5, 0x5a, 0xa5, 0x5a, 0xa5, 0x5a, 0xa5, 0x5a, 0xa5}
	for taken[key] {
		key[len(key)-1]++
	}

	return mtglib.Secret{Key: key, Host: p.primary.Host, Mode: p.primary.Mode}
}

// summarise is the run's Summary. A removed block's name is shown only when
// it is a string that does not read as a value, and its until only when it is
// an RFC 3339 instant, which no value is.
func (p *Prepared) summarise() Summary {
	summary := Summary{
		Name:  p.req.Name,
		Until: p.until,
		NoOp:  !p.req.Rotate && len(p.removed) == 0,
	}

	for _, i := range p.removed {
		entry := p.conf.RetiringSecrets[i]

		var removed Removed

		if p.loc.blocks[i].nameIsString && !readsAsAValue(entry.Name) {
			removed.Name = entry.Name
		}

		if _, err := time.Parse(time.RFC3339Nano, entry.Until); err == nil {
			removed.Until = entry.Until
		}

		summary.Removed = append(summary.Removed, removed)
	}

	return summary
}

// Warnings are the problem and warning lines the file already has, from
// GetRetiringSecrets at the run's instant: value-free, and never a refusal.
func (p *Prepared) Warnings() []string {
	return slices.Clone(p.report.Lines)
}

// Primary is the name's current primary, which a rotation's new key takes the
// mode and host of; the zero Secret for --prune alone. It is a credential:
// never format it.
func (p *Prepared) Primary() mtglib.Secret {
	return p.primary
}

// Summary is what the run does, known before any key is generated.
func (p *Prepared) Summary() Summary {
	summary := p.summary
	summary.Removed = slices.Clone(p.summary.Removed)

	return summary
}

// Apply is steps 2 to 5 of spec §7.3: it splices newPrimary in, in the
// current value's encoding and quotes; inserts the new block before the
// [secrets] header and the comment lines directly above it, or at the end of
// the file without one; removes the blocks of both header kinds; and verifies
// the result by parsing it again. Any difference is ErrEditVerification, a key
// usable again that nothing accepted is ErrKeyRevived, and in either case
// nothing is returned. With Rotate false it ignores newPrimary and splices no
// value, and the verification requires the primary unchanged.
func (p *Prepared) Apply(newPrimary mtglib.Secret) ([]byte, error) {
	if p.req.Rotate {
		switch {
		case !newPrimary.Valid():
			return nil, errors.New("the new key is not a valid secret")
		case newPrimary.Key == p.primary.Key:
			return nil, errors.New("the new key is the current key")
		}
	}

	out, ok := p.splice(newPrimary)
	if !ok {
		return nil, ErrEditVerification
	}

	out = spliceHook(out)

	if err := p.verify(out, newPrimary); err != nil {
		return nil, err
	}

	return out, nil
}
