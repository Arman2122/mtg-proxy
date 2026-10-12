// Package rotation is the edit mtg-proxy rotate-secret makes to an
// operator's config file (spec §7.3), as pure functions over bytes: no
// filesystem, no network, no clock -- the run's one instant is a field of the
// request. Pure, that is, up to the config layer's own types: config.Parse,
// which the verification must use, stats the file paths listed under
// [defense.blocklist] and [defense.allowlist] (os.Stat, filepath.Abs). A list
// file that appears or goes between the two parses makes them differ, and the
// edit then fails closed.
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
	"maps"
	"slices"
	"strconv"
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
	// Name is the name the run was asked for -- empty for --prune alone, and
	// also empty when the name reads as a secret value (a user named by a
	// key's hex, say), which is never echoed: the caller then prints a label
	// of its own, such as "the secret you named".
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

// errKeyHeld is a new primary whose key the file already holds.
var errKeyHeld = errors.New("the new key is already held by this file, as a primary or a previous key; generate another")

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
	p, err := plan(doc, req)
	if err != nil {
		return nil, err
	}

	if err := p.simulate(); err != nil {
		return nil, err
	}

	p.summary = p.summarise()

	return p, nil
}

// plan is Prepare but for judging the planned edit (simulate): it reads and
// checks the file and the request, locates, and works out the edit -- the
// removals, the new block, the entries and unknown keys the edited file must
// parse to.
func plan(doc []byte, req Request) (*Prepared, error) {
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

	if p.loc.retiringKey || len(p.loc.blocks) != len(conf.RetiringSecrets) {
		return nil, errors.New("the file's retiring-secret entries are not all [[retiring-secret]] blocks " +
			"(an inline array of tables, or a retiring-secret key?); rotate-secret edits only blocks: " +
			"rewrite them as blocks and retry")
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
		return fmt.Errorf("the value of %s cannot be found in the file for editing; edit it by hand", shown(p.req.Name))
	}

	if raw := p.doc[value.start:value.end]; bytes.HasPrefix(raw, []byte(`"""`)) || bytes.HasPrefix(raw, []byte(`'''`)) {
		return fmt.Errorf("the value of %s is a multi-line string, which rotate-secret does not edit: "+
			`write it on one line, between "" or '', and retry`, shown(p.req.Name))
	}

	return nil
}

// shown is a name as a message shows it: quoted, or, when it reads as a
// secret value (readsAsAValue: a user named by a key's hex, say), a phrase in
// its place. The name a run was asked for goes through it wherever it is
// echoed, as every block's name does through entryLabel.
func shown(name string) string {
	if readsAsAValue(name) {
		return "the secret asked for (its name reads as a secret value and is not shown)"
	}

	return fmt.Sprintf("%q", name)
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
		return fmt.Errorf("%s already has %d unexpired previous keys, the most one secret can have: "+
			"end them with --end-overlap, or wait for one to expire, and retry", shown(p.req.Name), held)
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
		if p.addBlock && p.newBlockHasLine(added) {
			if refusal := p.collision(sim.GetSecrets()); refusal != nil {
				return refusal
			}
		}

		named := make([]string, 0, len(added))
		for _, line := range added {
			named = append(named, p.asWritten(line))
		}

		return errors.New("the edit would add a problem the file does not have: " + strings.Join(named, "; and "))
	}

	if label, revived := p.revived(report, sim.GetSecrets(), placeholder); revived {
		return revivalError(label)
	}

	if !p.req.Rotate {
		return nil
	}

	if holder, until, held := p.keyStillHeld(report); held {
		return fmt.Errorf("the current key of %s would still be accepted until %s by %s; %s",
			shown(p.req.Name), until.UTC().Format(time.RFC3339),
			p.labelFor(holder, p.primary.Key, until), endOverlapAdvice(holder))
	}

	return nil
}

// endOverlapAdvice says how to remove a block of holder: --end-overlap for
// that name, which ends every previous key of it, or an edit by hand. The
// holder is always unexpired (keyStillHeld reads what is usable now), so
// --prune would not remove it.
func endOverlapAdvice(holder string) string {
	if readsAsAValue(holder) {
		return "rotate-secret <config> <that name> --end-overlap ends every previous key of that name; " +
			"or edit the block by hand"
	}

	return fmt.Sprintf("rotate-secret <config> %q --end-overlap ends every previous key of %q; "+
		"or edit the block by hand", holder, holder)
}

// newBlockHasLine reports whether one of the lines the edit would add is the
// new block's: it carries the new block's position in the edited file.
func (p *Prepared) newBlockHasLine(added []string) bool {
	at := slices.Index(p.expectedFrom, -1)
	if at < 0 {
		return false
	}

	for _, line := range added {
		if n, _, labelled := position(line); labelled && n == at+1 {
			return true
		}
	}

	return false
}

// collision explains a new block that rule 5 would drop at once: another
// name already claims the key being retired, by a block of the file (expired
// and dangling ones too: rule 5 judges every entry that passes rule 1) or as
// its primary. Nil when no such claim is found, and the caller words the
// problem lines instead.
func (p *Prepared) collision(primaries map[string]mtglib.Secret) error {
	for i, entry := range p.expected {
		from := p.expectedFrom[i]
		if from < 0 || entry.Name == p.req.Name || !p.claimsAKey(from) {
			continue
		}

		if secret, _ := mtglib.ParseSecret(entry.Secret); secret.Key == p.primary.Key {
			return fmt.Errorf("%s already holds the key being retired, so the new block would be ignored; "+
				"remove that block (--prune removes it if it has expired) and rotate again",
				entryLabel(from+1, entry.Name))
		}
	}

	for _, name := range slices.Sorted(maps.Keys(primaries)) {
		if name != p.req.Name && primaries[name].Key == p.primary.Key {
			return fmt.Errorf("the key being retired is also the primary key of %s, so the new block would be ignored; "+
				"two secrets share one key: give each its own, then rotate", shown(name))
		}
	}

	return nil
}

// claimsAKey reports whether the i-th entry of the file passes rule 1 and so
// claims its key under rule 5: a name that is a non-empty string, a valid
// secret, and an RFC 3339 until.
func (p *Prepared) claimsAKey(i int) bool {
	entry := p.conf.RetiringSecrets[i]

	secret, secretErr := mtglib.ParseSecret(entry.Secret)
	_, untilErr := time.Parse(time.RFC3339Nano, entry.Until)

	return p.loc.blocks[i].nameIsString && entry.Name != "" && secretErr == nil && secret.Valid() && untilErr == nil
}

// asWritten is a line of the edited file's report in the file's own terms:
// an existing block by its position in the file as it is, the new block as
// "the new block". The config layer numbers entries by their place in the
// edited file, which may be another block's place in this one.
func (p *Prepared) asWritten(line string) string {
	n, rest, labelled := position(line)
	if !labelled || n < 1 || n > len(p.expectedFrom) {
		return line
	}

	if from := p.expectedFrom[n-1]; from >= 0 {
		return fmt.Sprintf("%s #%d%s", retiringTable, from+1, rest)
	}

	return "the new block" + rest
}

// position splits a line labelled "retiring-secret #<n>" into n and what
// follows the number.
func position(line string) (int, string, bool) {
	const label = retiringTable + " #"

	if !strings.HasPrefix(line, label) {
		return 0, "", false
	}

	end := len(label)
	for end < len(line) && line[end] >= '0' && line[end] <= '9' {
		end++
	}

	n, err := strconv.Atoi(line[len(label):end])
	if err != nil {
		return 0, "", false
	}

	return n, line[end:], true
}

// labelFor names, as the config layer labels its entries, the block of the
// file that holds key for name until until -- the block a refusal is about --
// by its position in the file as it is, and its name unless that reads as a
// value.
func (p *Prepared) labelFor(name string, key [mtglib.SecretKeyLength]byte, until time.Time) string {
	for i, entry := range p.expected {
		if p.expectedFrom[i] < 0 || entry.Name != name {
			continue
		}

		secret, secretErr := mtglib.ParseSecret(entry.Secret)
		at, untilErr := time.Parse(time.RFC3339Nano, entry.Until)

		if secretErr == nil && untilErr == nil && secret.Key == key && at.Equal(until) {
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

// heldKeys are the keys the file holds: every primary's, and the key of every
// entry whose secret parses, whatever else is wrong with it.
func (p *Prepared) heldKeys() map[[mtglib.SecretKeyLength]byte]bool {
	held := map[[mtglib.SecretKeyLength]byte]bool{}

	for _, secret := range p.conf.GetSecrets() {
		held[secret.Key] = true
	}

	for _, entry := range p.conf.RetiringSecrets {
		if secret, err := mtglib.ParseSecret(entry.Secret); err == nil {
			held[secret.Key] = true
		}
	}

	return held
}

// placeholder is a stand-in for the new primary: the current one's mode and
// host, and a key the file does not hold.
func (p *Prepared) placeholder() mtglib.Secret {
	held := p.heldKeys()

	key := [mtglib.SecretKeyLength]byte{0x5a, 0xa5, 0x5a, 0xa5, 0x5a, 0xa5, 0x5a, 0xa5, 0x5a, 0xa5, 0x5a, 0xa5, 0x5a, 0xa5, 0x5a, 0xa5}
	for held[key] {
		key[len(key)-1]++
	}

	return mtglib.Secret{Key: key, Host: p.primary.Host, Mode: p.primary.Mode}
}

// summarise is the run's Summary. The name asked for, and a removed block's
// name, are shown only when they do not read as a value (a removed block's
// only when it is a string too), and a removed block's until only when it is
// an RFC 3339 instant, which no value is.
func (p *Prepared) summarise() Summary {
	summary := Summary{
		Until: p.until,
		NoOp:  !p.req.Rotate && len(p.removed) == 0,
	}

	if !readsAsAValue(p.req.Name) {
		summary.Name = p.req.Name
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
// value, and the verification requires the primary unchanged. A rotation
// refuses, before any edit, a newPrimary that is not valid, is the current
// key, or is a key the file already holds (any primary's, or any entry's that
// parses): generation never draws one, and two secrets sharing a key is not
// an edit this tool makes.
func (p *Prepared) Apply(newPrimary mtglib.Secret) ([]byte, error) {
	if p.req.Rotate {
		switch {
		case !newPrimary.Valid():
			return nil, errors.New("the new key is not a valid secret")
		case newPrimary.Key == p.primary.Key:
			return nil, errors.New("the new key is the current key")
		case p.heldKeys()[newPrimary.Key]:
			return nil, errKeyHeld
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
