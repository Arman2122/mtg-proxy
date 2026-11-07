package rotation

import (
	"cmp"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/Arman2122/mtg-proxy/mtglib"
)

// spliceHook sees the edited document before the verification does. It is a
// test seam (R2): a test makes it corrupt the splice and checks that the
// verification refuses the result. In production it returns its argument.
var spliceHook = func(b []byte) []byte { return b }

// ValueText is s as Apply writes it into the file: in hex when the current
// value's text decodes as hex, in base64url otherwise -- the rule
// mtglib.Secret.Set reads by -- so the file keeps one style. rotate-secret
// prints the new value in this spelling.
func (p *Prepared) ValueText(s mtglib.Secret) string {
	if p.hexValue {
		return s.Hex()
	}

	return s.Base64()
}

// splice builds the edited document: the new value spliced into the
// primary's string node between its own quotes, the removed blocks cut, and
// the new block inserted before [secrets] -- or, without a [secrets] header,
// appended at the end of the file, after a newline if the file lacks a final
// one. It reports false when two edits overlap, which a correct layout never
// gives.
//
// Line endings follow the file: new text uses the ending of the file's first
// line (CRLF when it ends so), and every kept line keeps its own, so a file of
// mixed endings stays mixed. A file without a final newline keeps none. One
// corner of a mixed file without a final newline: when a cut reaches the end
// and a block is then appended, the last kept line, whose ending the cut had
// trimmed, gets the first line's ending.
func (p *Prepared) splice(newPrimary mtglib.Secret) ([]byte, bool) {
	edits := slices.Clone(p.cuts)

	if p.req.Rotate {
		quote := string(p.doc[p.loc.target.start])
		edits = append(edits, span{
			start: p.loc.target.start,
			end:   p.loc.target.end,
			text:  []byte(quote + p.ValueText(newPrimary) + quote),
		})
	}

	var block string

	if p.addBlock {
		block = strings.Join(p.blockLines(), p.loc.eol)
	}

	if p.addBlock && p.insertAt >= 0 {
		edits = append(edits, span{start: p.insertAt, end: p.insertAt, text: []byte(block + p.loc.eol + p.loc.eol)})
	}

	out, ok := assemble(p.doc, edits)
	if !ok {
		return nil, false
	}

	if p.cutToEnd && !p.loc.finalNewline {
		out = trimLineEnding(out)
	}

	if p.addBlock && p.insertAt < 0 {
		if len(out) > 0 && out[len(out)-1] != '\n' {
			out = append(out, p.loc.eol...)
		}

		if len(out) > 0 && !lastLineBlank(out) {
			out = append(out, p.loc.eol...)
		}

		out = append(out, block...)

		if p.loc.finalNewline {
			out = append(out, p.loc.eol...)
		}
	}

	return out, true
}

// blockLines are the new [[retiring-secret]] block's lines, as in spec §1.1:
// the rotation's own comment inside the block, so it goes with the block when
// the block is removed, then the name, the old value exactly as the file
// spelled it (quotes and encoding included) and until, in UTC to the second.
func (p *Prepared) blockLines() []string {
	return []string{
		"[[" + retiringTable + "]]",
		"# added by mtg-proxy rotate-secret at " + p.req.Now.UTC().Format(time.RFC3339),
		"name   = " + basicString(p.req.Name),
		"secret = " + string(p.doc[p.loc.target.start:p.loc.target.end]),
		"until  = " + basicString(p.until.Format(time.RFC3339)),
	}
}

// assemble applies non-overlapping edits to doc in one forward pass; an
// insertion sorts before a cut that starts where it is. It reports false for
// overlapping edits.
func assemble(doc []byte, edits []span) ([]byte, bool) {
	slices.SortStableFunc(edits, func(a, b span) int {
		if c := cmp.Compare(a.start, b.start); c != 0 {
			return c
		}

		return cmp.Compare(a.end, b.end)
	})

	out := make([]byte, 0, len(doc)+256)
	at := 0

	for _, e := range edits {
		if e.start < at || e.end < e.start || e.end > len(doc) {
			return nil, false
		}

		out = append(out, doc[at:e.start]...)
		out = append(out, e.text...)
		at = e.end
	}

	return append(out, doc[at:]...), true
}

// trimLineEnding drops one final line ending.
func trimLineEnding(b []byte) []byte {
	switch {
	case len(b) >= 2 && b[len(b)-2] == '\r' && b[len(b)-1] == '\n':
		return b[:len(b)-2]
	case len(b) >= 1 && b[len(b)-1] == '\n':
		return b[:len(b)-1]
	default:
		return b
	}
}

// lastLineBlank reports whether the last line of b, which ends in a newline,
// holds only whitespace.
func lastLineBlank(b []byte) bool {
	for _, c := range b[lineStart(b, len(b)-1) : len(b)-1] {
		if c != ' ' && c != '\t' && c != '\r' {
			return false
		}
	}

	return true
}

// basicString is s as a TOML basic string.
func basicString(s string) string {
	var out strings.Builder

	out.WriteByte('"')

	for _, r := range s {
		switch r {
		case '"':
			out.WriteString(`\"`)
		case '\\':
			out.WriteString(`\\`)
		case '\b':
			out.WriteString(`\b`)
		case '\t':
			out.WriteString(`\t`)
		case '\n':
			out.WriteString(`\n`)
		case '\f':
			out.WriteString(`\f`)
		case '\r':
			out.WriteString(`\r`)
		default:
			if r < 0x20 || r == 0x7f {
				fmt.Fprintf(&out, `\u%04X`, r)
			} else {
				out.WriteRune(r)
			}
		}
	}

	out.WriteByte('"')

	return out.String()
}
