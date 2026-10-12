package rotation

import (
	"bytes"
	"errors"
	"slices"

	"github.com/pelletier/go-toml/v2/unstable"
)

// retiringTable is the name of the [[retiring-secret]] table.
const retiringTable = "retiring-secret"

// errUnlocatable is a document the locator cannot map although config.Parse
// read it. It never carries the parser's own text, which may quote the
// document.
var errUnlocatable = errors.New("the config cannot be mapped for editing; edit it by hand")

// header is one [table] or [[array of tables]] header line.
type header struct {
	line  int      // the first byte of the header's line
	path  []string // the table's key path, unquoted
	array bool     // [[...]] rather than [...]
}

// block is one [[retiring-secret]] block, or the single-table typo
// [retiring-secret], which the parser reads as one entry.
type block struct {
	start        int  // the first byte of its header line
	end          int  // the first byte of the next header line, or the end of the document
	single       bool // written [retiring-secret]
	nameIsString bool // its name is a TOML string, not another type
}

// stringValue is where the value at the target path is: its raw range, quotes
// included, and its text.
type stringValue struct {
	found     bool
	notString bool
	start     int
	end       int
	text      string
}

// layout is what the locator found in a document, all offsets into it.
type layout struct {
	doc          []byte
	eol          string       // "\r\n" when the first line ends so, else "\n"
	finalNewline bool         // the document ends with a newline
	comments     map[int]bool // the first byte of every line holding only a comment
	headers      []header     // every table header, in file order
	blocks       []block      // every retiring-secret block, in file order
	secrets      int          // the index in headers of [secrets], or -1
	target       stringValue  // the value at the path locate was asked for
}

// locate maps doc with go-toml's unstable parser, comments kept. A key's path
// is the current table's path plus the key's own dotted parts, each unquoted,
// so [secrets] alice = …, [secrets] "alice" = …, secrets.alice = … and
// secrets = { alice = … } all resolve to secrets.alice; a line that merely
// looks like a key -- a comment, or text inside a multi-line string -- is never
// one. target is the path whose value is wanted, nil for none.
func locate(doc []byte, target []string) (*layout, error) {
	l := &layout{
		doc:          doc,
		eol:          lineEnding(doc),
		finalNewline: len(doc) > 0 && doc[len(doc)-1] == '\n',
		comments:     map[int]bool{},
		secrets:      -1,
	}

	parser := unstable.Parser{KeepComments: true}
	parser.Reset(doc)

	var table []string

	inBlock := -1

	for parser.NextExpression() {
		expr := parser.Expression()

		switch expr.Kind {
		case unstable.Comment:
			// A comment expression of its own is the first thing on its line:
			// a comment after a key or a header is that expression's sibling.
			l.comments[lineStart(doc, int(expr.Raw.Offset))] = true
		case unstable.Table, unstable.ArrayTable:
			h, err := locateHeader(doc, expr)
			if err != nil {
				return nil, err
			}

			l.headers = append(l.headers, h)
			table, inBlock = h.path, -1

			if len(h.path) == 1 && h.path[0] == retiringTable {
				l.blocks = append(l.blocks, block{start: h.line, single: !h.array})
				inBlock = len(l.blocks) - 1
			}

			if !h.array && len(h.path) == 1 && h.path[0] == "secrets" {
				l.secrets = len(l.headers) - 1
			}
		case unstable.KeyValue:
			l.visit(expr, table, target, inBlock)
		default:
			return nil, errUnlocatable
		}
	}

	if parser.Error() != nil {
		return nil, errUnlocatable
	}

	for i := range l.blocks {
		l.blocks[i].end = len(doc)

		for _, h := range l.headers {
			if h.line > l.blocks[i].start {
				l.blocks[i].end = h.line

				break
			}
		}
	}

	return l, nil
}

// locateHeader finds a header's line. The header node's own Raw is empty, so
// the line is found from its first key node's Raw, scanning back over
// whitespace to the [ (or [[) that opens it.
func locateHeader(doc []byte, expr *unstable.Node) (header, error) {
	h := header{array: expr.Kind == unstable.ArrayTable}
	first := -1

	keys := expr.Key()
	for keys.Next() {
		key := keys.Node()
		if first < 0 {
			first = int(key.Raw.Offset)
		}

		h.path = append(h.path, string(key.Data))
	}

	if first < 0 {
		return header{}, errUnlocatable
	}

	at := first - 1
	for at >= 0 && (doc[at] == ' ' || doc[at] == '\t') {
		at--
	}

	if at < 0 || doc[at] != '[' {
		return header{}, errUnlocatable
	}

	if h.array {
		if at == 0 || doc[at-1] != '[' {
			return header{}, errUnlocatable
		}

		at--
	}

	h.line = lineStart(doc, at)
	if len(bytes.TrimLeft(doc[h.line:at], " \t")) != 0 {
		return header{}, errUnlocatable
	}

	return h, nil
}

// visit records a key's value when its full path is the target, and whether
// a block's name is a string. An inline table's keys are visited under the
// table's path.
func (l *layout) visit(kv *unstable.Node, table, target []string, inBlock int) {
	path := slices.Clone(table)

	keys := kv.Key()
	for keys.Next() {
		path = append(path, string(keys.Node().Data))
	}

	value := kv.Value()

	if value.Kind == unstable.InlineTable {
		children := value.Children()
		for children.Next() {
			if child := children.Node(); child.Kind == unstable.KeyValue {
				l.visit(child, path, target, -1)
			}
		}

		return
	}

	if target != nil && slices.Equal(path, target) {
		l.target = stringValue{found: true, notString: value.Kind != unstable.String}

		if value.Kind == unstable.String {
			l.target.start = int(value.Raw.Offset)
			l.target.end = int(value.Raw.Offset + value.Raw.Length)
			l.target.text = string(value.Data)
		}
	}

	if inBlock >= 0 && slices.Equal(path, []string{retiringTable, "name"}) {
		l.blocks[inBlock].nameIsString = value.Kind == unstable.String
	}
}

// insertionPoint is where a new block goes: before the [secrets] header line
// and the run of comment lines directly above it, so a heading comment stays
// with its table; -1 when there is no [secrets] header.
func (l *layout) insertionPoint() int {
	if l.secrets < 0 {
		return -1
	}

	at := l.headers[l.secrets].line
	for at > 0 && l.comments[previousLine(l.doc, at)] {
		at = previousLine(l.doc, at)
	}

	return at
}

// span is a byte range of the document, and what replaces it.
type span struct {
	start, end int
	text       []byte
}

// cuts are the byte ranges that remove the given blocks, merged. A block goes
// from its header line to the next header line, that end walked back over the
// comment and blank lines directly above the next header, so a comment that
// heads the next table stays; the blank lines between the block and that
// comment go with the block. A comment above a block's own header is not the
// block's and stays. A range that reaches the end of the document also takes
// the blank lines above it.
func (l *layout) cuts(blocks []block) []span {
	cuts := make([]span, 0, len(blocks))

	for _, b := range blocks {
		end := b.end

		if end < len(l.doc) {
			for {
				prev := previousLine(l.doc, end)
				if prev <= b.start || (!l.comments[prev] && !l.blank(prev)) {
					break
				}

				end = prev
			}

			for end < b.end && l.blank(end) {
				end = nextLine(l.doc, end)
			}
		}

		cuts = append(cuts, span{start: b.start, end: end})
	}

	slices.SortFunc(cuts, func(a, b span) int { return a.start - b.start })

	merged := cuts[:0]

	for _, cut := range cuts {
		if n := len(merged); n > 0 && cut.start <= merged[n-1].end {
			merged[n-1].end = max(merged[n-1].end, cut.end)

			continue
		}

		merged = append(merged, cut)
	}

	if n := len(merged); n > 0 && merged[n-1].end == len(l.doc) {
		for merged[n-1].start > 0 && l.blank(previousLine(l.doc, merged[n-1].start)) {
			merged[n-1].start = previousLine(l.doc, merged[n-1].start)
		}
	}

	return merged
}

// blank reports whether the line starting at line holds only whitespace.
func (l *layout) blank(line int) bool {
	for _, c := range l.doc[line:] {
		switch c {
		case '\n':
			return true
		case ' ', '\t', '\r':
		default:
			return false
		}
	}

	return true
}

// lineStart is the first byte of the line holding the byte at.
func lineStart(doc []byte, at int) int {
	return bytes.LastIndexByte(doc[:at], '\n') + 1
}

// previousLine is the first byte of the line before the one starting at line,
// which must not be the first.
func previousLine(doc []byte, line int) int {
	return lineStart(doc, line-1)
}

// nextLine is the first byte of the line after the one starting at line, or
// the end of the document.
func nextLine(doc []byte, line int) int {
	if i := bytes.IndexByte(doc[line:], '\n'); i >= 0 {
		return line + i + 1
	}

	return len(doc)
}

// lineEnding is CRLF when the document's first line ends in CRLF, else LF.
func lineEnding(doc []byte) string {
	if i := bytes.IndexByte(doc, '\n'); i > 0 && doc[i-1] == '\r' {
		return "\r\n"
	}

	return "\n"
}
