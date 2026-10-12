package config

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/pelletier/go-toml/v2"
)

// What the config layer says about a document it cannot read, or reads only in
// part, never carries a secret value of it (D21, C8). go-toml's Error() form
// quotes no line of the document, but its message can hold a key's name (a key
// or a table defined twice) or a number's literal (a float out of range); the
// JSON step's types can quote the text they refuse; and the unknown-key list is
// every stray key's dotted path. A value written where TOML reads a key or a
// number -- Task 8b's review found five such shapes -- came back in each of
// them: on run, run --check, doctor, the /reload 500 body and rotate-secret.
//
// So the text that could spell a value is replaced with valueNotShown, and
// every other word stays the library's, byte for byte. Text that could spell a
// value is a run of at least valueRunMin characters of the hex and base64
// alphabets, '=' included -- the shortest spelling of a 16-byte key is 22
// characters of unpadded base64 -- that is not a plain word: lowercase letters,
// '-' and '_' only, the way the file's own keys are written in either case
// convention. A random key's spelling is a plain word about once in 10^8.
//
// In a message the run must also be the document's own text, which go-toml's
// words and the Go names of the fields it decodes into
// (DomainFrontingProxyProtocol) are not. Every part of a key is the document's
// text, so a key is held to the first two conditions only. A value is hidden
// wherever it sits in a run, joined to other characters or not.

// valueNotShown is what stands where a value might have been printed.
const valueNotShown = "<not shown: reads as a secret value>"

// valueRunMin is the length of the shortest spelling of a key: 16 bytes in
// unpadded base64.
const valueRunMin = 22

// ParseError is a document the TOML parser refused: the parser's Error() form,
// with any text that could spell a secret value replaced, and with the place
// in the document named after it when something was. It keeps the parser's
// position and key -- what run's advice about the [[retiring-secret]] table is
// built from -- and not the parser's own error, whose Error() and String()
// forms both carry the text it replaced: it is deliberately not unwrapped.
type ParseError struct {
	text         string
	line, column int
	key          []string
}

func (e *ParseError) Error() string { return e.text }

// Position is the line and column at which the parser stopped, both from 1.
func (e *ParseError) Position() (line, column int) { return e.line, e.column }

// Key is the key the parser was at when it stopped, one part per element,
// with any part that could spell a value not shown. It is relative to its
// table for a key defined twice, and nil when the parser names none (a
// byte-order mark, an unterminated string).
func (e *ParseError) Key() []string { return slices.Clone(e.key) }

// parseError is toml.Unmarshal's error over doc as a ParseError, or, for an
// error of any other kind, the error with its text cleaned the same way.
func parseError(doc []byte, err error) error {
	var decodeErr *toml.DecodeError
	if !errors.As(err, &decodeErr) {
		return valueFreeError(doc, err)
	}

	line, column := decodeErr.Position()

	text, replaced := withoutValues(decodeErr.Error(), inDocument(doc))
	if replaced {
		text += fmt.Sprintf(" (line %d, column %d)", line, column)
	}

	return &ParseError{text: text, line: line, column: column, key: valueFreeKey(decodeErr.Key())}
}

// valueFreeError is err itself when its text holds nothing of doc that could
// spell a value, and otherwise a new error with that text replaced. The chain
// is cut there: every error in it carries the text.
func valueFreeError(doc []byte, err error) error {
	text, replaced := withoutValues(err.Error(), inDocument(doc))
	if !replaced {
		return err
	}

	return errors.New(text)
}

// valueFreeKey is key with any text that could spell a value replaced in each
// part, and nil for no key.
func valueFreeKey(key []string) []string {
	if len(key) == 0 {
		return nil
	}

	out := make([]string, len(key))

	for i, part := range key {
		out[i], _ = withoutValues(part, func(string) bool { return true })
	}

	return out
}

// inDocument reports whether a run of text is text of doc.
func inDocument(doc []byte) func(string) bool {
	return func(run string) bool { return bytes.Contains(doc, []byte(run)) }
}

// withoutValues is text with every run that could spell a value, and that
// fromDocument accepts, replaced by valueNotShown; and whether any was.
func withoutValues(text string, fromDocument func(string) bool) (string, bool) {
	var (
		out      strings.Builder
		replaced bool
	)

	for start := 0; start < len(text); {
		if !valueChar(text[start]) {
			out.WriteByte(text[start])
			start++

			continue
		}

		end := start
		for end < len(text) && valueChar(text[end]) {
			end++
		}

		run := text[start:end]

		if len(run) >= valueRunMin && !plainWord(run) && fromDocument(run) {
			out.WriteString(valueNotShown)

			replaced = true
		} else {
			out.WriteString(run)
		}

		start = end
	}

	return out.String(), replaced
}

// valueChar reports whether c is in the hex alphabet or either base64 one,
// padding included.
func valueChar(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		return true
	default:
		return c == '+' || c == '/' || c == '=' || c == '-' || c == '_'
	}
}

// plainWord reports whether run is lowercase letters, '-' and '_' only.
func plainWord(run string) bool {
	for i := range len(run) {
		if c := run[i]; (c < 'a' || c > 'z') && c != '-' && c != '_' {
			return false
		}
	}

	return true
}
