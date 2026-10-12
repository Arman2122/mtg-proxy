package config_test

import (
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Arman2122/mtg-proxy/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// C8, D21 (Task 8b's review, m2). A config file is the one place a secret value
// lives, so what the config layer says about a file it cannot read, or reads
// only in part, must not carry one. go-toml quotes no line of the document in
// its Error() form, but its message can hold a key's name (a key defined twice)
// or a number's literal (a float out of range), and the unknown-key list is
// every key's dotted path. A value written where TOML reads a key or a number
// therefore came back in every one of them, on run, run --check, doctor, the
// /reload 500 body and rotate-secret. The text that could spell a value is
// replaced; every other word of an error is go-toml's, byte for byte.

// parseNotShown is what replaces text that reads as a secret value.
const parseNotShown = "<not shown: reads as a secret value>"

// parseFloatValue is a plain secret value -- its key, in hex -- that TOML reads
// as a float out of range: digits, one e, digits.
const parseFloatValue = "1234567890123456789012345678e999"

// parseDoc frames body as a document: bind-to on line 1, body from line 3, and
// alice in [secrets] last.
func parseDoc(body string) string {
	return "bind-to = \"0.0.0.0:3128\"\n\n" + body + "[secrets]\nalice = \"" + rotEE(rotKeyAlice) + "\"\n"
}

// parseBlock is a well-formed block of alice's on lines 3 to 6, holding value.
func parseBlock(value string) string {
	return "[[retiring-secret]]\nname = \"alice\"\nsecret = \"" + value + "\"\nuntil = \"" + rotIn(24*time.Hour) + "\"\n"
}

// The shapes that put a value where TOML reads a key or a number, and are
// refused whole: the parse error is all that is printed of them.
func TestAParseErrorCarriesNoValueOfTheFile(t *testing.T) {
	t.Parallel()

	old := rotEE(rotKeyLeak)
	oldB64 := rotB64(old)

	for name, tc := range map[string]struct {
		doc          string
		value        string // the value, in hex, that the document holds where it does not belong
		line, column int
		key          []string // DecodeError.Key(), with any value-like part not shown
	}{
		// 8b's row 12.
		"a plain value written unquoted, which reads as a float": {
			doc: parseDoc("[[retiring-secret]]\nname = \"alice\"\nsecret = " + parseFloatValue +
				"\nuntil = \"" + rotIn(time.Hour) + "\"\n\n"),
			value: parseFloatValue, line: 5, column: 10, key: []string{"retiring-secret", "secret"},
		},
		// 8b's row 14.
		"a value written as a key, twice, inside a block": {
			doc:   parseDoc(parseBlock(old) + old + " = 1\n" + old + " = 1\n\n"),
			value: old, line: 8, column: 1, key: []string{parseNotShown},
		},
		"a value in base64url written as a key, twice, inside a block": {
			doc:   parseDoc(parseBlock(old) + oldB64 + " = 1\n" + oldB64 + " = 1\n\n"),
			value: old, line: 8, column: 1, key: []string{parseNotShown},
		},
		// The duplicate is inside an inline table: go-toml's key is the
		// enclosing one, and only the message names the value.
		"a value written as a key, twice, inside an inline table": {
			doc:   parseDoc("x = { " + old + " = 1, " + old + " = 2 }\n\n"),
			value: old, line: 3, column: 1, key: []string{"x"},
		},
		"a value written as a table, twice": {
			doc:   parseDoc(parseBlock(old) + "\n[retiring-secret." + oldB64 + "]\na = 1\n\n[retiring-secret." + oldB64 + "]\nb = 1\n\n"),
			value: old, line: 11, column: 2, key: []string{"retiring-secret", parseNotShown},
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, err := config.Parse([]byte(tc.doc))
			require.Error(t, err, "the file parses")

			// First, so that no failing assertion below prints a key: the value
			// out of place, or alice's primary.
			require.Empty(t, rotLeaks(err.Error(), tc.value, rotEE(rotKeyAlice)), "the error carries a value")

			var parseErr *config.ParseError
			require.ErrorAs(t, err, &parseErr, "the parser's error is a ParseError")

			require.Empty(t, rotLeaks(strings.Join(parseErr.Key(), "."), tc.value, rotEE(rotKeyAlice)),
				"the key carries a value")

			line, column := parseErr.Position()
			assert.Equal(t, tc.line, line, "the line")
			assert.Equal(t, tc.column, column, "the column")
			assert.Equal(t, tc.key, parseErr.Key())

			assert.Contains(t, err.Error(), parseNotShown, "the text that held the value is not marked")
			assert.True(t, strings.HasSuffix(err.Error(), " (line "+strconv.Itoa(tc.line)+", column "+strconv.Itoa(tc.column)+")"),
				"the place in the file is not named: %s", err.Error())
			assert.NotContains(t, err.Error(), "\n", "one line")
			assert.True(t, strings.HasPrefix(err.Error(), "cannot parse toml config: toml: "), "go-toml's words: %s", err.Error())
		})
	}

	// The JSON step of Parse turns the decoded file into typed values; a type's
	// own refusal can quote the text it was given.
	t.Run("a value pasted into a typed field", func(t *testing.T) {
		t.Parallel()

		_, err := config.Parse([]byte(parseDoc("[domain-fronting]\nhost = \"" + old + " x\"\n\n")))
		require.Error(t, err)
		require.Empty(t, rotLeaks(err.Error(), old, rotEE(rotKeyAlice)), "the error carries a value")

		assert.Equal(t, `cannot parse a config: incorrect host "`+parseNotShown+` x"`, err.Error())
	})
}

// Every other refusal reads exactly as go-toml, or the type, wrote it -- a key,
// a Go type or a number that cannot be a key's spelling is left alone -- and
// the parser's key and place are still there for run's advice about the
// [[retiring-secret]] table.
func TestAParseErrorOfAnOrdinaryFileIsUnchanged(t *testing.T) {
	t.Parallel()

	for name, tc := range map[string]struct {
		doc          string
		text         string
		line, column int
		key          []string
	}{
		"a long key defined twice": {
			doc:  parseDoc("allow-fallback-on-unknown-dc = true\nallow-fallback-on-unknown-dc = true\n\n"),
			text: "cannot parse toml config: toml: key allow-fallback-on-unknown-dc is already defined",
			line: 4, column: 1, key: []string{"allow-fallback-on-unknown-dc"},
		},
		"a string where a boolean belongs": {
			doc: parseDoc("domain-fronting-proxy-protocol = \"yes\"\n\n"),
			text: "cannot parse toml config: toml: cannot decode TOML string into struct field " +
				"config.tomlConfig.DomainFrontingProxyProtocol of type bool",
			line: 3, column: 34, key: []string{"domain-fronting-proxy-protocol"},
		},
		"an integer where a boolean belongs": {
			doc: parseDoc("allow-fallback-on-unknown-dc = 1\n\n"),
			text: "cannot parse toml config: toml: cannot decode TOML integer into struct field " +
				"config.tomlConfig.AllowFallbackOnUnknownDC of type bool",
			line: 3, column: 32, key: []string{"allow-fallback-on-unknown-dc"},
		},
		"an impossible date inside a block": {
			doc: parseDoc("[[retiring-secret]]\nname = \"alice\"\nsecret = \"" + rotEE(rotKeyLeak) +
				"\"\nuntil = 2026-02-30T09:30:00Z\n\n"),
			text: "cannot parse toml config: toml: impossible date",
			line: 6, column: 17, key: []string{"retiring-secret", "until"},
		},
		"a byte-order mark": {
			doc:  "\xef\xbb\xbf" + parseDoc(""),
			text: "cannot parse toml config: toml: invalid character at start of key: U+00EF 'ï'",
			line: 1, column: 1,
		},
		"a number too large for its field": {
			doc:  parseDoc("domain-fronting-port = 99999999999999999999\n\n"),
			text: "cannot parse toml config: toml: decimal number is too large to fit in a 64-bit signed integer",
			line: 3, column: 24, key: []string{"domain-fronting-port"},
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, err := config.Parse([]byte(tc.doc))
			require.Error(t, err)
			require.Empty(t, rotLeaks(err.Error(), rotEE(rotKeyLeak), rotEE(rotKeyAlice)), "the error carries a value")

			assert.Equal(t, tc.text, err.Error())

			var parseErr *config.ParseError
			require.ErrorAs(t, err, &parseErr)

			line, column := parseErr.Position()
			assert.Equal(t, tc.line, line, "the line")
			assert.Equal(t, tc.column, column, "the column")
			assert.Equal(t, tc.key, parseErr.Key())
		})
	}

	// A refusal of the JSON step that holds nothing like a value keeps its
	// words and its chain.
	t.Run("a port out of range", func(t *testing.T) {
		t.Parallel()

		_, err := config.Parse([]byte(parseDoc("[domain-fronting]\nport = 99999999\n\n")))
		require.Error(t, err)

		assert.Equal(t, "cannot parse a config: incorrect port number (99999999): "+
			"strconv.ParseUint: parsing \"99999999\": value out of range", err.Error())

		var numErr *strconv.NumError
		assert.True(t, errors.As(err, &numErr), "the error's chain is cut")
	})
}

// 8b's rows 13, 15 and 16: a value written as a key in a file that parses. The
// key is unknown, and its path is what run logs, run --check refuses with and
// doctor lists. The part that reads as a value is not shown; the rest of the
// path is, so the operator still learns where the stray key is.
func TestAnUnknownKeyThatReadsAsAValueIsNotShown(t *testing.T) {
	t.Parallel()

	old := rotEE(rotKeyLeak)
	oldB64 := rotB64(old)

	for name, doc := range map[string]string{
		"a key in base64url inside a block":   parseDoc(parseBlock(old) + oldB64 + " = \"x\"\n\n"),
		"a key in hex inside a block":         parseDoc(parseBlock(old) + old + " = \"x\"\n\n"),
		"a subtable of a block named by it":   parseDoc(parseBlock(old) + "\n[retiring-secret." + oldB64 + "]\nx = 1\n\n"),
		"a dotted key below the table's name": parseDoc("retiring-secret." + old + " = 1\n\n"),
		"a quoted key holding the value":      parseDoc(parseBlock(old) + "\"old " + oldB64 + "\" = 1\n\n"),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			conf, err := config.Parse([]byte(doc))
			require.Empty(t, rotLeaks(rotErrText(err), old, rotEE(rotKeyAlice)), "the error carries a value")
			require.NoError(t, err, "the file parses")

			text := strings.Join(conf.UnknownKeys, "\n") + "\n" + strings.Join(conf.UnknownKeyWarnings(), "\n")
			require.Empty(t, rotLeaks(text, old, rotEE(rotKeyAlice)), "an unknown key carries a value")

			require.Len(t, conf.UnknownKeys, 1)
			assert.True(t, strings.HasPrefix(conf.UnknownKeys[0], "retiring-secret."), "the path around the value is kept")
			assert.Contains(t, conf.UnknownKeys[0], parseNotShown)
		})
	}

	// A key that only looks long -- a word, in either case convention -- is no
	// value: it is shown, as are the keys TestUnknownKeysAreNamed pins.
	t.Run("an ordinary misspelt key is shown", func(t *testing.T) {
		t.Parallel()

		conf, err := config.Parse([]byte(parseDoc("allow_fallback_on_unknown_dc = true\n\n" +
			"[web]\ndomain-fronting-proxy-protocol = true\n\n")))
		require.NoError(t, err)

		assert.Equal(t, []string{"allow_fallback_on_unknown_dc", "web.domain-fronting-proxy-protocol"}, conf.UnknownKeys)
	})
}
