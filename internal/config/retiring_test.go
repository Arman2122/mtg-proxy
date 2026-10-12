package config_test

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/Arman2122/mtg-proxy/internal/config"
	"github.com/Arman2122/mtg-proxy/mtglib"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// rotNow is the instant the [[retiring-secret]] tests judge a file at.
var rotNow = time.Date(2026, 10, 8, 9, 30, 0, 0, time.UTC)

const (
	rotHost = "storage.googleapis.com"

	// 16-byte keys in hex. The olds are ordered by their bytes, which rule 8
	// breaks ties by.
	rotKeyAlice = "a1a1a1a1b2b2b2b2c3c3c3c3d4d4d4d4"
	rotKeyBob   = "b5b5b5b5c6c6c6c6d7d7d7d7e8e8e8e8"
	rotKeyOld1  = "1111111111111111aaaaaaaaaaaaaaaa"
	rotKeyOld2  = "2222222222222222bbbbbbbbbbbbbbbb"
	rotKeyOld3  = "3333333333333333cccccccccccccccc"
	rotKeyOld4  = "4444444444444444dddddddddddddddd"
	rotKeyOld5  = "5555555555555555eeeeeeeeeeeeeeee"
	rotKeyLeak  = "9a8b7c6d5e4f30211203f4e5d6c7b8a9"
	rotKeyZero  = "00000000000000000000000000000000"
)

// The reasons of the problem lines, as the operator reads them.
const (
	whyNameMissing     = "name is missing or empty"
	whyNameType        = "name is not a string"
	whySecretMissing   = "secret is missing or empty"
	whySecretType      = "secret is not a string"
	whySecretInvalid   = "secret is not a valid secret value (hex or base64url, in the ee, dd or plain form)"
	whySecretZeroKey   = "secret has an all-zero key"
	whyUntilMissing    = "until is missing or empty"
	whyUntilInvalid    = "until is not an RFC 3339 date-time with an offset, such as 2026-10-09T09:30:00Z"
	whyDangling        = "name is not a configured secret"
	whyDanglingDefault = `name "default" is the top-level secret, which is not served while [secrets] is present`
	whyPrimaryOfOther  = "the key is another secret's primary key"
	whyKeyOfOther      = "the key is also the key of a retiring-secret entry of another name"
	whyOverCapName     = "more than 4 unexpired entries for this name; only the 4 with the latest until are kept"
	whyOverCapAll      = "more than 4096 unexpired entries in all; only the 4096 with the latest until are kept"
)

// rotLabels names the fixture keys in a projected Usable list, so a failing
// assertion prints a label and never a key.
var rotLabels = map[string]string{
	rotKeyAlice: "alice's key",
	rotKeyBob:   "bob's key",
	rotKeyOld1:  "old1",
	rotKeyOld2:  "old2",
	rotKeyOld3:  "old3",
	rotKeyOld4:  "old4",
	rotKeyOld5:  "old5",
	rotKeyLeak:  "leak",
}

// rotAllValues is every fixture value, in hex, for the leak checks: each key in
// its ee, dd and plain form.
var rotAllValues = func() []string {
	var out []string

	for key := range rotLabels {
		out = append(out, rotEE(key), rotDD(key), key)
	}

	return out
}()

// rotEE is key's ee value fronting rotHost, in hex.
func rotEE(key string) string { return "ee" + key + hex.EncodeToString([]byte(rotHost)) }

// rotDD is key's dd value, in hex.
func rotDD(key string) string { return "dd" + key }

// rotB64 respells a hex value in base64url, the other spelling a value has.
func rotB64(valueHex string) string {
	raw, err := hex.DecodeString(valueHex)
	if err != nil {
		panic(err)
	}

	return base64.RawURLEncoding.EncodeToString(raw)
}

// rotIn is the instant d after rotNow, spelled as rotate-secret writes it.
func rotIn(d time.Duration) string { return rotNow.Add(d).Format(time.RFC3339) }

// rotBlock is one [[retiring-secret]] block; each argument is one of its lines.
func rotBlock(lines ...string) string {
	return "[[retiring-secret]]\n" + strings.Join(lines, "\n") + "\n\n"
}

func rotName(name string) string     { return fmt.Sprintf("name = %q", name) }
func rotSecret(value string) string  { return fmt.Sprintf("secret = %q", value) }
func rotUntil(instant string) string { return fmt.Sprintf("until = %q", instant) }

// rotFile is a config whose [secrets] are alice and bob (bob's value spelled in
// base64url), after the given blocks.
func rotFile(blocks ...string) string {
	return "bind-to = \"0.0.0.0:3128\"\n\n" + strings.Join(blocks, "") +
		"[secrets]\nalice = \"" + rotEE(rotKeyAlice) + "\"\nbob = \"" + rotB64(rotEE(rotKeyBob)) + "\"\n"
}

// rotSingleFile is a config with only the top-level secret, which is served
// as "default", before the given blocks.
func rotSingleFile(blocks ...string) string {
	return "bind-to = \"0.0.0.0:3128\"\nsecret = \"" + rotEE(rotKeyAlice) + "\"\n\n" + strings.Join(blocks, "")
}

// rotParse parses text, which must load: no retiring entry ever blocks it.
func rotParse(t *testing.T, text string) *config.Config {
	t.Helper()

	conf, err := config.Parse([]byte(text))
	require.NoError(t, err, "a [[retiring-secret]] entry never blocks the load")

	return conf
}

func problemLine(n int, name, reason string) string {
	return fmt.Sprintf("retiring-secret #%d (name %q): %s; the entry is ignored and its key is not accepted", n, name, reason)
}

// namelessProblemLine is a problem of an entry whose name is missing, empty
// or not a string: there is no name to show, and a name of the wrong type is
// not echoed (an array or inline table can hold a pasted value).
func namelessProblemLine(n int, reason string) string {
	return fmt.Sprintf("retiring-secret #%d: %s; the entry is ignored and its key is not accepted", n, reason)
}

func overLongLine(n int, name string) string {
	return fmt.Sprintf("retiring-secret #%d (name %q): until is more than 720h away; it is honoured, "+
		"but an overlap is a migration window, not a second key: shorten it (run --check refuses this file)", n, name)
}

func ownPrimaryNote(n int, name string) string {
	return fmt.Sprintf("retiring-secret #%d (name %q): the key is the secret's own primary; the entry changes nothing", n, name)
}

func duplicateNote(n int, name string) string {
	return fmt.Sprintf("retiring-secret #%d (name %q): the same key as another entry of this name; the later until is kept",
		n, name)
}

// rotUse is one projected Usable entry: name, key label, mode and until.
func rotUse(name, label, mode, until string) string {
	return name + "|" + label + "|" + mode + "|" + until
}

// rotUsable projects report.Usable for comparison, naming each key by its
// label. A RetiringSecret is never formatted: its Secret's String() is the
// value.
func rotUsable(report config.RetiringReport) []string {
	out := make([]string, 0, len(report.Usable))

	for _, entry := range report.Usable {
		label, known := rotLabels[hex.EncodeToString(entry.Secret.Key[:])]
		if !known {
			label = "an unlabelled key"
		}

		out = append(out, rotUse(entry.Name, label, entry.Secret.Mode.String(), entry.Until.UTC().Format(time.RFC3339Nano)))
	}

	return out
}

// rotSame compares two lists, reading nil and empty alike.
func rotSame(t *testing.T, want, got []string, what string) {
	t.Helper()

	if len(want) == 0 {
		assert.Empty(t, got, what)

		return
	}

	assert.Equal(t, want, got, what)
}

// rotLeaks names the spellings of the given values (in hex) that text
// carries: the value in hex, base64url and base64, and its 16-byte key in hex,
// base64 and base64url. It names them by label and position and never prints
// one. The base64 forms are unpadded, which a padded form contains; hex is
// matched in either case.
func rotLeaks(text string, valuesHex ...string) []string {
	lower := strings.ToLower(text)

	var found []string

	for i, valueHex := range valuesHex {
		raw, err := hex.DecodeString(valueHex)
		if err != nil {
			panic(err)
		}

		key := raw

		switch {
		case len(raw) == mtglib.SecretKeyLength+1:
			key = raw[1:]
		case len(raw) > mtglib.SecretKeyLength+1:
			key = raw[1 : 1+mtglib.SecretKeyLength]
		}

		for _, spelling := range []struct {
			label, text string
			hex         bool
		}{
			{"value in hex", valueHex, true},
			{"value in base64url", base64.RawURLEncoding.EncodeToString(raw), false},
			{"value in base64", base64.RawStdEncoding.EncodeToString(raw), false},
			{"key in hex", hex.EncodeToString(key), true},
			{"key in base64", base64.RawStdEncoding.EncodeToString(key), false},
			{"key in base64url", base64.RawURLEncoding.EncodeToString(key), false},
		} {
			haystack, needle := text, spelling.text
			if spelling.hex {
				haystack, needle = lower, strings.ToLower(needle)
			}

			if strings.Contains(haystack, needle) {
				found = append(found, fmt.Sprintf("value %d: %s", i, spelling.label))
			}
		}
	}

	return found
}

// C1: every row of §1.3, as a problem (a line, the entry dropped), a warning
// (a line, the entry kept) or inert (no line), each with its exact text: a
// reason is a fixed phrase and never carries the value, so a line that echoed
// Secret.Set's error, or the value itself, fails here.
func TestEveryRetiringRuleClassifies(t *testing.T) {
	t.Parallel()

	day := rotIn(24 * time.Hour)
	twoDays := rotIn(48 * time.Hour)
	ago := rotIn(-time.Hour)

	alice := func(value, until string) string { return rotBlock(rotName("alice"), rotSecret(value), rotUntil(until)) }
	bob := func(value, until string) string { return rotBlock(rotName("bob"), rotSecret(value), rotUntil(until)) }
	carol := func(value, until string) string { return rotBlock(rotName("carol"), rotSecret(value), rotUntil(until)) }

	cases := []struct {
		name    string
		text    string
		usable  []string
		lines   []string
		notes   []string
		expired int
	}{
		{
			name:   "a well-formed entry is usable",
			text:   rotFile(alice(rotEE(rotKeyOld1), day)),
			usable: []string{rotUse("alice", "old1", "ee", day)},
		},
		{
			name:  "rule 1: no name",
			text:  rotFile(rotBlock(rotSecret(rotEE(rotKeyOld1)), rotUntil(day))),
			lines: []string{namelessProblemLine(1, whyNameMissing)},
		},
		{
			name:  "rule 1: an empty name",
			text:  rotFile(rotBlock(rotName(""), rotSecret(rotEE(rotKeyOld1)), rotUntil(day))),
			lines: []string{namelessProblemLine(1, whyNameMissing)},
		},
		{
			name:  "rule 1: a name that is not a string is not echoed",
			text:  rotFile(rotBlock("name = 7", rotSecret(rotEE(rotKeyOld1)), rotUntil(day))),
			lines: []string{namelessProblemLine(1, whyNameType)},
		},
		{
			name:  "rule 1: no secret",
			text:  rotFile(rotBlock(rotName("alice"), rotUntil(day))),
			lines: []string{problemLine(1, "alice", whySecretMissing)},
		},
		{
			name:  "rule 1: an empty secret",
			text:  rotFile(alice("", day)),
			lines: []string{problemLine(1, "alice", whySecretMissing)},
		},
		{
			name:  "rule 1: a secret that is not a string",
			text:  rotFile(rotBlock(rotName("alice"), "secret = 7", rotUntil(day))),
			lines: []string{problemLine(1, "alice", whySecretType)},
		},
		{
			name: "rule 1: a secret that does not parse, in either spelling",
			text: rotFile(
				alice("not a secret!", day),
				alice("ff"+rotKeyOld1+hex.EncodeToString([]byte(rotHost)), day),
				alice(rotB64("ff"+rotKeyOld2+hex.EncodeToString([]byte(rotHost))), day),
				alice(rotKeyOld3+"0", day),
			),
			lines: []string{
				problemLine(1, "alice", whySecretInvalid),
				problemLine(2, "alice", whySecretInvalid),
				problemLine(3, "alice", whySecretInvalid),
				problemLine(4, "alice", whySecretInvalid),
			},
		},
		{
			name:  "rule 1: an all-zero key, in every mode",
			text:  rotFile(alice(rotEE(rotKeyZero), day), alice(rotDD(rotKeyZero), day), alice(rotKeyZero, day)),
			lines: []string{problemLine(1, "alice", whySecretZeroKey), problemLine(2, "alice", whySecretZeroKey), problemLine(3, "alice", whySecretZeroKey)},
		},
		{
			name:  "rule 1: no until",
			text:  rotFile(rotBlock(rotName("alice"), rotSecret(rotEE(rotKeyOld1)))),
			lines: []string{problemLine(1, "alice", whyUntilMissing)},
		},
		{
			name:  "rule 1: an until without an offset",
			text:  rotFile(alice(rotEE(rotKeyOld1), "2026-10-09T09:30:00")),
			lines: []string{problemLine(1, "alice", whyUntilInvalid)},
		},
		{
			name:  "rule 1: an until that is not RFC 3339",
			text:  rotFile(alice(rotEE(rotKeyOld1), "tomorrow")),
			lines: []string{problemLine(1, "alice", whyUntilInvalid)},
		},
		{
			name:  "rule 1 comes before rule 2: an expired entry with a bad value is still a problem",
			text:  rotFile(alice("not a secret!", ago)),
			lines: []string{problemLine(1, "alice", whySecretInvalid)},
		},
		{
			name:    "rule 2: an expired entry is inert",
			text:    rotFile(alice(rotEE(rotKeyOld1), ago)),
			expired: 1,
		},
		{
			name:    "rule 2: until equal to now has expired",
			text:    rotFile(alice(rotEE(rotKeyOld1), rotIn(0))),
			expired: 1,
		},
		{
			name:    "rule 2 before rule 3: an expired block whose name is no longer in [secrets] is inert",
			text:    rotFile(carol(rotEE(rotKeyOld1), ago)),
			expired: 1,
		},
		{
			name:  "rule 3: an unexpired block for a name not in [secrets]",
			text:  rotFile(carol(rotEE(rotKeyOld1), day)),
			lines: []string{problemLine(1, "carol", whyDangling)},
		},
		{
			name:  "rule 3: default while [secrets] is present",
			text:  rotFile(rotBlock(rotName("default"), rotSecret(rotEE(rotKeyOld1)), rotUntil(day))),
			lines: []string{problemLine(1, "default", whyDanglingDefault)},
		},
		{
			name:   "default names the top-level secret when [secrets] is empty",
			text:   rotSingleFile(rotBlock(rotName("default"), rotSecret(rotEE(rotKeyOld1)), rotUntil(day))),
			usable: []string{rotUse("default", "old1", "ee", day)},
		},
		{
			name:  "rule 3: without [secrets], alice is not a configured secret",
			text:  rotSingleFile(alice(rotEE(rotKeyOld1), day)),
			lines: []string{problemLine(1, "alice", whyDangling)},
		},
		{
			name:   "rule 4: until more than 720h away is kept, and warned",
			text:   rotFile(alice(rotEE(rotKeyOld1), rotIn(721*time.Hour))),
			usable: []string{rotUse("alice", "old1", "ee", rotIn(721*time.Hour))},
			lines:  []string{overLongLine(1, "alice")},
		},
		{
			name:   "rule 4: until exactly 720h away is not warned",
			text:   rotFile(alice(rotEE(rotKeyOld1), rotIn(720*time.Hour))),
			usable: []string{rotUse("alice", "old1", "ee", rotIn(720*time.Hour))},
		},
		{
			name:  "rule 5: another secret's primary key, spelled otherwise and in another mode",
			text:  rotFile(alice(rotB64(rotDD(rotKeyBob)), day)),
			lines: []string{problemLine(1, "alice", whyPrimaryOfOther)},
		},
		{
			name:  "rule 5: two names share a retiring key, and both entries are dropped",
			text:  rotFile(alice(rotEE(rotKeyOld1), day), bob(rotB64(rotDD(rotKeyOld1)), twoDays)),
			lines: []string{problemLine(1, "alice", whyKeyOfOther), problemLine(2, "bob", whyKeyOfOther)},
		},
		{
			name:    "rule 5 counts an expired entry of another name",
			text:    rotFile(alice(rotEE(rotKeyOld1), ago), bob(rotKeyOld1, day)),
			lines:   []string{problemLine(2, "bob", whyKeyOfOther)},
			expired: 1,
		},
		{
			name:  "rule 5 counts a dangling entry of another name",
			text:  rotFile(carol(rotEE(rotKeyOld1), day), alice(rotKeyOld1, day)),
			lines: []string{problemLine(1, "carol", whyDangling), problemLine(2, "alice", whyKeyOfOther)},
		},
		{
			name:    "rule 5 counts an expired, dangling entry of another name",
			text:    rotFile(carol(rotEE(rotKeyOld1), ago), alice(rotKeyOld1, day)),
			lines:   []string{problemLine(2, "alice", whyKeyOfOther)},
			expired: 1,
		},
		{
			name: "rule 5 counts no entry that fails rule 1",
			text: rotFile(alice(rotEE(rotKeyOld1), day), rotBlock(rotName("bob"), rotSecret(rotEE(rotKeyOld1)))),
			usable: []string{
				rotUse("alice", "old1", "ee", day),
			},
			lines: []string{problemLine(2, "bob", whyUntilMissing)},
		},
		{
			name:  "rule 5 before rule 4: an over-long entry that collides is dropped, not warned",
			text:  rotFile(alice(rotEE(rotKeyBob), rotIn(721*time.Hour))),
			lines: []string{problemLine(1, "alice", whyPrimaryOfOther)},
		},
		{
			name:  "rule 6: the secret's own primary key is a note",
			text:  rotFile(alice(rotDD(rotKeyAlice), day)),
			notes: []string{ownPrimaryNote(1, "alice")},
		},
		{
			name:  "rule 6 without [secrets]: the top-level secret's key",
			text:  rotSingleFile(rotBlock(rotName("default"), rotSecret(rotKeyAlice), rotUntil(day))),
			notes: []string{ownPrimaryNote(1, "default")},
		},
		{
			name:   "rule 7: one name, one key twice: the later until is kept",
			text:   rotFile(alice(rotEE(rotKeyOld1), twoDays), alice(rotB64(rotEE(rotKeyOld1)), day)),
			usable: []string{rotUse("alice", "old1", "ee", twoDays)},
			notes:  []string{duplicateNote(2, "alice")},
		},
		{
			name:   "rule 7: on a tie the ee form is kept, whatever the file order",
			text:   rotFile(alice(rotDD(rotKeyOld1), day), alice(rotEE(rotKeyOld1), day)),
			usable: []string{rotUse("alice", "old1", "ee", day)},
			notes:  []string{duplicateNote(1, "alice")},
		},
		{
			name:    "rule 7 looks only at unexpired entries",
			text:    rotFile(alice(rotEE(rotKeyOld1), ago), alice(rotEE(rotKeyOld1), day)),
			usable:  []string{rotUse("alice", "old1", "ee", day)},
			expired: 1,
		},
		{
			name: "rule 8: the fifth entry of a name, the one that expires first, is dropped",
			text: rotFile(
				alice(rotEE(rotKeyOld1), day),
				alice(rotEE(rotKeyOld2), twoDays),
				alice(rotEE(rotKeyOld3), rotIn(72*time.Hour)),
				alice(rotEE(rotKeyOld4), rotIn(96*time.Hour)),
				alice(rotEE(rotKeyOld5), rotIn(12*time.Hour)),
			),
			usable: []string{
				rotUse("alice", "old1", "ee", day),
				rotUse("alice", "old2", "ee", twoDays),
				rotUse("alice", "old3", "ee", rotIn(72*time.Hour)),
				rotUse("alice", "old4", "ee", rotIn(96*time.Hour)),
			},
			lines: []string{problemLine(5, "alice", whyOverCapName)},
		},
		{
			name: "rule 8: a tie on until is broken by key bytes, not by file order",
			text: rotFile(
				alice(rotEE(rotKeyOld5), day),
				alice(rotEE(rotKeyOld4), day),
				alice(rotEE(rotKeyOld3), day),
				alice(rotEE(rotKeyOld2), day),
				alice(rotEE(rotKeyOld1), day),
			),
			usable: []string{
				rotUse("alice", "old4", "ee", day),
				rotUse("alice", "old3", "ee", day),
				rotUse("alice", "old2", "ee", day),
				rotUse("alice", "old1", "ee", day),
			},
			lines: []string{problemLine(1, "alice", whyOverCapName)},
		},
		{
			name: "rule 8: over-long entries share the cap, and only kept ones are warned",
			text: rotFile(
				alice(rotEE(rotKeyOld1), rotIn(721*time.Hour)),
				alice(rotEE(rotKeyOld2), rotIn(722*time.Hour)),
				alice(rotEE(rotKeyOld3), rotIn(723*time.Hour)),
				alice(rotEE(rotKeyOld4), rotIn(724*time.Hour)),
				alice(rotEE(rotKeyOld5), rotIn(725*time.Hour)),
			),
			usable: []string{
				rotUse("alice", "old2", "ee", rotIn(722*time.Hour)),
				rotUse("alice", "old3", "ee", rotIn(723*time.Hour)),
				rotUse("alice", "old4", "ee", rotIn(724*time.Hour)),
				rotUse("alice", "old5", "ee", rotIn(725*time.Hour)),
			},
			lines: []string{
				problemLine(1, "alice", whyOverCapName),
				overLongLine(2, "alice"),
				overLongLine(3, "alice"),
				overLongLine(4, "alice"),
				overLongLine(5, "alice"),
			},
		},
		{
			name: "rule 8 counts only unexpired entries",
			text: rotFile(
				alice(rotEE(rotKeyOld1), day),
				alice(rotEE(rotKeyOld2), day),
				alice(rotEE(rotKeyOld5), ago),
				alice(rotEE(rotKeyOld3), day),
				alice(rotEE(rotKeyOld4), day),
			),
			usable: []string{
				rotUse("alice", "old1", "ee", day),
				rotUse("alice", "old2", "ee", day),
				rotUse("alice", "old3", "ee", day),
				rotUse("alice", "old4", "ee", day),
			},
			expired: 1,
		},
		{
			name: "rule 8 counts a key once after rule 7",
			text: rotFile(
				alice(rotEE(rotKeyOld1), day),
				alice(rotEE(rotKeyOld1), twoDays),
				alice(rotEE(rotKeyOld2), day),
				alice(rotEE(rotKeyOld3), day),
				alice(rotEE(rotKeyOld4), day),
			),
			usable: []string{
				rotUse("alice", "old1", "ee", twoDays),
				rotUse("alice", "old2", "ee", day),
				rotUse("alice", "old3", "ee", day),
				rotUse("alice", "old4", "ee", day),
			},
			notes: []string{duplicateNote(1, "alice")},
		},
		{
			name: "rule 8 counts no entry another rule took",
			text: rotFile(
				alice(rotEE(rotKeyOld1), day),
				alice(rotEE(rotKeyOld2), day),
				alice(rotKeyAlice, day),
				alice(rotEE(rotKeyOld3), day),
				alice(rotEE(rotKeyOld4), day),
			),
			usable: []string{
				rotUse("alice", "old1", "ee", day),
				rotUse("alice", "old2", "ee", day),
				rotUse("alice", "old3", "ee", day),
				rotUse("alice", "old4", "ee", day),
			},
			notes: []string{ownPrimaryNote(3, "alice")},
		},
		{
			name: "rule 8 caps per name: five entries over two names are all kept, in file order",
			text: rotFile(
				alice(rotEE(rotKeyOld1), day),
				bob(rotEE(rotKeyOld5), twoDays),
				alice(rotDD(rotKeyOld2), day),
				alice(rotKeyOld3, day),
				alice(rotEE(rotKeyOld4), day),
			),
			usable: []string{
				rotUse("alice", "old1", "ee", day),
				rotUse("bob", "old5", "ee", twoDays),
				rotUse("alice", "old2", "dd", day),
				rotUse("alice", "old3", "plain", day),
				rotUse("alice", "old4", "ee", day),
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			conf := rotParse(t, tc.text)
			require.Empty(t, conf.UnknownKeys)

			report := conf.GetRetiringSecrets(rotNow)

			rotSame(t, tc.usable, rotUsable(report), "usable")
			rotSame(t, tc.lines, report.Lines, "lines")
			rotSame(t, tc.notes, report.Notes, "notes")
			assert.Equal(t, tc.expired, report.Expired, "expired")

			assert.Empty(t, rotLeaks(strings.Join(append(report.Lines, report.Notes...), "\n"), rotAllValues...),
				"a line or a note carries a value")
		})
	}

	t.Run("rule 8: past 4096 in all, the latest until are kept, then by name, then by key bytes", func(t *testing.T) {
		t.Parallel()

		for _, variant := range []struct {
			name      string
			earlyName int // the name whose entries expire first; -1 for none
		}{
			{"a tie on until falls to name and key bytes", -1},
			{"the entries that expire first are dropped", 0},
		} {
			// 1,025 names: u0000..u1022 with 4 entries each, u1023 with 3 and
			// u1024 with 2, so 4,097 entries and one over the cap.
			var blocks, secrets strings.Builder

			n, dropped := 0, 0

			for i := range 1025 {
				name := fmt.Sprintf("u%04d", i)
				fmt.Fprintf(&secrets, "%s = %q\n", name, rotEE(fmt.Sprintf("ff%030x", i+1)))

				count := 4

				switch i {
				case 1023:
					count = 3
				case 1024:
					count = 2
				}

				// Each name's entries are written with descending key bytes, so
				// the one rule 8 drops is never simply the last one written.
				for j := count; j > 0; j-- {
					n++

					until := day
					if i == variant.earlyName {
						until = rotIn(12 * time.Hour)
					}

					fmt.Fprintf(&blocks, "[[retiring-secret]]\nname = %q\nsecret = %q\nuntil = %q\n\n",
						name, rotEE(fmt.Sprintf("%028x%04x", i+1, j)), until)

					// The one ranked last: the early name's highest key, or with
					// no early name, u1024's highest key (the first written).
					if (variant.earlyName == i && j == count) || (variant.earlyName < 0 && i == 1024 && j == count) {
						dropped = n
					}
				}
			}

			conf := rotParse(t, "bind-to = \"0.0.0.0:3128\"\n\n"+blocks.String()+"[secrets]\n"+secrets.String())
			report := conf.GetRetiringSecrets(rotNow)

			droppedName := "u1024"
			if variant.earlyName >= 0 {
				droppedName = fmt.Sprintf("u%04d", variant.earlyName)
			}

			assert.Len(t, report.Usable, mtglib.MaxRetiringSecrets, variant.name)
			assert.Equal(t, []string{problemLine(dropped, droppedName, whyOverCapAll)}, report.Lines, variant.name)
			assert.Empty(t, report.Notes, variant.name)
		}
	})
}

// C2: until is an instant with an offset, quoted or as a TOML offset
// date-time; the offset changes only the spelling. Anything else is a
// problem of the entry, never a failure to parse the file.
func TestUntilSpellings(t *testing.T) {
	t.Parallel()

	want := time.Date(2026, 10, 9, 9, 30, 0, 0, time.UTC)

	for _, tc := range []struct {
		name  string
		until string // the right-hand side, verbatim
		at    time.Time
		ok    bool
	}{
		{"a quoted instant in UTC", `"2026-10-09T09:30:00Z"`, want, true},
		{"a quoted instant with a positive offset", `"2026-10-09T13:00:00+03:30"`, want, true},
		{"a quoted instant with a negative offset", `"2026-10-09T04:30:00-05:00"`, want, true},
		{"a quoted instant with a fraction", `"2026-10-09T09:30:00.25Z"`, want.Add(250 * time.Millisecond), true},
		{"a TOML offset date-time", `2026-10-09T09:30:00Z`, want, true},
		{"a TOML offset date-time with an offset", `2026-10-09T13:00:00+03:30`, want, true},
		{"a TOML offset date-time with nanoseconds", `2026-10-09T09:30:00.123456789Z`, want.Add(123456789), true},
		{"a TOML offset date-time with a space", `2026-10-09 09:30:00Z`, want, true},
		{"a TOML local date-time", `2026-10-09T09:30:00`, time.Time{}, false},
		{"a TOML local date", `2026-10-09`, time.Time{}, false},
		{"a TOML local time", `09:30:00`, time.Time{}, false},
		{"an integer", `1791451800`, time.Time{}, false},
		{"a float", `1.5`, time.Time{}, false},
		{"a boolean", `true`, time.Time{}, false},
		{"a quoted local date-time", `"2026-10-09T09:30:00"`, time.Time{}, false},
		{"a quoted date", `"2026-10-09"`, time.Time{}, false},
		{"a quoted instant with a space", `"2026-10-09 09:30:00Z"`, time.Time{}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			conf := rotParse(t, rotFile(rotBlock(rotName("alice"), rotSecret(rotEE(rotKeyOld1)), "until = "+tc.until)))
			require.Empty(t, conf.UnknownKeys)

			report := conf.GetRetiringSecrets(rotNow)

			if !tc.ok {
				assert.Empty(t, report.Usable)
				assert.Equal(t, []string{problemLine(1, "alice", whyUntilInvalid)}, report.Lines)

				return
			}

			require.Len(t, report.Usable, 1)
			assert.True(t, report.Usable[0].Until.Equal(tc.at), "until is the same instant whatever its spelling")
			assert.Empty(t, report.Lines)
		})
	}

	t.Run("an empty until is missing", func(t *testing.T) {
		t.Parallel()

		conf := rotParse(t, rotFile(rotBlock(rotName("alice"), rotSecret(rotEE(rotKeyOld1)), `until = ""`)))
		assert.Equal(t, []string{problemLine(1, "alice", whyUntilMissing)}, conf.GetRetiringSecrets(rotNow).Lines)
	})
}

// C3: a field of the wrong TOML type -- a number, a boolean, an array, an
// inline table -- is a problem of its entry. The file still parses, still
// validates, and the entry beside it is still usable.
func TestWrongTypesAreProblemsNotParseFailures(t *testing.T) {
	t.Parallel()

	day := rotIn(24 * time.Hour)
	value := rotSecret(rotEE(rotKeyOld1))
	until := rotUntil(day)

	conf := rotParse(t, rotFile(
		rotBlock("name = 42", value, until),
		rotBlock(`name = ["alice"]`, value, until),
		rotBlock(`name = { first = "alice" }`, value, until),
		rotBlock(rotName("alice"), "secret = 42", until),
		rotBlock(rotName("alice"), fmt.Sprintf("secret = [%q]", rotEE(rotKeyOld2)), until),
		rotBlock(rotName("alice"), fmt.Sprintf("secret = { value = %q }", rotEE(rotKeyOld3)), until),
		rotBlock(rotName("alice"), "secret = true", until),
		rotBlock(rotName("alice"), value, "until = true"),
		rotBlock(rotName("alice"), value, `until = ["2026-10-09T09:30:00Z"]`),
		rotBlock(rotName("alice"), value, "until = 1791451800"),
		rotBlock(rotName("alice"), rotSecret(rotEE(rotKeyOld4)), until),
	))

	require.Empty(t, conf.UnknownKeys, "a wrong type is not an unknown key")
	require.NoError(t, conf.Validate())
	require.Len(t, conf.RetiringSecrets, 11)

	report := conf.GetRetiringSecrets(rotNow)

	assert.Equal(t, []string{
		namelessProblemLine(1, whyNameType),
		namelessProblemLine(2, whyNameType),
		namelessProblemLine(3, whyNameType),
		problemLine(4, "alice", whySecretType),
		problemLine(5, "alice", whySecretType),
		problemLine(6, "alice", whySecretType),
		problemLine(7, "alice", whySecretType),
		problemLine(8, "alice", whyUntilInvalid),
		problemLine(9, "alice", whyUntilInvalid),
		problemLine(10, "alice", whyUntilInvalid),
	}, report.Lines)
	assert.Equal(t, []string{rotUse("alice", "old4", "ee", day)}, rotUsable(report),
		"one bad block never takes its neighbour with it")
	assert.Empty(t, rotLeaks(strings.Join(report.Lines, "\n"), rotAllValues...))
}

// C4: Validate never looks at the table. web-relay, access and doctor run it,
// none of them serves a retiring key, and a problem in one drops that entry
// under run instead of refusing the file.
func TestValidateIgnoresRetiringEntries(t *testing.T) {
	t.Parallel()

	day := rotIn(24 * time.Hour)
	alice := func(value, until string) string { return rotBlock(rotName("alice"), rotSecret(value), rotUntil(until)) }

	for _, text := range []string{
		rotFile(
			rotBlock(rotName("carol"), rotSecret(rotEE(rotKeyOld1)), rotUntil(day)),
			rotBlock(rotName("alice"), "secret = 7", rotUntil(day)),
			rotBlock("name = 7", rotSecret(rotEE(rotKeyOld1)), rotUntil(day)),
			alice(rotEE(rotKeyZero), day),
			alice(rotEE(rotKeyOld1), "2026-10-09T09:30:00"),
			alice(rotEE(rotKeyBob), day),
			alice(rotEE(rotKeyOld1), rotIn(721*time.Hour)),
			alice(rotEE(rotKeyOld2), day),
			alice(rotEE(rotKeyOld3), day),
			alice(rotEE(rotKeyOld4), day),
			alice(rotEE(rotKeyOld5), day),
			alice(rotEE(rotKeyLeak), rotIn(-time.Hour)),
		),
		rotSingleFile(alice(rotEE(rotKeyOld1), day), rotBlock(rotName("default"), "secret = []", rotUntil(day))),
	} {
		conf := rotParse(t, text)

		require.NotEmpty(t, conf.GetRetiringSecrets(rotNow).Lines, "the file has problems to ignore")
		assert.NoError(t, conf.Validate(), "Validate never refuses a file for its retiring entries")
	}
}

// C11: a misspelt field inside a block is an unknown key, named by its path,
// as in every other table; the block itself, spelt right, is not.
func TestAnUnknownFieldInTheBlockIsAnUnknownKey(t *testing.T) {
	t.Parallel()

	day := rotIn(24 * time.Hour)

	clean := rotParse(t, rotFile(rotBlock(rotName("alice"), rotSecret(rotEE(rotKeyOld1)), rotUntil(day))))
	assert.Empty(t, clean.UnknownKeys, "[[retiring-secret]] is a table this binary reads")

	conf := rotParse(t, rotFile(rotBlock(rotName("alice"), fmt.Sprintf("secrte = %q", rotEE(rotKeyLeak)), rotUntil(day))))

	assert.Equal(t, []string{"retiring-secret.secrte"}, conf.UnknownKeys)
	assert.Equal(t, []string{problemLine(1, "alice", whySecretMissing)}, conf.GetRetiringSecrets(rotNow).Lines,
		"the misspelt field gave the entry no value")
	assert.Empty(t, rotLeaks(strings.Join(conf.UnknownKeyWarnings(), "\n"), rotEE(rotKeyLeak)),
		"an unknown key is named by its path, never by its value")
}

// C13, rule 4 as a named sequence: an until 721h away is kept with a warning
// now (run --check refuses the file), and still kept an hour later, when it is
// 720h away and nothing is said (run --check accepts it). Dropping it now
// would accept it an hour later: P2 is why rule 4 is a warning.
func TestAnOverLongUntilIsWarnedNotDropped(t *testing.T) {
	t.Parallel()

	until := rotIn(721 * time.Hour)
	text := rotFile(rotBlock(rotName("alice"), rotSecret(rotEE(rotKeyOld1)), rotUntil(until)))
	kept := []string{rotUse("alice", "old1", "ee", until)}

	now := rotParse(t, text).GetRetiringSecrets(rotNow)
	assert.Equal(t, kept, rotUsable(now), "kept now")
	assert.Equal(t, []string{overLongLine(1, "alice")}, now.Lines, "warned now: run --check refuses")

	later := rotParse(t, text).GetRetiringSecrets(rotNow.Add(time.Hour))
	assert.Equal(t, kept, rotUsable(later), "still kept an hour later")
	assert.Empty(t, later.Lines, "720h away is not over-long: run --check accepts")

	after := rotParse(t, text).GetRetiringSecrets(rotNow.Add(721 * time.Hour))
	assert.Empty(t, after.Usable, "bounded by its own until")
	assert.Equal(t, 1, after.Expired)
	assert.Empty(t, after.Lines)
}

// C14, rule 5 as a named sequence: alice (until T1) and bob (until T2 > T1)
// share a retiring key. Both are dropped before T1, and bob's entry stays
// dropped after T1, when alice's has expired, every time the file is re-read:
// rule 5 is judged against every syntactically valid entry, expired or not,
// so the collision does not go away with time and a dropped key never comes
// back.
func TestACrossNameCollisionStaysDroppedAfterOneExpires(t *testing.T) {
	t.Parallel()

	t1, t2 := rotNow.Add(2*time.Hour), rotNow.Add(4*time.Hour)
	text := rotFile(
		rotBlock(rotName("alice"), rotSecret(rotEE(rotKeyOld1)), rotUntil(t1.Format(time.RFC3339))),
		rotBlock(rotName("bob"), rotSecret(rotB64(rotDD(rotKeyOld1))), rotUntil(t2.Format(time.RFC3339))),
	)

	for _, step := range []struct {
		name    string
		now     time.Time
		lines   []string
		expired int
	}{
		{"before T1", rotNow, []string{problemLine(1, "alice", whyKeyOfOther), problemLine(2, "bob", whyKeyOfOther)}, 0},
		{"just before T1", t1.Add(-time.Nanosecond), []string{problemLine(1, "alice", whyKeyOfOther), problemLine(2, "bob", whyKeyOfOther)}, 0},
		{"at T1", t1, []string{problemLine(2, "bob", whyKeyOfOther)}, 1},
		{"between T1 and T2", t1.Add(time.Hour), []string{problemLine(2, "bob", whyKeyOfOther)}, 1},
		{"at T2", t2, nil, 2},
	} {
		report := rotParse(t, text).GetRetiringSecrets(step.now)

		assert.Empty(t, report.Usable, "%s: neither entry is ever usable", step.name)
		rotSame(t, step.lines, report.Lines, step.name)
		assert.Equal(t, step.expired, report.Expired, step.name)
	}
}

// The C8 slice for the config layer: a retiring value placed everywhere a
// file can hold it -- every rule, every wrong type, a misspelt field, a value
// that does not parse -- never reaches a line, a note, an unknown-key warning
// or Config.String(); nor does it reach the error of a file whose table has a
// shape the parser refuses (the one shape that blocks a load). Only that
// error's Error() is ever printed: (*toml.DecodeError).String() quotes the
// document, and nothing calls it.
func TestConfigLinesNeverCarryTheValue(t *testing.T) {
	t.Parallel()

	leak := rotEE(rotKeyLeak)
	zero := rotEE(rotKeyZero)
	values := []string{leak, rotDD(rotKeyLeak), rotKeyLeak, zero}

	day := rotIn(24 * time.Hour)
	alice := func(value, until string) string { return rotBlock(rotName("alice"), rotSecret(value), rotUntil(until)) }

	// bob's primary, then alice's, is the leaked value.
	leakIsBobs := "bind-to = \"0.0.0.0:3128\"\n\n" +
		alice(leak, day) + rotBlock(rotName("bob"), rotSecret(rotB64(leak)), rotUntil(day)) +
		"[secrets]\nalice = \"" + rotEE(rotKeyAlice) + "\"\nbob = \"" + leak + "\"\n"

	parsed := []string{
		rotFile(alice(leak, day)),
		rotFile(alice(rotB64(leak), rotIn(-time.Hour))),
		rotFile(rotBlock(rotName("carol"), rotSecret(leak), rotUntil(day))),
		rotFile(rotBlock(rotName("default"), rotSecret(leak), rotUntil(day))),
		rotSingleFile(rotBlock(rotName("default"), rotSecret(leak), rotUntil(day))),
		rotFile(alice(leak, rotIn(721*time.Hour))),
		rotFile(alice(leak, day), rotBlock(rotName("bob"), rotSecret(rotB64(rotDD(rotKeyLeak))), rotUntil(day))),
		leakIsBobs,
		rotFile(alice(leak, day), alice(rotB64(leak), rotIn(48*time.Hour))),
		rotFile(
			alice(leak, rotIn(12*time.Hour)),
			alice(rotEE(rotKeyOld1), day), alice(rotEE(rotKeyOld2), day),
			alice(rotEE(rotKeyOld3), day), alice(rotEE(rotKeyOld4), day),
		),
		rotFile(rotBlock(rotName("alice"), fmt.Sprintf("secret = [%q]", leak), rotUntil(day))),
		rotFile(rotBlock(rotName("alice"), fmt.Sprintf("secret = { value = %q }", leak), rotUntil(day))),
		rotFile(rotBlock(fmt.Sprintf("name = [%q]", leak), rotSecret(rotEE(rotKeyOld1)), rotUntil(day))),
		rotFile(rotBlock(rotName("alice"), rotSecret(rotEE(rotKeyOld1)), fmt.Sprintf("until = [%q]", leak))),
		rotFile(rotBlock(rotName("alice"), rotSecret(rotEE(rotKeyOld1)), fmt.Sprintf("until = { at = %q }", rotB64(leak)))),
		rotFile(alice(leak+"zz", day)),
		rotFile(alice("ff"+leak[2:], day)),
		rotFile(alice(zero, day)),
		rotFile(rotBlock(rotName("alice"), fmt.Sprintf("secrte = %q", leak), rotUntil(day))),
	}

	for i, text := range parsed {
		conf := rotParse(t, text)

		var seen []string

		for _, at := range []time.Time{rotNow, rotNow.Add(1000 * time.Hour)} {
			report := conf.GetRetiringSecrets(at)
			seen = append(seen, report.Lines...)
			seen = append(seen, report.Notes...)
		}

		seen = append(seen, conf.UnknownKeyWarnings()...)
		seen = append(seen, conf.String())

		assert.Empty(t, rotLeaks(strings.Join(seen, "\n"), values...), "file %d", i)
	}

	// The one shape of the table that blocks a load, and other documents the
	// parser refuses while holding the value.
	for i, text := range []string{
		"bind-to = \"0.0.0.0:3128\"\nretiring-secret = \"" + leak + "\"\n\n[secrets]\nalice = \"" + rotEE(rotKeyAlice) + "\"\n",
		"bind-to = \"0.0.0.0:3128\"\nretiring-secret = \"" + rotB64(leak) + "\"\n",
		"bind-to = \"0.0.0.0:3128\"\nretiring-secret = [\"" + leak + "\"]\n",
		"bind-to = \"0.0.0.0:3128\"\n\n[[retiring-secret]]\nsecret = \"" + leak + "\"\nsecret = \"" + leak + "\"\n",
		"bind-to = \"0.0.0.0:3128\"\n\n[[retiring-secret]]\nsecret = \"" + leak + "\n",
	} {
		_, err := config.Parse([]byte(text))
		require.Error(t, err, "document %d is refused", i)

		assert.Empty(t, rotLeaks(err.Error(), values...), "document %d: the parser's error", i)
	}
}
