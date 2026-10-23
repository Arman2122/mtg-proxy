package cli

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"maps"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Arman2122/mtg-proxy/internal/utils"
	"github.com/Arman2122/mtg-proxy/mtglib"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// run --check refuses a [[retiring-secret]] table with a problem in it and
// accepts one whose entries are only inert; run itself never refuses for an
// entry, and a table that does not parse at all refuses the whole file, in
// words that name the shape and never the value.

// retiringLeaks names the spellings of each secret that text carries: the
// value in hex (any case), in base64url and in standard base64, and the key in
// hex (any case), in standard base64 and in base64url. It returns labels, never
// a spelling, so a failing assertion prints no credential. The unpadded base64
// forms are checked because the padded ones contain them.
//
// The key in another mode's form is looked for too (Task 10's review, M-8):
// its dd value in both base64 alphabets, and the first 21 characters of its ee
// value in both, which are the same whatever host follows. Hex needs no such
// row: the key's hex is inside every mode's.
func retiringLeaks(text string, secrets ...mtglib.Secret) []string {
	var leaks []string

	lower := strings.ToLower(text)

	for i, secret := range secrets {
		value, err := hex.DecodeString(secret.Hex())
		if err != nil {
			panic(err)
		}

		ddForm := append([]byte{0xdd}, secret.Key[:]...)
		eeForm := append([]byte{0xee}, secret.Key[:]...)

		for label, spelling := range map[string]string{
			"the value in hex":                     secret.Hex(),
			"the value in base64url":               base64.RawURLEncoding.EncodeToString(value),
			"the value in standard base64":         base64.RawStdEncoding.EncodeToString(value),
			"the key in hex":                       hex.EncodeToString(secret.Key[:]),
			"the key in standard base64":           base64.RawStdEncoding.EncodeToString(secret.Key[:]),
			"the key in base64url":                 base64.RawURLEncoding.EncodeToString(secret.Key[:]),
			"the key's dd form in standard base64": base64.RawStdEncoding.EncodeToString(ddForm),
			"the key's dd form in base64url":       base64.RawURLEncoding.EncodeToString(ddForm),
			"the key's ee form in standard base64": base64.RawStdEncoding.EncodeToString(eeForm)[:21],
			"the key's ee form in base64url":       base64.RawURLEncoding.EncodeToString(eeForm)[:21],
		} {
			haystack := text
			if strings.HasPrefix(label, "the value in hex") || strings.HasPrefix(label, "the key in hex") {
				haystack, spelling = lower, strings.ToLower(spelling)
			}

			if strings.Contains(haystack, spelling) {
				leaks = append(leaks, fmt.Sprintf("secret %d: %s", i, label))
			}
		}
	}

	return leaks
}

// retiringBlock is one [[retiring-secret]] block as an operator writes it.
func retiringBlock(name string, secret mtglib.Secret, until string) string {
	return fmt.Sprintf("[[retiring-secret]]\nname = %q\nsecret = %q\nuntil = %q\n\n", name, secret.Hex(), until)
}

// retiringFile is a config with the given top-level bind-to, the blocks, and
// [secrets] last, the layout rotate-secret writes.
func retiringFile(bindTo string, secrets map[string]mtglib.Secret, blocks ...string) string {
	var out strings.Builder

	fmt.Fprintf(&out, "bind-to = %q\n\n", bindTo)

	for _, block := range blocks {
		out.WriteString(block)
	}

	out.WriteString("[secrets]\n")

	for _, name := range []string{"alice", "bob", "carol"} {
		if secret, ok := secrets[name]; ok {
			fmt.Fprintf(&out, "%s = %q\n", name, secret.Hex())
		}
	}

	return out.String()
}

// rfc3339 is how a test writes an until.
func rfc3339(at time.Time) string {
	return at.UTC().Format(time.RFC3339)
}

// C5. A problem refuses the file, and the refusal names the entry and never its
// value; an inert entry -- expired, its own primary, a duplicate -- does not,
// and neither does an expired block whose name has since left [secrets].
func TestRunCheckRefusesProblemsAndAcceptsInertEntries(t *testing.T) {
	t.Parallel()

	alice := mtglib.GenerateSecret("cover.example.com")
	bob := mtglib.GenerateSecret("cover.example.com")
	aliceOld := mtglib.GenerateSecret("old.example.com")
	shared := mtglib.GenerateSecret("old.example.com")
	everyValue := []mtglib.Secret{alice, bob, aliceOld, shared}

	primaries := map[string]mtglib.Secret{"alice": alice, "bob": bob}

	// run --check reads the wall clock, so these are wide of it.
	now := time.Now()
	tomorrow := rfc3339(now.Add(24 * time.Hour))
	dayAfter := rfc3339(now.Add(48 * time.Hour))
	yesterday := rfc3339(now.Add(-24 * time.Hour))
	farAway := rfc3339(now.Add(800 * time.Hour))

	const tail = "; the entry is ignored and its key is not accepted"

	refused := map[string]struct {
		blocks []string
		lines  []string
	}{
		"a name that is not a configured secret": {
			blocks: []string{retiringBlock("carol", aliceOld, tomorrow)},
			lines:  []string{`retiring-secret #1 (name "carol"): name is not a configured secret` + tail},
		},
		"a malformed until": {
			blocks: []string{retiringBlock("alice", aliceOld, "tomorrow")},
			lines: []string{`retiring-secret #1 (name "alice"): until is not an RFC 3339 date-time with an offset, ` +
				`such as 2026-10-09T09:30:00Z` + tail},
		},
		"an until more than 720h away": {
			blocks: []string{retiringBlock("alice", aliceOld, farAway)},
			lines: []string{`retiring-secret #1 (name "alice"): until is more than 720h away; it is honoured, ` +
				`but an overlap is a migration window, not a second key: shorten it (run --check refuses this file)`},
		},
		"another secret's primary key": {
			blocks: []string{retiringBlock("alice", bob, tomorrow)},
			lines:  []string{`retiring-secret #1 (name "alice"): the key is another secret's primary key` + tail},
		},
		"a key two names hold as retiring": {
			blocks: []string{retiringBlock("alice", shared, tomorrow), retiringBlock("bob", shared, dayAfter)},
			lines: []string{
				`retiring-secret #1 (name "alice"): the key is also the key of a retiring-secret entry of another name` + tail,
				`retiring-secret #2 (name "bob"): the key is also the key of a retiring-secret entry of another name` + tail,
			},
		},
	}

	for name, tc := range refused {
		t.Run("refuses "+name, func(t *testing.T) {
			t.Parallel()

			r := &Run{ConfigPath: writeConfig(t, retiringFile("127.0.0.1:3128", primaries, tc.blocks...)), Check: true}

			// First, so that no failing assertion below prints a key.
			err := r.Run(nil, "test")
			require.Empty(t, retiringLeaks(errText(err), everyValue...), "the refusal carries a key")

			require.ErrorIs(t, err, errRetiringProblems)
			assert.NotErrorIs(t, err, errUnknownKeys)

			for _, line := range tc.lines {
				assert.Contains(t, err.Error(), line)
			}
		})
	}

	accepted := map[string][]string{
		"an unexpired, well-formed entry":                    {retiringBlock("alice", aliceOld, tomorrow)},
		"an expired entry":                                   {retiringBlock("alice", aliceOld, yesterday)},
		"an expired block whose name has left [secrets]":     {retiringBlock("carol", aliceOld, yesterday)},
		"an entry whose key is its own name's primary":       {retiringBlock("alice", alice, tomorrow)},
		"two entries of one name with one key":               {retiringBlock("alice", aliceOld, tomorrow), retiringBlock("alice", aliceOld, dayAfter)},
		"an expired entry beside an unexpired one":           {retiringBlock("alice", shared, yesterday), retiringBlock("bob", aliceOld, tomorrow)},
		"an expired block of a removed name, and a live one": {retiringBlock("carol", shared, yesterday), retiringBlock("alice", aliceOld, tomorrow)},
	}

	for name, blocks := range accepted {
		t.Run("accepts "+name, func(t *testing.T) {
			t.Parallel()

			r := &Run{ConfigPath: writeConfig(t, retiringFile("127.0.0.1:3128", primaries, blocks...)), Check: true}

			err := r.Run(nil, "test")
			require.Empty(t, retiringLeaks(errText(err), everyValue...), "the refusal carries a key")
			require.NoError(t, err)
		})
	}

	// checkConfig judges at the instant it is given: an entry for a name that
	// has left [secrets] is a problem while it is unexpired and inert once it
	// is not. run --check passes the wall clock, which the rows above pin: at the
	// zero time every one of them but the own-primary entry would be refused.
	t.Run("judges at the instant it is given", func(t *testing.T) {
		t.Parallel()

		until := time.Date(2026, 10, 9, 9, 30, 0, 0, time.UTC)

		conf, err := utils.ParseConfig([]byte(
			retiringFile("127.0.0.1:3128", primaries, retiringBlock("carol", aliceOld, rfc3339(until)))))
		require.NoError(t, err)

		require.ErrorIs(t, checkConfig(conf, until.Add(-time.Hour)), errRetiringProblems)
		require.NoError(t, checkConfig(conf, until))
		require.NoError(t, checkConfig(conf, until.Add(time.Hour)))
	})

	t.Run("names unknown keys and problems together", func(t *testing.T) {
		t.Parallel()

		raw := "track-client-ip = true\n" + retiringFile("127.0.0.1:3128", primaries, retiringBlock("carol", aliceOld, tomorrow))

		err := (&Run{ConfigPath: writeConfig(t, raw), Check: true}).Run(nil, "test")
		require.Empty(t, retiringLeaks(errText(err), everyValue...), "the refusal carries a key")
		require.ErrorIs(t, err, errUnknownKeys)
		require.ErrorIs(t, err, errRetiringProblems)
		assert.Contains(t, err.Error(), "track-client-ip")
		assert.Contains(t, err.Error(), `retiring-secret #1 (name "carol")`)
	})
}

// C10. The file the panel writes has no [[retiring-secret]] table, and run
// --check over it reports nothing new, at any instant.
func TestThePanelsConfigHasNoRetiringLines(t *testing.T) {
	t.Parallel()

	// The copy Task 8a keeps of TestPanelEmittedConfigIsAccepted's text, which
	// a config test re-asserts on every run.
	const panelFile = "../config/testdata/panel-rendered.toml"

	require.NoError(t, (&Run{ConfigPath: panelFile, Check: true}).Run(nil, "test"))

	conf, err := utils.ReadConfig(panelFile)
	require.NoError(t, err)

	for _, at := range []time.Time{
		time.Now(),
		time.Date(2026, 10, 8, 9, 30, 0, 0, time.UTC),
		time.Date(2200, 1, 1, 0, 0, 0, 0, time.UTC),
	} {
		require.NoError(t, checkConfig(conf, at))

		report := conf.GetRetiringSecrets(at)
		assert.Empty(t, report.Lines)
		assert.Empty(t, report.Notes)
		assert.Zero(t, report.Expired)
		assert.Zero(t, len(report.Usable), "the panel's file holds no retiring entry")
	}

	// It serves what it always served, and run logs nothing new over it.
	assert.Equal(t, []string{"alice"}, slices.Sorted(maps.Keys(conf.GetSecrets())))

	log, sink := newLevelLogger()
	assert.Zero(t, len(usableRetiringSecrets(conf, mtglib.NewRotationClock(time.Now, nil), log)))
	assert.Zero(t, len(sink.all()), "run logs something new for the panel's file")
}

// runRefuses runs `run` (not --check) on path and returns what it returned. A
// run that started would never return, so it is given a deadline: a file run
// must refuse is one it must refuse before it listens.
func runRefuses(t *testing.T, path string) error {
	t.Helper()

	done := make(chan error, 1)

	go func() { done <- (&Run{ConfigPath: path}).Run(nil, "test") }()

	select {
	case err := <-done:
		return err
	case <-time.After(15 * time.Second):
		t.Fatal("run started on a file it must refuse")

		return nil
	}
}

// C15. The table's shapes. A single [retiring-secret] table is one usable
// entry. A scalar, an inline table, a TOML syntax error inside a block, and a
// [secrets] user named retiring-secret written twice each refuse the whole file:
// run does not start, a reload keeps the set in force -- the leaked key
// included, when the same edit re-keyed it, which the reload's error says -- and
// run --check and doctor print the parser's Error() form only, after words of
// their own that name the shape and never the value. A file that starts with a
// UTF-8 byte-order mark is refused too, as it is today, with no such words.
//
// Every failing assertion here runs after the leak check, so none prints a key.
func TestTheTablesShapes(t *testing.T) {
	t.Parallel()

	t.Run("a single [retiring-secret] table is one usable entry", func(t *testing.T) {
		t.Parallel()

		old := mtglib.GenerateSecret("old.example.com")
		renewed := mtglib.GenerateSecret("cover.example.com")
		until := time.Now().Add(24 * time.Hour).Truncate(time.Second)

		raw := fmt.Sprintf("bind-to = \"127.0.0.1:%d\"\n\n[retiring-secret]\nname = \"alice\"\nsecret = %q\nuntil = %q\n\n"+
			"[secrets]\nalice = %q\n", takenPort(t), old.Hex(), rfc3339(until), renewed.Hex())
		path := writeConfig(t, raw)

		conf, err := utils.ParseConfig([]byte(raw))
		require.NoError(t, err)
		assert.Empty(t, conf.UnknownKeys)

		err = (&Run{ConfigPath: path, Check: true}).Run(nil, "test")
		require.Empty(t, retiringLeaks(errText(err), old, renewed), "the refusal carries a key")
		require.NoError(t, err)

		cfg, err := makeSecretsReloader(path, newRecordingLogger(), mtglib.NewRotationClock(time.Now, nil))()
		require.NoError(t, err)
		require.Equal(t, 1, len(cfg.Retiring), "one block, one entry")
		assert.Equal(t, "alice", cfg.Retiring[0].Name)
		assert.True(t, cfg.Retiring[0].Secret == old, "the entry holds the block's key")
		assert.True(t, cfg.Retiring[0].Until.Equal(until))
	})

	old := mtglib.GenerateSecret("old.example.com")
	renewed := mtglib.GenerateSecret("cover.example.com")
	tomorrow := rfc3339(time.Now().Add(24 * time.Hour))

	const (
		atTheKey     = "at a key named retiring-secret"
		insideABlock = "inside a [[retiring-secret]] block"
	)

	// Every refused file re-keys alice to renewed and keeps old on the refused
	// line, so a printed document shows a value and a reload that went through
	// would change the primary.
	refused := map[string]struct {
		text   func(bindTo string) string
		line   int    // where the parser stops; 0 for the BOM, which names none
		where  string // what run, --check and doctor say it stopped at; "" for no advice
		reason string
	}{
		"a scalar where the table belongs": {
			text: func(bindTo string) string {
				return fmt.Sprintf("bind-to = %q\nretiring-secret = %q\n\n[secrets]\nalice = %q\n",
					bindTo, old.Hex(), renewed.Hex())
			},
			line:   2,
			where:  atTheKey,
			reason: "cannot decode TOML string",
		},
		"an inline table": {
			text: func(bindTo string) string {
				return fmt.Sprintf("bind-to = %q\nretiring-secret = { name = \"alice\", secret = %q, until = %q }\n\n"+
					"[secrets]\nalice = %q\n", bindTo, old.Hex(), tomorrow, renewed.Hex())
			},
			line:   2,
			where:  atTheKey,
			reason: "cannot decode TOML inline table",
		},
		"a TOML syntax error inside a block": {
			text: func(bindTo string) string {
				return fmt.Sprintf("bind-to = %q\n\n[[retiring-secret]]\nname = \"alice\"\nsecret = %q\n"+
					"until = 2026-02-30T09:30:00Z\n\n[secrets]\nalice = %q\n", bindTo, old.Hex(), renewed.Hex())
			},
			line:   6,
			where:  insideABlock,
			reason: "impossible date",
		},
		// The I1 mis-edit, written twice below [secrets]: that does not parse,
		// and the words are the ones its single form gets from run.
		"a [secrets] user named retiring-secret, twice": {
			text: func(bindTo string) string {
				return fmt.Sprintf("bind-to = %q\n\n[secrets]\nalice = %q\nretiring-secret = %q\nretiring-secret = %q\n",
					bindTo, renewed.Hex(), old.Hex(), old.Hex())
			},
			line:   6,
			where:  atTheKey,
			reason: "is already defined",
		},
		"a UTF-8 byte-order mark": {
			text: func(bindTo string) string {
				return "\xef\xbb\xbf" + retiringFile(bindTo, map[string]mtglib.Secret{"alice": renewed},
					retiringBlock("alice", old, tomorrow))
			},
			reason: "invalid character at start of key",
		},
	}

	for name, tc := range refused {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			// A port held by the test: a run that wrongly got past the parse
			// fails at its bind and returns, rather than serving.
			bindTo := fmt.Sprintf("127.0.0.1:%d", takenPort(t))
			raw := tc.text(bindTo)
			path := writeConfig(t, raw)

			_, err := utils.ParseConfig([]byte(raw))
			require.Empty(t, retiringLeaks(errText(err), old, renewed), "the parse error carries a key")
			require.Error(t, err, "the whole file is refused")

			ran := runRefuses(t, path)
			checked := (&Run{ConfigPath: path, Check: true}).Run(nil, "test")
			doctored := (&Doctor{ConfigPath: path}).Run(nil, "test")

			for who, err := range map[string]error{"run": ran, "run --check": checked, "doctor": doctored} {
				// First, so that no failing assertion below prints a key: a
				// String() form, which quotes the refused line, has one.
				text := errText(err)
				require.Empty(t, retiringLeaks(text, old, renewed), who+" prints a key")

				require.Error(t, err, who)
				assert.Contains(t, text, "cannot init config", who+" refuses before anything else")
				assert.Contains(t, text, tc.reason, who+" prints the parser's error")
				assert.False(t, strings.Contains(text, "\n"), who+" prints the one-line Error() form only")

				if tc.where != "" {
					assert.Contains(t, text, fmt.Sprintf("the file does not parse at line %d, %s", tc.line, tc.where), who)
					assert.Contains(t, text, retiringShapeAdvice, who)
				} else {
					assert.NotContains(t, text, retiringShapeAdvice, who+" blames the table for an error elsewhere")
				}
			}

			// A reload keeps the set in force, and so the leaked key stays the
			// primary until the file is fixed -- which the reload's error says.
			proxy := reloadingProxy(t, path, retiringFile(bindTo, map[string]mtglib.Secret{"alice": old}))

			require.NoError(t, os.WriteFile(path, []byte(raw), 0o600))

			reloadErr := proxy.ReloadSecrets()
			require.Empty(t, retiringLeaks(errText(reloadErr), old, renewed), "the reload's error carries a key")
			require.Error(t, reloadErr)

			if tc.where != "" {
				assert.Contains(t, reloadErr.Error(), retiringShapeAdvice)
				assert.True(t, strings.HasSuffix(reloadErr.Error(), "; the secret set in force is kept: "+
					"nothing in this edit is applied; if it re-keyed [secrets] or secret, "+
					"the old key stays the primary until the file is fixed and reloaded"),
					"the refused reload does not say what stays in force")
			} else {
				assert.NotContains(t, reloadErr.Error(), retiringReloadKept)
			}

			alice := snapshotOf(t, proxy, "alice")
			assert.True(t, alice.Secret == old.Base64(), "the refused reload changed the primary")
			assert.Zero(t, alice.RetiringKeys)
		})
	}
}
