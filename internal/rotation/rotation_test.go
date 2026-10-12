package rotation

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Arman2122/mtg-proxy/internal/config"
	"github.com/Arman2122/mtg-proxy/mtglib"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testNow is the run's one instant in every test, and testUntil the end of a
// 24h overlap from it, as rotate-secret writes it.
var (
	testNow   = time.Date(2026, 10, 8, 9, 30, 0, 0, time.UTC)
	testUntil = testNow.Add(24 * time.Hour)
)

const (
	hostHex = "73746f726167652e676f6f676c65617069732e636f6d" // storage.googleapis.com

	// 16-byte keys, in hex.
	keyAlice      = "a1a1a1a1b2b2b2b2c3c3c3c3d4d4d4d4"
	keyBob        = "b5b5b5b5c6c6c6c6d7d7d7d7e8e8e8e8"
	keyOld1       = "1111111111111111aaaaaaaaaaaaaaaa"
	keyOld2       = "2222222222222222bbbbbbbbbbbbbbbb"
	keyOld3       = "3333333333333333cccccccccccccccc"
	keyOld4       = "4444444444444444dddddddddddddddd"
	keyOld5       = "5555555555555555eeeeeeeeeeeeeeee"
	keyOld6       = "6666666666666666ffffffffffffffff"
	keyExample    = "367a189aee18fa31c190054efd4a8e95" // example.config.toml's alice
	keyExampleBob = "0123456789abcdef0123456789abcd95" // and its bob

	// keyNew is the key every test hands Apply as the new primary.
	keyNew = "c0ffee00c0ffee00c0ffee00c0ffee00"
)

// fixtureKeys are every key a fixture holds; the leak checks look for each in
// every spelling and every mode.
var fixtureKeys = []string{
	keyAlice, keyBob, keyOld1, keyOld2, keyOld3, keyOld4, keyOld5, keyOld6, keyExample, keyExampleBob,
}

// ee is key's ee value fronting storage.googleapis.com, in hex.
func ee(key string) string { return "ee" + key + hostHex }

// dd is key's dd value, in hex.
func dd(key string) string { return "dd" + key }

// b64 respells a hex value in base64url.
func b64(valueHex string) string {
	raw, err := hex.DecodeString(valueHex)
	if err != nil {
		panic(err)
	}

	return base64.RawURLEncoding.EncodeToString(raw)
}

func mustKey(keyHex string) [mtglib.SecretKeyLength]byte {
	var key [mtglib.SecretKeyLength]byte

	raw, err := hex.DecodeString(keyHex)
	if err != nil || len(raw) != len(key) {
		panic("not a 16-byte key in hex")
	}

	copy(key[:], raw)

	return key
}

// newPrimaryLike is what a run generates for old: the fixed new key, in old's
// mode and host.
func newPrimaryLike(old mtglib.Secret) mtglib.Secret {
	return mtglib.Secret{Key: mustKey(keyNew), Host: old.Host, Mode: old.Mode}
}

// lines is a document of the given lines, each ending in LF.
func lines(text ...string) []byte {
	return []byte(strings.Join(text, "\n") + "\n")
}

func quoted(value string) string { return `"` + value + `"` }

func at(d time.Duration) string { return testNow.Add(d).Format(time.RFC3339) }

func fixture(t *testing.T, name string) []byte {
	t.Helper()

	data, err := os.ReadFile(filepath.Join("testdata", name))
	require.NoError(t, err)
	require.False(t, bytes.Contains(data, []byte("\r")), "%s: fixtures are LF; a CRLF one is built in its test", name)

	return data
}

func toCRLF(lf []byte) []byte { return bytes.ReplaceAll(lf, []byte("\n"), []byte("\r\n")) }

// assertSameBytes compares an edited document with what it must be. A
// mismatch names the first line that differs and the line counts, never the
// text: both hold secret values.
func assertSameBytes(t *testing.T, want, got []byte, what string) bool {
	t.Helper()

	if bytes.Equal(want, got) {
		return true
	}

	wantLines := bytes.SplitAfter(want, []byte("\n"))
	gotLines := bytes.SplitAfter(got, []byte("\n"))

	line := 0
	for line < len(wantLines) && line < len(gotLines) && bytes.Equal(wantLines[line], gotLines[line]) {
		line++
	}

	return assert.Fail(t, what+": the bytes differ",
		"first difference on line %d (want %d lines, %d bytes; got %d lines, %d bytes)",
		line+1, len(wantLines), len(want), len(gotLines), len(got))
}

// leaks names the spellings of a fixture key that text carries: each key's
// ee, dd and plain values in hex, base64url and base64, and the key itself in
// hex, base64 and base64url. It names them by label and never prints one; hex
// is matched in either case.
func leaks(text string) []string {
	lower := strings.ToLower(text)

	var found []string

	for _, key := range fixtureKeys {
		raw := mustKey(key)

		spellings := map[string]string{
			"key in base64":    base64.RawStdEncoding.EncodeToString(raw[:]),
			"key in base64url": base64.RawURLEncoding.EncodeToString(raw[:]),
		}

		for mode, valueHex := range map[string]string{"ee": ee(key), "dd": dd(key), "plain": key} {
			spellings[mode+" value in base64url"] = b64(valueHex)

			value, _ := hex.DecodeString(valueHex)
			spellings[mode+" value in base64"] = base64.RawStdEncoding.EncodeToString(value)
		}

		for label, spelling := range spellings {
			if strings.Contains(text, spelling) {
				found = append(found, fmt.Sprintf("key %s…: %s", key[:4], label))
			}
		}

		// The key in hex is inside every hex value, so it covers them all.
		if strings.Contains(lower, key) {
			found = append(found, fmt.Sprintf("key %s…: in hex", key[:4]))
		}
	}

	return found
}

// R1: rotation over a corpus of layouts. Each case's output is its golden file
// byte for byte, under a fixed new key and instant; Apply returning it means
// the re-parse diff passed, and the result is parsed here once more, on its
// own.
func TestRotateTheCorpus(t *testing.T) {
	t.Parallel()

	rotate := func(name string) Request {
		return Request{Name: name, Rotate: true, Until: testUntil, Now: testNow}
	}

	rotatePrune := func(name string) Request {
		req := rotate(name)
		req.Prune = true

		return req
	}

	for _, tc := range []struct {
		name string
		req  Request
		crlf string // built from this LF case, input and golden alike
	}{
		{name: "example", req: rotate("alice")},
		{name: "panel-quoted-keys", req: rotate("alice")},
		{name: "dotted-secrets", req: rotate("bob")},
		{name: "inline-secrets", req: rotate("bob smith")},
		{name: "single-secret", req: rotate("default")},
		{name: "crlf", req: rotatePrune("alice"), crlf: "existing-blocks"},
		{name: "no-final-newline", req: rotatePrune("default")},
		{name: "comments-above-secrets", req: rotate("alice")},
		{name: "existing-blocks", req: rotatePrune("alice")},
		{name: "single-table-typo-block", req: rotatePrune("alice")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var doc, golden []byte

			if tc.crlf != "" {
				doc = toCRLF(fixture(t, tc.crlf+".toml"))
				golden = toCRLF(fixture(t, tc.crlf+".golden"))
			} else {
				doc = fixture(t, tc.name+".toml")
				golden = fixture(t, tc.name+".golden")
			}

			before := bytes.Clone(doc)

			prepared, err := Prepare(doc, tc.req)
			require.NoError(t, err)

			old := prepared.Primary()
			newPrimary := newPrimaryLike(old)

			out, err := prepared.Apply(newPrimary)
			require.NoError(t, err, "the re-parse verification passes")
			assert.True(t, bytes.Equal(before, doc), "the input is never written to")

			assertSameBytes(t, golden, out, tc.name)

			conf, err := config.Parse(out)
			require.NoError(t, err)
			require.NoError(t, conf.Validate())

			assert.True(t, conf.GetSecrets()[tc.req.Name] == newPrimary, "the name's primary is the new key")

			report := conf.GetRetiringSecrets(testNow)
			assert.Empty(t, report.Lines, "the edit adds no problem")

			held := 0

			for _, entry := range report.Usable {
				if entry.Secret.Key == old.Key {
					held++

					assert.Equal(t, tc.req.Name, entry.Name)
					assert.True(t, entry.Until.Equal(testUntil), "the previous key is accepted until the until asked")
				}
			}

			assert.Equal(t, 1, held, "one entry holds the previous key")
		})
	}
}

// spliceDoc is a small file the seam tests corrupt.
func spliceDoc() []byte {
	return lines(
		`bind-to = "0.0.0.0:3128"`,
		`concurrency = 64`,
		``,
		`[[retiring-secret]]`,
		`name   = "bob"`,
		`secret = `+quoted(ee(keyOld1)),
		`until  = "2026-10-09T12:00:00Z"`,
		``,
		`[secrets]`,
		`alice = `+quoted(ee(keyAlice)),
		`bob = `+quoted(ee(keyBob)),
	)
}

// insertedBlock is where the new block sits in an edited document: from its
// header to the blank line after it.
func insertedBlock(t *testing.T, out []byte) (int, int) {
	t.Helper()

	start := bytes.Index(out, []byte("[[retiring-secret]]\n# added by"))
	require.GreaterOrEqual(t, start, 0)

	end := bytes.Index(out[start:], []byte("\n\n"))
	require.GreaterOrEqual(t, end, 0)

	return start, start + end + 2
}

// R2: the verification catches an edit that changed more than it meant to,
// whichever field the damage reaches, and nothing is returned. Not parallel:
// it sets spliceHook.
func TestABadSpliceIsCaught(t *testing.T) {
	req := Request{Name: "alice", Rotate: true, Until: testUntil, Now: testNow}
	newPrimary := mtglib.Secret{Key: mustKey(keyNew), Host: "storage.googleapis.com"}

	t.Run("without a hook the edit passes", func(t *testing.T) {
		prepared, err := Prepare(spliceDoc(), req)
		require.NoError(t, err)

		_, err = prepared.Apply(newPrimary)
		require.NoError(t, err)
	})

	for _, tc := range []struct {
		name string
		hook func(t *testing.T, out []byte) []byte
	}{
		{
			name: "the new value is corrupted",
			hook: func(_ *testing.T, out []byte) []byte {
				return bytes.Replace(out, []byte("c0ffee00c0ffee00c0ffee00c0ffee00"), []byte("c0ffee00c0ffee00c0ffee00c0ffee01"), 1)
			},
		},
		{
			name: "the block lands inside [secrets]",
			hook: func(t *testing.T, out []byte) []byte {
				start, end := insertedBlock(t, out)
				block := bytes.Clone(out[start:end])
				rest := append(bytes.Clone(out[:start]), out[end:]...)
				at := bytes.Index(rest, []byte("bob = "))
				require.GreaterOrEqual(t, at, 0)

				return append(append(bytes.Clone(rest[:at]), block...), rest[at:]...)
			},
		},
		{
			name: "a field outside [secrets] changes",
			hook: func(_ *testing.T, out []byte) []byte {
				return bytes.Replace(out, []byte("concurrency = 64"), []byte("concurrency = 65"), 1)
			},
		},
		{
			name: "an unknown key appears and nothing else",
			hook: func(_ *testing.T, out []byte) []byte {
				return append([]byte("stray-key = 1\n"), out...)
			},
		},
		{
			name: "the new block is dropped",
			hook: func(t *testing.T, out []byte) []byte {
				start, end := insertedBlock(t, out)

				return append(bytes.Clone(out[:start]), out[end:]...)
			},
		},
		{
			name: "the new block's until moves",
			hook: func(_ *testing.T, out []byte) []byte {
				return bytes.Replace(out, []byte(`until  = "2026-10-09T09:30:00Z"`), []byte(`until  = "2026-10-09T09:30:01Z"`), 1)
			},
		},
		{
			name: "a block meant to stay loses its name",
			hook: func(_ *testing.T, out []byte) []byte {
				return bytes.Replace(out, []byte(`name   = "bob"`+"\n"), nil, 1)
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			doc := spliceDoc()
			before := bytes.Clone(doc)

			prepared, err := Prepare(doc, req)
			require.NoError(t, err)

			spliceHook = func(out []byte) []byte { return tc.hook(t, out) }
			t.Cleanup(func() { spliceHook = func(b []byte) []byte { return b } })

			out, err := prepared.Apply(newPrimary)
			require.ErrorIs(t, err, ErrEditVerification)
			assert.Equal(t, "internal error: the edit changed more than it meant to; nothing was written", err.Error())
			assert.Nil(t, out, "nothing is returned to write")
			assert.True(t, bytes.Equal(before, doc), "the input is never written to")
		})
	}

	// Unknown keys may not go either: not one the file had at the top level,
	// and, while another block is pruned, not a misspelt field of a block
	// that stays.
	for _, tc := range []struct {
		name, gone string
		doc        []byte
		req        Request
	}{
		{
			name: "an unknown key the file had disappears",
			gone: "stray-key = 1\n",
			doc:  append([]byte("stray-key = 1\n"), spliceDoc()...),
			req:  req,
		},
		{
			name: "a kept block's unknown field disappears while another is pruned",
			gone: "note   = \"for his phone\"\n",
			doc: refusalDoc(
				blockOf("alice", ee(keyOld1), at(-time.Hour)),
				strings.Replace(blockOf("bob", ee(keyOld2), at(time.Hour)), "until", "note   = \"for his phone\"\nuntil", 1),
			),
			req: Request{Name: "alice", Rotate: true, Until: testUntil, Prune: true, Now: testNow},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			prepared, err := Prepare(tc.doc, tc.req)
			require.NoError(t, err)

			_, err = prepared.Apply(newPrimary)
			require.NoError(t, err, "without the hook the edit passes")

			spliceHook = func(out []byte) []byte { return bytes.Replace(out, []byte(tc.gone), nil, 1) }
			t.Cleanup(func() { spliceHook = func(b []byte) []byte { return b } })

			out, err := prepared.Apply(newPrimary)
			require.ErrorIs(t, err, ErrEditVerification)
			assert.Nil(t, out)
		})
	}

	// No seam: a new key that is another name's retiring key gives that
	// entry a problem the file did not have, which only the re-parse can see.
	t.Run("a new key that another name's block holds", func(t *testing.T) {
		prepared, err := Prepare(spliceDoc(), req)
		require.NoError(t, err)

		out, err := prepared.Apply(mtglib.Secret{Key: mustKey(keyOld1), Host: "storage.googleapis.com"})
		require.ErrorIs(t, err, ErrEditVerification)
		assert.Nil(t, out)
	})
}

// R3: removing a block keeps the comment that heads the next table, and takes
// a comment written inside the block with it.
func TestRemovalKeepsTheNextTablesHeadingComment(t *testing.T) {
	t.Parallel()

	users := []string{
		`[secrets]`,
		`alice = ` + quoted(ee(keyAlice)),
		`bob = ` + quoted(ee(keyBob)),
	}

	for _, tc := range []struct {
		name      string
		doc, want []byte
		req       Request
	}{
		{
			name: "end-overlap, the users' heading kept",
			doc: lines(append([]string{
				`bind-to = "0.0.0.0:3128"`,
				``,
				`[[retiring-secret]]`,
				`# added by mtg-proxy rotate-secret at 2026-10-07T09:30:00Z`,
				`name   = "alice"`,
				`# a note someone wrote inside the block`,
				`secret = ` + quoted(ee(keyOld1)),
				`until  = "2026-10-09T09:30:00Z"`,
				``,
				`# The users. Keep this table last.`,
			}, users...)...),
			want: lines(append([]string{
				`bind-to = "0.0.0.0:3128"`,
				``,
				`# The users. Keep this table last.`,
			}, users...)...),
			req: Request{Name: "alice", EndOverlap: true, Now: testNow},
		},
		{
			name: "prune, the next block's heading kept",
			doc: lines(append([]string{
				`bind-to = "0.0.0.0:3128"`,
				``,
				`[[retiring-secret]]`,
				`# added by mtg-proxy rotate-secret at 2026-10-01T09:30:00Z`,
				`name   = "alice"`,
				`secret = ` + quoted(ee(keyOld1)),
				`# expired; a note inside the block`,
				`until  = "2026-10-07T09:30:00Z"`,
				``,
				`# bob's previous link, for his phone.`,
				`[[retiring-secret]]`,
				`name   = "bob"`,
				`secret = ` + quoted(ee(keyOld2)),
				`until  = "2026-10-09T09:30:00Z"`,
				``,
			}, users...)...),
			want: lines(append([]string{
				`bind-to = "0.0.0.0:3128"`,
				``,
				`# bob's previous link, for his phone.`,
				`[[retiring-secret]]`,
				`name   = "bob"`,
				`secret = ` + quoted(ee(keyOld2)),
				`until  = "2026-10-09T09:30:00Z"`,
				``,
			}, users...)...),
			req: Request{Prune: true, Now: testNow},
		},
		{
			name: "end-overlap of a single-table block",
			doc: lines(append([]string{
				`bind-to = "0.0.0.0:3128"`,
				``,
				`[retiring-secret]`,
				`# bob's previous key, with one pair of brackets`,
				`name = "bob"`,
				`secret = ` + quoted(ee(keyOld1)),
				`until = "2026-10-09T09:30:00Z"`,
				``,
				`# The users.`,
			}, users...)...),
			want: lines(append([]string{
				`bind-to = "0.0.0.0:3128"`,
				``,
				`# The users.`,
			}, users...)...),
			req: Request{Name: "bob", EndOverlap: true, Now: testNow},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			prepared, err := Prepare(tc.doc, tc.req)
			require.NoError(t, err)

			out, err := prepared.Apply(mtglib.Secret{})
			require.NoError(t, err)

			assertSameBytes(t, tc.want, out, tc.name)
		})
	}
}

// The new value is written in the old text's encoding (hex when it decodes as
// hex, base64url otherwise) and between the old text's quotes; the block's
// secret is the old text as it was.
func TestTheNewValueKeepsTheOldEncodingAndQuoteStyle(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name  string
		token string
		hex   bool
		quote string
	}{
		{"ee, hex, basic", quoted(ee(keyAlice)), true, `"`},
		{"ee, hex, literal", `'` + ee(keyAlice) + `'`, true, `'`},
		{"ee, base64url, basic", quoted(b64(ee(keyAlice))), false, `"`},
		{"ee, base64url, literal", `'` + b64(ee(keyAlice)) + `'`, false, `'`},
		{"ee, upper-case hex", quoted(strings.ToUpper(ee(keyAlice))), true, `"`},
		{"dd, hex", quoted(dd(keyAlice)), true, `"`},
		{"dd, base64url, literal", `'` + b64(dd(keyAlice)) + `'`, false, `'`},
		{"plain, hex", quoted(keyAlice), true, `"`},
		{"plain, base64url", quoted(b64(keyAlice)), false, `"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			doc := lines(
				`bind-to = "0.0.0.0:3128"`,
				``,
				`[secrets]`,
				`alice = `+tc.token,
				`zed = `+quoted(ee(keyBob)),
			)

			prepared, err := Prepare(doc, Request{Name: "alice", Rotate: true, Until: testUntil, Now: testNow})
			require.NoError(t, err)

			newPrimary := newPrimaryLike(prepared.Primary())

			spelled := newPrimary.Base64()
			if tc.hex {
				spelled = newPrimary.Hex()
			}

			assert.Equal(t, spelled, prepared.ValueText(newPrimary), "ValueText is what the file gets")

			out, err := prepared.Apply(newPrimary)
			require.NoError(t, err)

			assert.True(t, bytes.Contains(out, []byte("\nalice = "+tc.quote+spelled+tc.quote+"\n")),
				"the new value, in the old encoding and quotes")
			assert.True(t, bytes.Contains(out, []byte("\nsecret = "+tc.token+"\n")),
				"the block's secret is the old text as written")
		})
	}
}

// refusalDoc is a file with two users and no block.
func refusalDoc(extra ...string) []byte {
	return lines(append([]string{
		`bind-to = "0.0.0.0:3128"`,
		``,
	}, append(extra,
		`[secrets]`,
		`alice = `+quoted(ee(keyAlice)),
		`bob = `+quoted(ee(keyBob)),
	)...)...)
}

// blockOf is one [[retiring-secret]] block.
func blockOf(name, value, until string) string {
	return "[[retiring-secret]]\nname   = " + quoted(name) + "\nsecret = " + quoted(value) + "\nuntil  = " + quoted(until) + "\n"
}

// The pure half of R9, and every other refusal of step 1: none of them
// carries a value.
func TestPrepareRefuses(t *testing.T) {
	t.Parallel()

	rotate := Request{Name: "alice", Rotate: true, Until: testUntil, Now: testNow}

	with := func(change func(*Request)) Request {
		req := rotate
		change(&req)

		return req
	}

	four := []string{
		blockOf("alice", ee(keyOld1), at(time.Hour)),
		blockOf("alice", ee(keyOld2), at(2*time.Hour)),
		blockOf("alice", ee(keyOld3), at(3*time.Hour)),
		blockOf("alice", ee(keyOld4), at(4*time.Hour)),
	}

	for _, tc := range []struct {
		name string
		doc  []byte
		req  Request
		want string
	}{
		{
			name: "a UTF-8 byte-order mark",
			doc:  append([]byte("\xef\xbb\xbf"), refusalDoc()...),
			req:  rotate,
			want: "the config does not load: ",
		},
		{
			name: "the scalar shape",
			doc:  lines(`bind-to = "0.0.0.0:3128"`, `retiring-secret = `+quoted(ee(keyOld1)), ``, `[secrets]`, `alice = `+quoted(ee(keyAlice))),
			req:  rotate,
			want: "the config does not load: ",
		},
		{
			name: "a file Validate refuses",
			doc:  lines(`bind-to = ["0.0.0.0:3128", "0.0.0.0:3128"]`, ``, `[secrets]`, `alice = `+quoted(ee(keyAlice))),
			req:  rotate,
			want: "the config is not valid: duplicate bind-to address",
		},
		{
			name: "an unknown name",
			doc:  refusalDoc(),
			req:  with(func(r *Request) { r.Name = "carol" }),
			want: `there is no secret named "carol"`,
		},
		{
			name: "a value given as the name",
			doc:  refusalDoc(),
			req:  with(func(r *Request) { r.Name = ee(keyAlice) }),
			want: "there is no secret by that name (it is not shown: it reads as a secret value)",
		},
		{
			name: "an unknown name for --end-overlap",
			doc:  refusalDoc(),
			req:  Request{Name: "carol", EndOverlap: true, Now: testNow},
			want: `there is no secret named "carol"`,
		},
		{
			name: `"default" while [secrets] is present`,
			doc:  refusalDoc(),
			req:  with(func(r *Request) { r.Name = "default" }),
			want: `"default" is not served while [secrets] is present; rotate a name from [secrets]`,
		},
		{
			name: "a multi-line basic string",
			doc:  lines(`bind-to = "0.0.0.0:3128"`, ``, `[secrets]`, `alice = """`+ee(keyAlice)+`"""`),
			req:  rotate,
			want: `the value of "alice" is a multi-line string`,
		},
		{
			name: "a multi-line literal string",
			doc:  lines(`bind-to = "0.0.0.0:3128"`, ``, `[secrets]`, `alice = '''`+ee(keyAlice)+`'''`),
			req:  rotate,
			want: `the value of "alice" is a multi-line string`,
		},
		{
			name: "a fifth unexpired entry",
			doc:  refusalDoc(four...),
			req:  rotate,
			want: `"alice" already has 4 unexpired previous keys`,
		},
		{
			name: "a single-table block kept beside a new one",
			doc:  refusalDoc(strings.Replace(blockOf("bob", ee(keyOld1), at(time.Hour)), "[[retiring-secret]]", "[retiring-secret]", 1)),
			req:  rotate,
			want: "[retiring-secret] table with one pair of brackets",
		},
		{
			name: "an inline array of blocks",
			doc: refusalDoc(`retiring-secret = [{ name = "bob", secret = `+quoted(ee(keyOld1))+`, until = "2026-10-09T09:30:00Z" }]`,
				``),
			req:  rotate,
			want: "not all [[retiring-secret]] blocks",
		},
		{
			name: "an until that is not after now",
			doc:  refusalDoc(),
			req:  with(func(r *Request) { r.Until = testNow }),
			want: "until 2026-10-08T09:30:00Z is not after now",
		},
		{
			name: "an until more than 720h away",
			doc:  refusalDoc(),
			req:  with(func(r *Request) { r.Until = testNow.Add(721 * time.Hour) }),
			want: "is more than 720h after now",
		},
		{
			name: "a block of the name holding its key for longer",
			doc:  refusalDoc(blockOf("alice", ee(keyAlice), at(48*time.Hour))),
			req:  rotate,
			want: `the current key of "alice" would still be accepted until 2026-10-10T09:30:00Z: a [[retiring-secret]] block of "alice" holds it`,
		},
		{
			name: "the same, with an overlap of 0",
			doc:  refusalDoc(blockOf("alice", ee(keyAlice), at(48*time.Hour))),
			req:  with(func(r *Request) { r.Until = time.Time{} }),
			want: `the current key of "alice" would still be accepted until 2026-10-10T09:30:00Z: a [[retiring-secret]] block of "alice" holds it`,
		},
		{
			name: "another name's block holding the key, with an overlap of 0",
			doc:  refusalDoc(blockOf("bob", ee(keyAlice), at(48*time.Hour))),
			req:  with(func(r *Request) { r.Until = time.Time{} }),
			want: `the current key of "alice" would still be accepted until 2026-10-10T09:30:00Z: a [[retiring-secret]] block of "bob" holds it`,
		},
		{
			name: "another name's block that the new one would collide with",
			doc:  refusalDoc(blockOf("bob", ee(keyAlice), at(48*time.Hour))),
			req:  rotate,
			want: "retiring-secret #2 (name \"alice\"): the key is also the key of a retiring-secret entry of another name",
		},
		{
			name: "rotate and end-overlap at once",
			doc:  refusalDoc(),
			req:  with(func(r *Request) { r.EndOverlap = true }),
			want: "a rotation and --end-overlap cannot be asked at once",
		},
		{
			name: "nothing asked",
			doc:  refusalDoc(),
			req:  Request{Name: "alice", Now: testNow},
			want: "nothing to do",
		},
		{
			name: "a rotation without a name",
			doc:  refusalDoc(),
			req:  with(func(r *Request) { r.Name = "" }),
			want: "a rotation or --end-overlap needs a name",
		},
		{
			name: "an until without a rotation",
			doc:  refusalDoc(),
			req:  Request{Prune: true, Until: testUntil, Now: testNow},
			want: "an until is given without a rotation",
		},
		{
			name: "a name with --prune alone",
			doc:  refusalDoc(),
			req:  Request{Name: "alice", Prune: true, Now: testNow},
			want: "--prune alone takes no name",
		},
		{
			name: "no instant",
			doc:  refusalDoc(),
			req:  with(func(r *Request) { r.Now = time.Time{} }),
			want: "the run's instant is not set",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			prepared, err := Prepare(tc.doc, tc.req)
			require.Error(t, err)
			assert.Nil(t, prepared)

			// The text is printed by a failing assertion only once it is
			// known to carry no value.
			if !assert.Empty(t, leaks(err.Error()), "the refusal carries no value") {
				return
			}

			assert.Contains(t, err.Error(), tc.want)
		})
	}

	// What the refusals above must not catch.
	for _, tc := range []struct {
		name string
		doc  []byte
		req  Request
		noOp bool
	}{
		{name: "an overlap of 0 beside four entries", doc: refusalDoc(four...), req: with(func(r *Request) { r.Until = time.Time{} })},
		{name: "a single-table block with an overlap of 0", doc: refusalDoc(strings.Replace(blockOf("bob", ee(keyOld1), at(time.Hour)), "[[retiring-secret]]", "[retiring-secret]", 1)), req: with(func(r *Request) { r.Until = time.Time{} })},
		{name: "--prune with nothing to prune", doc: refusalDoc(), req: Request{Prune: true, Now: testNow}, noOp: true},
		{name: "--end-overlap for a name without blocks", doc: refusalDoc(), req: Request{Name: "bob", EndOverlap: true, Now: testNow}, noOp: true},
	} {
		t.Run("not refused: "+tc.name, func(t *testing.T) {
			t.Parallel()

			prepared, err := Prepare(tc.doc, tc.req)
			require.NoError(t, err)
			assert.Equal(t, tc.noOp, prepared.Summary().NoOp)

			out, err := prepared.Apply(newPrimaryLike(prepared.Primary()))
			require.NoError(t, err)

			if tc.noOp {
				assert.True(t, bytes.Equal(tc.doc, out), "a no-op changes no byte")
			}
		})
	}
}

// §7.3 step 1: problems the file already has are reported, value-free, and do
// not block an urgent rotation; only the problems the edit would add refuse.
func TestExistingProblemsDoNotBlockARotation(t *testing.T) {
	t.Parallel()

	t.Run("a rotation beside three problem blocks", func(t *testing.T) {
		t.Parallel()

		problems := []string{
			blockOf("carol", ee(keyOld1), at(time.Hour)),
			blockOf("bob", ee(keyOld2), "tomorrow"),
			blockOf("bob", ee(keyOld3), at(800*time.Hour)),
		}
		doc := refusalDoc(problems...)

		prepared, err := Prepare(doc, Request{Name: "alice", Rotate: true, Until: testUntil, Now: testNow})
		require.NoError(t, err)

		warnings := prepared.Warnings()
		require.Empty(t, leaks(strings.Join(warnings, "\n")), "the warnings carry no value")
		require.Len(t, warnings, 3)
		assert.Contains(t, warnings[0], `retiring-secret #1 (name "carol"): name is not a configured secret`)
		assert.Contains(t, warnings[1], `retiring-secret #2 (name "bob"): until is not an RFC 3339 date-time`)
		assert.Contains(t, warnings[2], `retiring-secret #3 (name "bob"): until is more than 720h away`)

		out, err := prepared.Apply(newPrimaryLike(prepared.Primary()))
		require.NoError(t, err)

		for i, problem := range problems {
			assert.True(t, bytes.Contains(out, []byte(problem)), "problem block %d is left as it was", i+1)
		}
	})

	t.Run("a prune above a problem block renumbers it", func(t *testing.T) {
		t.Parallel()

		doc := refusalDoc(
			blockOf("alice", ee(keyOld1), at(-time.Hour)),
			blockOf("carol", ee(keyOld2), at(time.Hour)),
		)

		prepared, err := Prepare(doc, Request{Name: "alice", Rotate: true, Until: testUntil, Prune: true, Now: testNow})
		require.NoError(t, err)
		require.Empty(t, leaks(strings.Join(prepared.Warnings(), "\n")), "the warnings carry no value")
		require.Len(t, prepared.Warnings(), 1)
		assert.Contains(t, prepared.Warnings()[0], `retiring-secret #2 (name "carol")`)

		out, err := prepared.Apply(newPrimaryLike(prepared.Primary()))
		require.NoError(t, err, "the problem is now #1, and it is still not a new one")

		assert.False(t, bytes.Contains(out, []byte(ee(keyOld1))), "the expired block is gone")
		assert.True(t, bytes.Contains(out, []byte(blockOf("carol", ee(keyOld2), at(time.Hour)))), "the problem block stays")
	})

	t.Run("a pruned block's unknown field goes with it", func(t *testing.T) {
		t.Parallel()

		doc := refusalDoc(strings.Replace(blockOf("alice", ee(keyOld1), at(-time.Hour)), "until", "untill = \"a typo\"\nuntil", 1))

		before, err := config.Parse(doc)
		require.NoError(t, err)
		require.Equal(t, []string{"retiring-secret.untill"}, before.UnknownKeys)

		prepared, err := Prepare(doc, Request{Name: "alice", Rotate: true, Until: testUntil, Prune: true, Now: testNow})
		require.NoError(t, err)

		out, err := prepared.Apply(newPrimaryLike(prepared.Primary()))
		require.NoError(t, err, "the unknown key the pruned block carried may go")
		assert.False(t, bytes.Contains(out, []byte("untill")), "the misspelt field is gone with its block")
	})
}

// A line that only looks like a comment -- the last line of a multi-line
// string -- is not one: the locator takes comment lines from the parser, so
// the new block does not go inside the string, and a removal does not leave
// the string's last line behind.
func TestALineThatOnlyLooksLikeACommentIsNotOne(t *testing.T) {
	t.Parallel()

	users := []string{`[secrets]`, `alice = ` + quoted(ee(keyAlice))}

	for _, tc := range []struct {
		name      string
		doc, want []byte
		req       Request
	}{
		{
			name: "above [secrets]",
			doc: lines(append([]string{
				`bind-to = "0.0.0.0:3128"`,
				`motd = """`,
				`Welcome.`,
				`# not a comment: the last line of a string"""`,
			}, users...)...),
			want: lines(
				`bind-to = "0.0.0.0:3128"`,
				`motd = """`,
				`Welcome.`,
				`# not a comment: the last line of a string"""`,
				`[[retiring-secret]]`,
				`# added by mtg-proxy rotate-secret at 2026-10-08T09:30:00Z`,
				`name   = "alice"`,
				`secret = `+quoted(ee(keyAlice)),
				`until  = "2026-10-09T09:30:00Z"`,
				``,
				`[secrets]`,
				`alice = `+quoted(ee(keyNew)),
			),
			req: Request{Name: "alice", Rotate: true, Until: testUntil, Now: testNow},
		},
		{
			name: "at the end of a removed block",
			doc: lines(append([]string{
				`bind-to = "0.0.0.0:3128"`,
				``,
				`[[retiring-secret]]`,
				`name   = "alice"`,
				`secret = ` + quoted(ee(keyOld1)),
				`until  = "2026-10-07T09:30:00Z"`,
				`note   = """`,
				`for her phone`,
				`# not a comment either"""`,
				``,
			}, users...)...),
			want: lines(append([]string{
				`bind-to = "0.0.0.0:3128"`,
				``,
			}, users...)...),
			req: Request{Prune: true, Now: testNow},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			prepared, err := Prepare(tc.doc, tc.req)
			require.NoError(t, err)

			out, err := prepared.Apply(newPrimaryLike(prepared.Primary()))
			require.NoError(t, err)

			assertSameBytes(t, tc.want, out, tc.name)
		})
	}
}

// The locator finds a header from its first key node, whatever the
// indentation, the spacing inside the brackets and the quoting of the name.
func TestHeadersAreFoundWhateverTheirSpelling(t *testing.T) {
	t.Parallel()

	doc := lines(
		`bind-to = "0.0.0.0:3128"`,
		``,
		`  [[ "retiring-secret" ]]`,
		`  name   = "alice"`,
		`  secret = `+quoted(ee(keyOld1)),
		`  until  = "2026-10-07T09:30:00Z"`,
		``,
		"\t# the users, indented",
		"\t[ 'secrets' ]  # a comment after the header",
		"\talice = "+quoted(ee(keyAlice)),
	)
	want := lines(
		`bind-to = "0.0.0.0:3128"`,
		``,
		`[[retiring-secret]]`,
		`# added by mtg-proxy rotate-secret at 2026-10-08T09:30:00Z`,
		`name   = "alice"`,
		`secret = `+quoted(ee(keyAlice)),
		`until  = "2026-10-09T09:30:00Z"`,
		``,
		"\t# the users, indented",
		"\t[ 'secrets' ]  # a comment after the header",
		"\talice = "+quoted(ee(keyNew)),
	)

	prepared, err := Prepare(doc, Request{Name: "alice", Rotate: true, Until: testUntil, Prune: true, Now: testNow})
	require.NoError(t, err)

	out, err := prepared.Apply(newPrimaryLike(prepared.Primary()))
	require.NoError(t, err)

	assertSameBytes(t, want, out, "headers spelled otherwise")
}

// With Rotate false (--end-overlap, or --prune alone) Apply ignores the key it
// is handed and splices no value, and a splice that changes the primary all
// the same is caught. Not parallel: it sets spliceHook.
func TestEndOverlapAndPruneLeaveThePrimaryAlone(t *testing.T) {
	doc := refusalDoc(
		blockOf("alice", ee(keyOld1), at(time.Hour)),
		blockOf("alice", ee(keyOld2), at(-time.Hour)),
	)
	users := doc[bytes.Index(doc, []byte("[secrets]")):]

	for _, tc := range []struct {
		name    string
		req     Request
		removed int
	}{
		{"--end-overlap", Request{Name: "alice", EndOverlap: true, Now: testNow}, 2},
		{"--prune alone", Request{Prune: true, Now: testNow}, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			prepared, err := Prepare(doc, tc.req)
			require.NoError(t, err)
			require.Equal(t, tc.removed, len(prepared.Summary().Removed), "blocks removed")

			// A real, different key: a verification that required it as the
			// primary would refuse this edit.
			out, err := prepared.Apply(mtglib.Secret{Key: mustKey(keyNew), Host: "storage.googleapis.com"})
			require.NoError(t, err)
			assert.True(t, bytes.HasSuffix(out, users), "[secrets] is byte for byte as it was")
			assert.False(t, bytes.Contains(out, []byte(keyNew)), "the key handed to Apply is written nowhere")

			spliceHook = func(out []byte) []byte {
				return bytes.Replace(out, []byte(ee(keyAlice)), []byte(ee(keyNew)), 1)
			}
			t.Cleanup(func() { spliceHook = func(b []byte) []byte { return b } })

			out, err = prepared.Apply(mtglib.Secret{Key: mustKey(keyNew), Host: "storage.googleapis.com"})
			require.ErrorIs(t, err, ErrEditVerification, "a primary changed by the splice is caught")
			assert.Nil(t, out)
		})
	}
}

// The pure half of R8: the summary is there before any key is generated, and
// no summary, warning or refusal holds a value -- not even a value pasted
// into a removed block's name or until.
func TestTheSummaryCarriesNoValue(t *testing.T) {
	t.Parallel()

	doc := refusalDoc(
		blockOf("alice", ee(keyOld1), at(-24*time.Hour)),
		blockOf(ee(keyOld2), ee(keyOld3), at(-48*time.Hour)),
		blockOf("bob", ee(keyOld4), ee(keyOld5)),
		blockOf("bob", dd(keyOld6), at(12*time.Hour)),
	)

	for _, tc := range []struct {
		name    string
		req     Request
		until   time.Time
		removed []Removed
	}{
		{
			name:  "a rotation that prunes",
			req:   Request{Name: "alice", Rotate: true, Until: testUntil, Prune: true, Now: testNow},
			until: testUntil,
			removed: []Removed{
				{Name: "alice", Until: at(-24 * time.Hour)},
				{Name: "", Until: at(-48 * time.Hour)},
			},
		},
		{
			name: "--end-overlap and --prune",
			req:  Request{Name: "bob", EndOverlap: true, Prune: true, Now: testNow},
			removed: []Removed{
				{Name: "alice", Until: at(-24 * time.Hour)},
				{Name: "", Until: at(-48 * time.Hour)},
				{Name: "bob", Until: ""},
				{Name: "bob", Until: at(12 * time.Hour)},
			},
		},
		{
			name:  "an overlap of 0",
			req:   Request{Name: "alice", Rotate: true, Now: testNow},
			until: time.Time{},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			prepared, err := Prepare(doc, tc.req)
			require.NoError(t, err)

			// The leak checks come first: the assertions after them print
			// what they compare when they fail.
			summary := prepared.Summary()
			require.Empty(t, leaks(fmt.Sprintf("%#v", summary)), "the summary carries no value")
			require.Empty(t, leaks(strings.Join(prepared.Warnings(), "\n")), "the warnings carry no value")

			assert.Equal(t, tc.req.Name, summary.Name)
			assert.True(t, summary.Until.Equal(tc.until), "the summary's until is the one written")
			assert.Equal(t, tc.removed, summary.Removed)
			assert.False(t, summary.NoOp)
		})
	}
}

// Line endings follow the file on the paths the corpus does not cover: CRLF
// at the end of the file, and a file without a final newline that has a
// [secrets] header.
func TestLineEndingsFollowTheFile(t *testing.T) {
	t.Parallel()

	newHex := ee(keyNew)
	newBlock := []string{
		`[[retiring-secret]]`,
		`# added by mtg-proxy rotate-secret at 2026-10-08T09:30:00Z`,
		`name   = "default"`,
		`secret = ` + quoted(ee(keyAlice)),
		`until  = "2026-10-09T09:30:00Z"`,
	}

	for _, tc := range []struct {
		name      string
		doc, want string
		req       Request
	}{
		{
			name: "CRLF, appended at the end",
			doc:  "bind-to = \"0.0.0.0:3128\"\r\nsecret = " + quoted(ee(keyAlice)) + "\r\n",
			want: "bind-to = \"0.0.0.0:3128\"\r\nsecret = " + quoted(newHex) + "\r\n\r\n" + strings.Join(newBlock, "\r\n") + "\r\n",
			req:  Request{Name: "default", Rotate: true, Until: testUntil, Now: testNow},
		},
		{
			name: "CRLF and no final newline, appended at the end",
			doc:  "bind-to = \"0.0.0.0:3128\"\r\nsecret = " + quoted(ee(keyAlice)),
			want: "bind-to = \"0.0.0.0:3128\"\r\nsecret = " + quoted(newHex) + "\r\n\r\n" + strings.Join(newBlock, "\r\n"),
			req:  Request{Name: "default", Rotate: true, Until: testUntil, Now: testNow},
		},
		{
			name: "no final newline, before [secrets]",
			doc:  "bind-to = \"0.0.0.0:3128\"\n\n[secrets]\nalice = " + quoted(ee(keyAlice)),
			want: "bind-to = \"0.0.0.0:3128\"\n\n" +
				strings.Replace(strings.Join(newBlock, "\n"), `"default"`, `"alice"`, 1) +
				"\n\n[secrets]\nalice = " + quoted(newHex),
			req: Request{Name: "alice", Rotate: true, Until: testUntil, Now: testNow},
		},
		{
			name: "no final newline, the last block pruned",
			doc: "bind-to = \"0.0.0.0:3128\"\nsecret = " + quoted(ee(keyAlice)) + "\n\n" +
				strings.TrimSuffix(blockOf("default", ee(keyOld1), at(-time.Hour)), "\n"),
			want: "bind-to = \"0.0.0.0:3128\"\nsecret = " + quoted(ee(keyAlice)),
			req:  Request{Prune: true, Now: testNow},
		},
		{
			name: "CRLF and no final newline, the last block pruned",
			doc: "bind-to = \"0.0.0.0:3128\"\r\nsecret = " + quoted(ee(keyAlice)) + "\r\n\r\n" +
				strings.TrimSuffix(string(toCRLF([]byte(blockOf("default", ee(keyOld1), at(-time.Hour))))), "\r\n"),
			want: "bind-to = \"0.0.0.0:3128\"\r\nsecret = " + quoted(ee(keyAlice)),
			req:  Request{Prune: true, Now: testNow},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			prepared, err := Prepare([]byte(tc.doc), tc.req)
			require.NoError(t, err)

			out, err := prepared.Apply(newPrimaryLike(prepared.Primary()))
			require.NoError(t, err)

			assertSameBytes(t, []byte(tc.want), out, tc.name)
		})
	}
}

// --end-overlap right after a rotation gives back the file as it was, but for
// the new value: the block's blank line goes with it, before [secrets] and at
// the end of the file alike.
func TestEndingTheOverlapUndoesTheBlock(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		fixture, name string
	}{
		{"comments-above-secrets", "alice"},
		{"single-secret", "default"},
		{"no-final-newline", "default"},
	} {
		t.Run(tc.fixture, func(t *testing.T) {
			t.Parallel()

			doc := fixture(t, tc.fixture+".toml")

			prepared, err := Prepare(doc, Request{Name: tc.name, Rotate: true, Until: testUntil, Now: testNow})
			require.NoError(t, err)

			old := prepared.Primary()
			newPrimary := newPrimaryLike(old)

			rotated, err := prepared.Apply(newPrimary)
			require.NoError(t, err)

			prepared, err = Prepare(rotated, Request{Name: tc.name, EndOverlap: true, Now: testNow})
			require.NoError(t, err)

			ended, err := prepared.Apply(mtglib.Secret{})
			require.NoError(t, err)

			// Every block of the name goes, the earlier ones of the fixture
			// too, so compare with the fixture's own --end-overlap.
			prepared, err = Prepare(doc, Request{Name: tc.name, EndOverlap: true, Now: testNow})
			require.NoError(t, err)

			want, err := prepared.Apply(mtglib.Secret{})
			require.NoError(t, err)

			want = bytes.Replace(want, []byte(prepared.ValueText(old)), []byte(prepared.ValueText(newPrimary)), 1)

			assertSameBytes(t, want, ended, tc.fixture)
		})
	}
}
