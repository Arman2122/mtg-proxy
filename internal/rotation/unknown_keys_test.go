package rotation

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/Arman2122/mtg-proxy/internal/config"
	"github.com/Arman2122/mtg-proxy/mtglib"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Task 10's review, M-6: an unknown key whose path hides a value-like part
// names the line it is on. A rotation inserts a block above it, so the line
// moves; the verification compares unknown keys by their path, and the edit
// is no change of them.
func TestAHiddenUnknownKeyBelowTheNewBlockIsNoChange(t *testing.T) {
	t.Parallel()

	doc := lines(
		`bind-to = "0.0.0.0:3128"`,
		``,
		`[secrets]`,
		`alice = `+quoted(ee(keyAlice)),
		``,
		`[network.timeout]`,
		dd(keyOld1)+` = "1s"`,
	)

	before, err := config.Parse(doc)
	require.Empty(t, leaks(errText(err)), "the parse error carries a key")
	require.NoError(t, err)
	require.Empty(t, leaks(strings.Join(before.UnknownKeys, "\n")), "an unknown key carries a key")
	require.Len(t, before.UnknownKeys, 1)
	assert.True(t, strings.HasSuffix(before.UnknownKeys[0], " (line 7)"), "the unknown key names its line")

	prepared, err := Prepare(doc, Request{Name: "alice", Rotate: true, Until: testUntil, Now: testNow})
	require.Empty(t, leaks(errText(err)), "the refusal carries a key")
	require.NoError(t, err)

	out, err := prepared.Apply(newPrimaryLike(mtglib.Secret{Mode: mtglib.SecretModeFakeTLS, Host: "storage.googleapis.com"}))
	require.Empty(t, leaks(errText(err)), "the refusal carries a key")
	require.NoError(t, err, "the moved line of a hidden unknown key fails the verification")

	after, err := config.Parse(out)
	require.NoError(t, err)
	require.Len(t, after.UnknownKeys, 1)
	assert.Equal(t, config.UnknownKeyPath(before.UnknownKeys[0]), config.UnknownKeyPath(after.UnknownKeys[0]))
	assert.NotEqual(t, before.UnknownKeys[0], after.UnknownKeys[0], "the key's line did not move")
}

// Task 10's review, M-7 and N-2: the edit shows a name by config's display
// rule, so a value with other text around it -- a space pasted after it, words
// on either side -- is withheld as a bare value is: in a refusal, and in the
// Summary of the blocks removed.
func TestANameHoldingAValueAmongOtherTextIsNeverEchoed(t *testing.T) {
	t.Parallel()

	t.Run("the name asked for", func(t *testing.T) {
		t.Parallel()

		doc := lines(`bind-to = "0.0.0.0:3128"`, ``, `[secrets]`, `alice = `+quoted(ee(keyAlice)))

		_, err := Prepare(doc, Request{Name: ee(keyOld1) + " ", Rotate: true, Until: testUntil, Now: testNow})
		require.Error(t, err)
		require.Empty(t, leaks(err.Error()), "the refusal carries a value")
		assert.Contains(t, err.Error(), "there is no secret by that name (it is not shown: it reads as a secret value)")
	})

	t.Run("the name of a removed block", func(t *testing.T) {
		t.Parallel()

		doc := lines(
			`bind-to = "0.0.0.0:3128"`,
			``,
			`[[retiring-secret]]`,
			`name = `+quoted("old "+b64(ee(keyOld1))+" copy"),
			`secret = `+quoted(dd(keyOld2)),
			`until = `+quoted(at(-time.Hour)),
			``,
			`[secrets]`,
			`alice = `+quoted(ee(keyAlice)),
		)

		prepared, err := Prepare(doc, Request{Prune: true, Now: testNow})
		require.Empty(t, leaks(errText(err)), "the refusal carries a value")
		require.NoError(t, err)

		summary := prepared.Summary()
		require.Empty(t, leaks(fmt.Sprintf("%#v", summary)), "the summary carries a value")
		require.Len(t, summary.Removed, 1)
		assert.Empty(t, summary.Removed[0].Name, "a name holding a value is shown")
	})
}

// errText is err's text, or nothing for no error.
func errText(err error) string {
	if err == nil {
		return ""
	}

	return err.Error()
}
