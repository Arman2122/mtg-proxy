package config_test

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/Arman2122/mtg-proxy/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Task 10's review, I-1, M-6, M-7 and N-8. A name of the file -- a key of
// [secret-ad-tags], a [secret-limits.<name>] table, a block's name, [web] host --
// is shown where an error or a line is about it; a secret value an operator
// pasted there must not be. The text that could spell a value is replaced by
// parse_error.go's rule, the one the unknown-key list uses, and an ordinary name
// reads exactly as it did.

// valueTag is a valid ad tag, which is no secret of the file.
const valueTag = "0123456789abcdef0123456789abcdef"

// validated is the error Validate gives for text, which must parse.
func validated(t *testing.T, text string) error {
	t.Helper()

	conf, err := config.Parse([]byte(text))
	require.Empty(t, rotLeaks(rotErrText(err), rotEE(rotKeyLeak), rotEE(rotKeyAlice)), "the parse error carries a value")
	require.NoError(t, err, "the file parses")

	return conf.Validate()
}

// I-1: the reviewer's R01-R08 and R30.
func TestValidateNeverEchoesAValueWrittenAsAName(t *testing.T) {
	t.Parallel()

	old := rotEE(rotKeyLeak)

	for name, tc := range map[string]struct {
		text  string
		value string // in hex, for the leak check
	}{
		"R01 a dd value in hex as a key of [secret-ad-tags]": {
			text:  parseDoc("[secret-ad-tags]\n" + rotDD(rotKeyLeak) + " = \"" + valueTag + "\"\n\n"),
			value: rotDD(rotKeyLeak),
		},
		"R02 an ee value in hex as a key of [secret-ad-tags]": {
			text:  parseDoc("[secret-ad-tags]\n" + old + " = \"" + valueTag + "\"\n\n"),
			value: old,
		},
		"R03 a value in base64url as a key of [secret-ad-tags]": {
			text:  parseDoc("[secret-ad-tags]\n" + rotB64(old) + " = \"" + valueTag + "\"\n\n"),
			value: old,
		},
		"R04 a value in padded standard base64, quoted, as a key of [secret-ad-tags]": {
			text:  parseDoc("[secret-ad-tags]\n\"" + rotStd(old) + "\" = \"" + valueTag + "\"\n\n"),
			value: old,
		},
		"R05 a dd value in hex as a [secret-limits] table": {
			text:  parseDoc("[secret-limits." + rotDD(rotKeyLeak) + "]\nquota = \"1GB\"\n\n"),
			value: rotDD(rotKeyLeak),
		},
		"R06 the 16-byte key in hex as a [secret-limits] table": {
			text:  parseDoc("[secret-limits." + rotKeyLeak + "]\nquota = \"1GB\"\n\n"),
			value: rotKeyLeak,
		},
		"R07 an ee value in uppercase hex as a [secret-limits] table": {
			text:  parseDoc("[secret-limits." + strings.ToUpper(old) + "]\nquota = \"1GB\"\n\n"),
			value: old,
		},
		"R08 the key in standard base64, quoted, as a [secret-limits] table": {
			text:  parseDoc("[secret-limits.\"" + rotStd(rotKeyLeak) + "\"]\nquota = \"1GB\"\n\n"),
			value: rotKeyLeak,
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			err := validated(t, tc.text)
			require.Error(t, err)
			require.Empty(t, rotLeaks(err.Error(), tc.value, rotEE(rotKeyAlice)), "Validate's error carries the value")

			assert.Contains(t, err.Error(), "refers to unknown secret \""+parseNotShown)
		})
	}

	// R30: a [secrets] user named by the value, whose [secret-limits] table
	// turns client-fair on with no speed.
	t.Run("R30 a user named by a value, with client-fair and no speed", func(t *testing.T) {
		t.Parallel()

		text := "bind-to = \"0.0.0.0:3128\"\n\n[secret-limits." + rotDD(rotKeyLeak) + "]\nclient-fair = true\n\n" +
			"[secrets]\n" + rotDD(rotKeyLeak) + " = \"" + rotEE(rotKeyAlice) + "\"\n"

		err := validated(t, text)
		require.Error(t, err)
		require.Empty(t, rotLeaks(err.Error(), rotDD(rotKeyLeak), rotEE(rotKeyAlice)), "Validate's error carries the value")

		assert.True(t, strings.HasPrefix(err.Error(), "secret-limits."+parseNotShown+": client-fair divides"), err.Error())
	})
}

// An ordinary name -- a typo -- reads byte for byte as it did.
func TestValidateShowsAnOrdinaryNameAsBefore(t *testing.T) {
	t.Parallel()

	for text, want := range map[string]string{
		parseDoc("[secret-ad-tags]\nalcie = \"" + valueTag + "\"\n\n"): `secret-ad-tags refers to unknown secret "alcie"`,
		parseDoc("[secret-limits.alcie]\nquota = \"1GB\"\n\n"):         `secret-limits refers to unknown secret "alcie"`,
		parseDoc("[secret-limits.alice]\nclient-fair = true\n\n"): "secret-limits.alice: client-fair divides the secret's speed " +
			"among its addresses and needs speed, speed-up or speed-down beside it",
		parseDoc("[secret-limits.\"team berlin\"]\nquota = \"1GB\"\n\n"): `secret-limits refers to unknown secret "team berlin"`,
	} {
		err := validated(t, text)
		require.Error(t, err)
		assert.Equal(t, want, err.Error())
	}
}

// N-8: [web] host, checked after the parse by ValidateWeb.
func TestValidateWebNeverEchoesAValueWrittenAsTheHost(t *testing.T) {
	t.Parallel()

	old := rotEE(rotKeyLeak)

	for host, want := range map[string]string{
		old:              "[web] host \"" + parseNotShown + "\" must be a fully qualified name with a public certificate",
		old + "@cdn.org": "[web] host \"" + parseNotShown + "@cdn.org\" must be a bare hostname, not a URL",
	} {
		conf, err := config.Parse([]byte(parseDoc("[web]\nenabled = true\nhost = \"" + host + "\"\n\n")))
		require.Empty(t, rotLeaks(rotErrText(err), old), "the parse error carries the value")
		require.NoError(t, err)

		err = conf.ValidateWeb()
		require.Error(t, err)
		require.Empty(t, rotLeaks(err.Error(), old), "ValidateWeb's error carries the value")

		assert.Equal(t, want, err.Error())
	}

	// An ordinary host reads as before.
	conf, err := config.Parse([]byte(parseDoc("[web]\nenabled = true\nhost = \"relay\"\n\n")))
	require.NoError(t, err)
	assert.EqualError(t, conf.ValidateWeb(), `[web] host "relay" must be a fully qualified name with a public certificate`)
}

// M-7: a block's name is shown only when no part of it could spell a value,
// whole or not: the reviewer's R26 (a trailing space from a paste) and a value
// between words. The entry is judged by its name as written either way.
func TestABlocksNameThatHoldsAValueIsNotShown(t *testing.T) {
	t.Parallel()

	old := rotEE(rotKeyLeak)

	for _, name := range []string{
		old + " ",
		"old " + old + " copy",
		"alice." + rotB64(old),
	} {
		conf := rotParse(t, rotFile(rotBlock(rotName(name), rotSecret(rotDD(rotKeyOld1)), rotUntil(rotIn(24*time.Hour)))))
		report := conf.GetRetiringSecrets(rotNow)

		text := strings.Join(report.Lines, "\n") + "\n" + strings.Join(report.Notes, "\n") + "\n" + conf.String()
		require.Empty(t, rotLeaks(text, old), "a line or the config's rendering carries the value")

		require.Len(t, report.Lines, 1)
		assert.Equal(t, namelessProblemLine(1, whyDangling), report.Lines[0])
	}
}

// M-6: an unknown key whose path hides a part names its line, so the operator
// can find it, and two such keys are two entries (the reviewer's R15).
func TestAHiddenUnknownKeyNamesItsLine(t *testing.T) {
	t.Parallel()

	old := rotEE(rotKeyLeak)

	conf := rotParse(t, parseDoc(old+" = 1\n"+rotB64(rotEE(rotKeyOld1))+" = 2\ntrack-client-ip = true\n\n"))

	require.Empty(t, rotLeaks(strings.Join(conf.UnknownKeys, "\n"), old, rotEE(rotKeyOld1)), "an unknown key carries a value")

	assert.Equal(t, []string{
		parseNotShown + " (line 3)",
		parseNotShown + " (line 4)",
		"track-client-ip",
	}, conf.UnknownKeys)

	assert.Equal(t, fmt.Sprintf("unknown config key %q is ignored: a typo, or a key written under the wrong table?",
		parseNotShown+" (line 3)"), conf.UnknownKeyWarnings()[0])
}
