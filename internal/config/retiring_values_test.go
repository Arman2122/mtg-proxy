package config_test

import (
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/Arman2122/mtg-proxy/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// valuesLabelled projects RetiringValues onto the fixture labels (rotLabels) so
// a failing assertion prints a label and never a value: a Secret's String() is
// its value, and testify would dump the key bytes of a []mtglib.Secret.
func valuesLabelled(conf *config.Config) []string {
	values := conf.RetiringValues()
	out := make([]string, 0, len(values))

	for _, value := range values {
		label, known := rotLabels[fmt.Sprintf("%x", value.Key[:])]
		if !known {
			label = "an unlabelled key"
		}

		out = append(out, label+"|"+value.Mode.String())
	}

	return out
}

// Task 11: RetiringValues is the WEB relay's list of retired values, and its
// rule is §1.3's rule 1 and nothing else. The relay recognises a capability so
// that the cover site never sees it; a value the engine would refuse, ignore,
// or already have expired is still a link somebody holds, so the accessor does
// not ask what the rest of the rules ask: not the name's existence (rule 3), not
// the time (rules 2 and 4), not whose key it is (rules 5 and 6), not duplicates
// (rule 7), not the caps (rule 8). Only an entry whose fields are not all there,
// of their types and well formed (rule 1) has no value to give.
//
// The duplicates are kept: the registry drops them, because an inert file must
// never refuse the relay's start. The order is the latest until first, ties in
// file order: the registry keeps the first 4,096 values, so a file with more
// keeps the latest grants and not the oldest.
func TestRetiringValuesFollowRuleOneOnly(t *testing.T) {
	t.Parallel()

	day := rotIn(24 * time.Hour)
	past := rotIn(-time.Hour)
	farOff := rotIn(1000 * 24 * time.Hour)

	t.Run("every entry that passes rule 1 gives its value, whatever its name or time", func(t *testing.T) {
		t.Parallel()

		conf := rotParse(t, rotFile(
			// A configured name, unexpired.
			rotBlock(rotName("alice"), rotSecret(rotEE(rotKeyOld1)), rotUntil(day)),
			// Expired (rule 2): inert, and still a link somebody holds.
			rotBlock(rotName("alice"), rotSecret(rotDD(rotKeyOld2)), rotUntil(past)),
			// A name that is no secret (rule 3).
			rotBlock(rotName("nobody"), rotSecret(rotEE(rotKeyOld3)), rotUntil(day)),
			// "default" while [secrets] is present (rule 3), in base64url.
			rotBlock(rotName("default"), rotSecret(rotB64(rotEE(rotKeyOld4))), rotUntil(day)),
			// The same key as an earlier entry of its name (rule 7).
			rotBlock(rotName("alice"), rotSecret(rotEE(rotKeyOld1)), rotUntil(rotIn(48*time.Hour))),
			// Another name's primary key (rule 5).
			rotBlock(rotName("bob"), rotSecret(rotEE(rotKeyAlice)), rotUntil(day)),
			// The name's own primary key (rule 6).
			rotBlock(rotName("alice"), rotSecret(rotEE(rotKeyAlice)), rotUntil(day)),
			// More than 720h away (rule 4), in the plain form.
			rotBlock(rotName("alice"), rotSecret(rotKeyOld5), rotUntil(farOff)),
			// A name that reads as a value: only its display is withheld.
			rotBlock(rotName(rotValueLikeName), rotSecret(rotEE(rotKeyLeak)), rotUntil(day)),
		))

		// The latest until first (the registry's cap keeps the first values, so
		// it keeps the latest grants), ties in file order, and a value that
		// appears twice has its later until first. Duplicates are kept.
		assert.Equal(t, []string{
			"old5|plain",                    // 1000 days
			"old1|ee",                       // 48h: the duplicate with the later until, from block 5
			"old1|ee", "old3|ee", "old4|ee", // 24h, in file order
			"alice's key|ee", "alice's key|ee", "leak|ee", // 24h, in file order
			"old2|dd", // expired an hour ago
		}, valuesLabelled(conf), "rule 1 alone decides, the latest until comes first, and the duplicates are kept")
	})

	t.Run("the order is by instant, not by how until is spelled", func(t *testing.T) {
		t.Parallel()

		// 09:00 at +03:00 is 06:00Z, earlier than 08:00Z though it sorts later as text.
		conf := rotParse(t, rotFile(
			rotBlock(rotName("alice"), rotSecret(rotEE(rotKeyOld1)), rotUntil("2026-10-09T09:00:00+03:00")),
			rotBlock(rotName("alice"), rotSecret(rotEE(rotKeyOld2)), rotUntil("2026-10-09T08:00:00Z")),
		))

		assert.Equal(t, []string{"old2|ee", "old1|ee"}, valuesLabelled(conf))
	})

	t.Run("an entry that fails rule 1 gives nothing", func(t *testing.T) {
		t.Parallel()

		for name, block := range map[string]string{
			"the name is missing":      rotBlock(rotSecret(rotEE(rotKeyOld1)), rotUntil(day)),
			"the name is empty":        rotBlock(rotName(""), rotSecret(rotEE(rotKeyOld1)), rotUntil(day)),
			"the name is an array":     rotBlock(`name = ["alice"]`, rotSecret(rotEE(rotKeyOld1)), rotUntil(day)),
			"the secret is missing":    rotBlock(rotName("alice"), rotUntil(day)),
			"the secret is empty":      rotBlock(rotName("alice"), rotSecret(""), rotUntil(day)),
			"the secret is a number":   rotBlock(rotName("alice"), "secret = 5", rotUntil(day)),
			"the secret is no value":   rotBlock(rotName("alice"), rotSecret("not-a-secret"), rotUntil(day)),
			"the secret's key is zero": rotBlock(rotName("alice"), rotSecret(rotEE(rotKeyZero)), rotUntil(day)),
			"until is missing":         rotBlock(rotName("alice"), rotSecret(rotEE(rotKeyOld1))),
			"until is empty":           rotBlock(rotName("alice"), rotSecret(rotEE(rotKeyOld1)), rotUntil("")),
			"until is no instant":      rotBlock(rotName("alice"), rotSecret(rotEE(rotKeyOld1)), rotUntil("tomorrow")),
			"until is a number":        rotBlock(rotName("alice"), rotSecret(rotEE(rotKeyOld1)), "until = 5"),
			"until is a local date":    rotBlock(rotName("alice"), rotSecret(rotEE(rotKeyOld1)), "until = 2026-10-09"),
		} {
			t.Run(name, func(t *testing.T) {
				t.Parallel()

				conf := rotParse(t, rotFile(block))
				assert.True(t, conf.RetiringValues() == nil, "an entry failing rule 1 gave %d values", len(conf.RetiringValues()))
			})
		}
	})

	t.Run("a bad entry does not stop the ones around it", func(t *testing.T) {
		t.Parallel()

		conf := rotParse(t, rotFile(
			rotBlock(rotName("alice"), rotSecret(rotEE(rotKeyOld1)), rotUntil("tomorrow")),
			rotBlock(rotName("alice"), rotSecret(rotEE(rotKeyOld2)), rotUntil(day)),
			rotBlock(rotName("alice"), rotSecret(rotEE(rotKeyZero)), rotUntil(day)),
			rotBlock(rotName("bob"), rotSecret(rotEE(rotKeyOld3)), rotUntil(past)),
		))

		assert.Equal(t, []string{"old2|ee", "old3|ee"}, valuesLabelled(conf))
	})

	t.Run("nil, not empty, when there is nothing", func(t *testing.T) {
		t.Parallel()

		assert.True(t, rotParse(t, rotFile()).RetiringValues() == nil, "a file without the table")
		assert.True(t, rotParse(t, rotFile(rotBlock(rotName("alice"), rotUntil(day)))).RetiringValues() == nil,
			"a file whose only entry fails rule 1")
	})
}

// D29 for the relay: the SECRET environment variable fully defines the secret
// set, clears the file's [[retiring-secret]] entries, and so the relay is left
// with no retired value to recognise. The variable is process-wide, so this
// does not run in parallel.
func TestRetiringValuesAreNilAfterTheSecretOverride(t *testing.T) {
	file := rotFile(rotBlock(rotName("alice"), rotSecret(rotEE(rotKeyOld1)), rotUntil(rotIn(24*time.Hour))))

	// Neither spelling of the variable is set, whatever the test process
	// inherited; t.Setenv restores both afterwards.
	for _, name := range []string{"SECRET", "MTG_SECRET"} {
		t.Setenv(name, "")
		require.NoError(t, os.Unsetenv(name))
	}

	conf := rotParse(t, file)
	require.NoError(t, conf.ApplyEnvironment())
	require.Len(t, conf.RetiringValues(), 1, "without the variable the file's value is given")

	for _, variable := range []string{"SECRET", "MTG_SECRET"} {
		t.Run(variable, func(t *testing.T) {
			t.Setenv(variable, rotEE(rotKeyBob))

			conf := rotParse(t, file)
			require.NoError(t, conf.ApplyEnvironment())

			assert.True(t, conf.RetiringValues() == nil, "%d values survived the variable", len(conf.RetiringValues()))
		})
	}
}
