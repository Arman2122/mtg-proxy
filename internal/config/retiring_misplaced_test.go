package config_test

import (
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Arman2122/mtg-proxy/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// misplacedLine is the problem line of a [secrets] user named retiring-secret.
const misplacedLine = `a [secrets] user named "retiring-secret" is ignored: ` +
	`[[retiring-secret]] blocks go in their own table, above or between the other tables, one per old key`

// rotMisplaced is the hand edit the line is for: the old link retired by a line
// appended where users are appended, below [secrets]. TOML makes it a user named
// retiring-secret whose primary key is the leaked one.
func rotMisplaced(valueHex string) string {
	return "retiring-secret = \"" + valueHex + "\"\n"
}

// rotErrText is err's text, or nothing for no error.
func rotErrText(err error) string {
	if err == nil {
		return ""
	}

	return err.Error()
}

// servedNames is GetSecrets' names, sorted, and whether any served secret holds
// the key in hex. It never formats a Secret.
func servedNames(conf *config.Config, keyHex string) ([]string, bool) {
	var (
		names []string
		holds bool
	)

	for name, secret := range conf.GetSecrets() {
		names = append(names, name)
		holds = holds || hex.EncodeToString(secret.Key[:]) == keyHex
	}

	slices.Sort(names)

	return names, holds
}

// Revision 4 of §1.1 (Task 8b's review, I1). retiring-secret = "<old value>"
// written below the first table header is no parse error: it is a [secrets]
// user named retiring-secret, and served it would be the leaked key accepted
// forever, as a primary. So that user is never served -- not by run, not by a
// reload, not by the relay or access, which all read GetSecrets -- and the
// report carries a line for it, which run logs at Warning and run --check and
// doctor refuse. The load itself is never refused for it.
func TestASecretsUserNamedRetiringSecretIsNotServed(t *testing.T) {
	t.Parallel()

	leaked := rotEE(rotKeyLeak)

	t.Run("below the other users", func(t *testing.T) {
		t.Parallel()

		conf := rotParse(t, rotFile()+rotMisplaced(leaked))
		require.NoError(t, conf.Validate(), "the user never blocks the load")

		names, holds := servedNames(conf, rotKeyLeak)
		assert.Equal(t, []string{"alice", "bob"}, names)
		assert.False(t, holds, "the leaked key is served")

		report := conf.GetRetiringSecrets(rotNow)
		require.Empty(t, rotLeaks(strings.Join(report.Lines, "\n")+conf.String(), leaked))
		assert.Equal(t, []string{misplacedLine}, report.Lines)
		assert.Empty(t, report.Notes)
		assert.Zero(t, report.Expired)
		assert.Zero(t, len(report.Usable))

		// Still so later: the line depends on the text alone.
		assert.Equal(t, []string{misplacedLine}, conf.GetRetiringSecrets(rotNow.Add(1000*time.Hour)).Lines)
	})

	t.Run("as the only user, beside a top-level secret", func(t *testing.T) {
		t.Parallel()

		conf := rotParse(t, rotSingleFile()+"\n[secrets]\n"+rotMisplaced(leaked))
		require.NoError(t, conf.Validate())

		names, holds := servedNames(conf, rotKeyLeak)
		assert.Equal(t, []string{"default"}, names, "an empty [secrets] serves the top-level secret")
		assert.False(t, holds, "the leaked key is served")
		assert.Equal(t, []string{misplacedLine}, conf.GetRetiringSecrets(rotNow).Lines)
	})

	// Nothing is left to serve, which no file may be: refused, as a file with no
	// secret at all is, and the leaked key is not served. With a fronting host
	// set, only the check of the secrets served stands between the file and a
	// proxy whose one secret is the empty top-level one.
	for name, top := range map[string]string{
		"as the only user, with nothing else to serve":                     "",
		"as the only user, with nothing else to serve and a fronting host": "[domain-fronting]\nhost = \"cover.example.com\"\n\n",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			conf := rotParse(t, "bind-to = \"0.0.0.0:3128\"\n\n"+top+"[secrets]\n"+rotMisplaced(leaked))

			err := conf.Validate()
			require.Empty(t, rotLeaks(rotErrText(err), leaked), "the refusal carries a key")
			require.Error(t, err)

			_, holds := servedNames(conf, rotKeyLeak)
			assert.False(t, holds, "the leaked key is served")
		})
	}

	t.Run("beside a block that retires the same key", func(t *testing.T) {
		t.Parallel()

		// The operator wrote both. The block is what was meant, and the user,
		// which is never served, is no other secret's primary for rule 5.
		conf := rotParse(t, rotFile(rotBlock(rotName("alice"), rotSecret(leaked), rotUntil(rotIn(time.Hour))))+
			rotMisplaced(leaked))

		report := conf.GetRetiringSecrets(rotNow)
		assert.Equal(t, []string{misplacedLine}, report.Lines)
		assert.Equal(t, []string{rotUse("alice", "leak", "ee", rotIn(time.Hour))}, rotUsable(report))
	})

	t.Run("a block may not name it", func(t *testing.T) {
		t.Parallel()

		conf := rotParse(t, rotFile(rotBlock(rotName("retiring-secret"), rotSecret(rotEE(rotKeyOld1)), rotUntil(rotIn(time.Hour))))+
			rotMisplaced(leaked))

		assert.Equal(t, []string{misplacedLine, problemLine(1, "retiring-secret", whyDangling)},
			conf.GetRetiringSecrets(rotNow).Lines)
	})

	// The name is reserved exactly. A user whose name merely looks like it is
	// an ordinary user, served with its own key and named in no line: dropping
	// one would cut a real client under a Warning about somebody else.
	t.Run("only the exact name is dropped", func(t *testing.T) {
		t.Parallel()

		lookalikes := map[string]string{
			"Retiring-Secret":    rotKeyOld1,
			"retiring-secret2":   rotKeyOld2,
			"my-retiring-secret": rotKeyOld3,
			"retiring_secret":    rotKeyOld4,
			"retiring-secrets":   rotKeyOld5,
		}

		var users strings.Builder

		for name, key := range lookalikes {
			fmt.Fprintf(&users, "%q = %q\n", name, rotEE(key))
		}

		conf := rotParse(t, rotFile()+users.String()+rotMisplaced(leaked))
		require.NoError(t, conf.Validate())

		names, holds := servedNames(conf, rotKeyLeak)
		assert.False(t, holds, "the leaked key is served")
		assert.Equal(t, []string{
			"Retiring-Secret", "alice", "bob", "my-retiring-secret", "retiring-secret2", "retiring-secrets", "retiring_secret",
		}, names)

		served := conf.GetSecrets()

		for name, key := range lookalikes {
			secret := served[name]
			assert.True(t, key == hex.EncodeToString(secret.Key[:]), "%s is served with its own key", name)
		}

		assert.Equal(t, []string{misplacedLine}, conf.GetRetiringSecrets(rotNow).Lines,
			"one line, for the exact name only")
	})

	t.Run("only the exact name is dropped, without the name itself", func(t *testing.T) {
		t.Parallel()

		conf := rotParse(t, rotFile()+fmt.Sprintf("%q = %q\n", "Retiring-Secret", rotEE(rotKeyOld1))+
			fmt.Sprintf("%q = %q\n", "retiring-secret2", rotEE(rotKeyOld2)))

		names, _ := servedNames(conf, rotKeyLeak)
		assert.Equal(t, []string{"Retiring-Secret", "alice", "bob", "retiring-secret2"}, names)
		rotEmptyReport(t, conf.GetRetiringSecrets(rotNow), "look-alike names only")
	})

	// V4 (bind-to fronts every failed hello) judges the secrets served. Here the
	// only ee secret with a host is the dropped user and the top-level secret is
	// a hostless dd: judged before the drop, the file would load and front with
	// nothing; judged after it, it is refused, as a file whose secrets cannot
	// front is.
	t.Run("the fronting check judges the secrets served", func(t *testing.T) {
		t.Parallel()

		conf := rotParse(t, "bind-to = \"0.0.0.0:3128\"\nsecret = \""+rotDD(rotKeyAlice)+"\"\n\n[secrets]\n"+
			rotMisplaced(leaked))

		names, holds := servedNames(conf, rotKeyLeak)
		assert.Equal(t, []string{"default"}, names)
		assert.False(t, holds, "the leaked key is served")

		err := conf.Validate()
		require.Empty(t, rotLeaks(rotErrText(err), leaked), "the refusal carries a key")
		require.Error(t, err, "a file whose served secrets cannot front loads")
		assert.Contains(t, err.Error(), "no secret carries a fronting hostname")
	})

	t.Run("a file without it is as before", func(t *testing.T) {
		t.Parallel()

		conf := rotParse(t, rotFile())

		names, _ := servedNames(conf, rotKeyLeak)
		assert.Equal(t, []string{"alice", "bob"}, names)
		rotEmptyReport(t, conf.GetRetiringSecrets(rotNow), "no table and no such user")
	})

	t.Run("the SECRET environment clears it with the rest of [secrets]", func(t *testing.T) {
		t.Parallel()

		conf := rotParse(t, rotFile()+rotMisplaced(leaked))
		conf.Secrets = nil // what applyEnvSecret does

		rotEmptyReport(t, conf.GetRetiringSecrets(rotNow), "[secrets] cleared")
	})
}
