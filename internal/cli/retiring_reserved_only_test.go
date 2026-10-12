package cli

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/Arman2122/mtg-proxy/internal/utils"
	"github.com/Arman2122/mtg-proxy/mtglib"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// onlyReservedRefusal is the config's refusal of a [secrets] that holds a user
// named retiring-secret and nothing else.
const onlyReservedRefusal = `[secrets] holds only the reserved name "retiring-secret", which is never served, ` +
	"and the top-level secret is not served while [secrets] is present, so the file serves no secret: " +
	"name the users to serve in [secrets], and write an old key as a [[retiring-secret]] block above [secrets]"

// Final review B, I-1, on the reviewer's own file: a top-level secret and a
// [secrets] holding only retiring-secret = "<old value>". The user is never
// served, and the top-level secret is not served while [secrets] is present --
// the file took up [secrets], and the key it left at the top was off. Serving it
// because the table's one user is dropped would make a key live again. So the
// file serves nothing, and every reader refuses it: run and run --check, doctor,
// access (no link at all), a reload (the set in force is kept), the WEB relay's
// parse, and rotate-secret, for which "default" is that top-level secret (refused,
// nothing written, no key made, dry run or not). None prints either key.
//
// Not parallel: access prints to os.Stdout, which the test captures, and the
// rotate-secret rows count generateSecret's calls through a package variable.
func TestAFileWhoseSecretsHoldOnlyTheReservedNameIsRefused(t *testing.T) {
	topLevel := mtglib.GenerateSecret("cover.example.com")
	reserved := mtglib.GenerateSecret("old.example.com")
	everyValue := []mtglib.Secret{topLevel, reserved}

	// A port held by the test: a run that wrongly got past the config fails at
	// its bind and returns, rather than serving.
	bindTo := fmt.Sprintf("127.0.0.1:%d", takenPort(t))
	raw := fmt.Sprintf("secret = %q\nbind-to = %q\n\n[secrets]\nretiring-secret = %q\n",
		topLevel.Hex(), bindTo, reserved.Hex())
	path := writeConfig(t, raw)

	// The read run, run --check, doctor, access, the reloader and the relay all
	// start with -- the relay's watcher from the bytes. First, and required: a
	// file it accepted would take doctor to its network checks and its exit.
	_, readErr := utils.ReadConfig(path)
	_, parseErr := utils.ParseConfig([]byte(raw))

	for who, err := range map[string]error{"the read": readErr, "the relay's parse": parseErr} {
		require.Empty(t, retiringLeaks(errText(err), everyValue...), who+" prints a key")
		require.Error(t, err, who+" accepts a file that serves nothing")
		assert.Equal(t, "invalid config: "+onlyReservedRefusal, err.Error(), who)
	}

	ran := runRefuses(t, path)
	checked := (&Run{ConfigPath: path, Check: true}).Run(nil, "test")
	doctored := (&Doctor{ConfigPath: path}).Run(nil, "test")
	links, accessed := captureStdout(t, func() error {
		return (&Access{ConfigPath: path, PublicIPv4: net.ParseIP("127.0.0.1"), PublicIPv6: net.ParseIP("::1")}).Run(nil, "test")
	})

	require.Empty(t, retiringLeaks(links, everyValue...), "access prints a key")
	assert.Empty(t, links, "access prints a link")

	for who, err := range map[string]error{"run": ran, "run --check": checked, "doctor": doctored, "access": accessed} {
		text := errText(err)
		require.Empty(t, retiringLeaks(text, everyValue...), who+" prints a key")

		require.Error(t, err, who)
		assert.Equal(t, "cannot init config: invalid config: "+onlyReservedRefusal, text, who)
	}

	t.Run("a reload is refused, and the set in force is kept", func(t *testing.T) {
		alice := mtglib.GenerateSecret("cover.example.com")
		reloadPath := filepath.Join(t.TempDir(), "config.toml")
		proxy := reloadingProxy(t, reloadPath, retiringFile(bindTo, map[string]mtglib.Secret{"alice": alice}))

		require.NoError(t, os.WriteFile(reloadPath, []byte(raw), 0o600))

		err := proxy.ReloadSecrets()
		require.Empty(t, retiringLeaks(errText(err), append(everyValue, alice)...), "the reload's error carries a key")
		require.Error(t, err, "the reload serves a file that serves nothing")
		assert.Equal(t, "cannot reload secrets: invalid config: "+onlyReservedRefusal, err.Error())

		served := proxy.SnapshotSecrets()
		require.Equal(t, 1, len(served), "alice, and no other secret")
		assert.Equal(t, "alice", served[0].Name)
		assert.True(t, served[0].Secret == alice.Base64(), "the refused reload changed alice's key")
	})

	for _, dryRun := range []bool{true, false} {
		t.Run(fmt.Sprintf("rotate-secret default is refused, dry run %t", dryRun), func(t *testing.T) {
			rotatePath := writeConfig(t, raw)
			dir := filepath.Dir(rotatePath)
			before := listing(t, dir)
			generated := recordGenerations(t, nil)

			res := runRotate(t, RotateSecret{ConfigPath: rotatePath, Name: "default", Overlap: "1h", DryRun: dryRun})
			require.Empty(t, retiringLeaks(res.printed()+"\n"+res.stdout, everyValue...), "the run prints a key")

			require.Error(t, res.err, "default, the top-level secret, is rotated while [secrets] is present")
			assert.Equal(t, "the config is not valid: "+onlyReservedRefusal+"; "+nothingWritten, res.err.Error())
			assert.Empty(t, res.stdout, "a new value is printed")
			assert.Empty(t, res.stderr, "the run says what it did, or would do")
			assert.Empty(t, generated.modes, "a key is generated")
			assert.Equal(t, before, listing(t, dir), "the file changed, or a lock or a temporary file is left")
		})
	}
}
