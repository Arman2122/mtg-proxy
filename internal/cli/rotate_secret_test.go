package cli

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Arman2122/mtg-proxy/internal/config"
	"github.com/Arman2122/mtg-proxy/mtglib"
	"github.com/alecthomas/kong"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mtg-proxy rotate-secret, the command and its I/O (spec §7.1, §7.2, §7.4,
// §7.6, §7.7; R4-R9, R11). The edit itself is internal/rotation's, and its
// tests are there.
//
// Every assertion that could print a secret on failure runs after a leak
// check, or compares with assert.True, so that a failing test prints no key.
// A test that swaps generateSecret, renameFile or syncDir does not run in
// parallel, and puts the original back in t.Cleanup.

// rotateNow is the run's one instant in these tests.
var rotateNow = time.Date(2026, 10, 8, 9, 30, 0, 0, time.UTC)

// rotateUntil is rotateNow plus the 24h overlap, as the file gets it.
const rotateUntil = "2026-10-09T09:30:00Z"

// rotateFiles is a config in a directory of its own, with an ee, a dd and a
// plain secret in [secrets], each in hex.
type rotateFiles struct {
	dir, path         string
	alice, bob, carol mtglib.Secret
}

// old is every primary of the file: what no message may print.
func (f rotateFiles) old() []mtglib.Secret { return []mtglib.Secret{f.alice, f.bob, f.carol} }

func mustGenerate(t *testing.T, mode mtglib.SecretMode, host string) mtglib.Secret {
	t.Helper()

	secret, err := mtglib.GenerateSecretMode(mode, host)
	require.NoError(t, err)

	return secret
}

// newRotateFiles writes the three secrets, with the blocks above [secrets].
func newRotateFiles(t *testing.T, blocks ...string) rotateFiles {
	t.Helper()

	f := rotateFiles{
		dir:   t.TempDir(),
		alice: mustGenerate(t, mtglib.SecretModeFakeTLS, "old.example.com"),
		bob:   mustGenerate(t, mtglib.SecretModeDD, ""),
		carol: mustGenerate(t, mtglib.SecretModePlain, ""),
	}

	f.path = filepath.Join(f.dir, "config.toml")
	raw := retiringFile("127.0.0.1:3128", map[string]mtglib.Secret{"alice": f.alice, "bob": f.bob, "carol": f.carol}, blocks...)
	require.NoError(t, os.WriteFile(f.path, []byte(raw), 0o600))

	return f
}

// rewrite replaces the file's text.
func (f rotateFiles) rewrite(t *testing.T, raw string) {
	t.Helper()
	require.NoError(t, os.WriteFile(f.path, []byte(raw), 0o600))
}

// resolved is the path with its symlinks resolved, which is where the run
// writes, locks and puts its temporary file.
func resolved(t *testing.T, path string) string {
	t.Helper()

	target, err := filepath.EvalSymlinks(path)
	require.NoError(t, err)

	return target
}

type rotateResult struct {
	stdout, stderr string
	err            error
}

// printed is all a run says to a person: its stderr, and its error, which
// kong prints on stderr.
func (r rotateResult) printed() string { return r.stderr + "\n" + errText(r.err) }

// oneLine is the value a run printed on stdout, and whether stdout is exactly
// one line.
func (r rotateResult) oneLine() (string, bool) {
	value, ok := strings.CutSuffix(r.stdout, "\n")

	return value, ok && value != "" && !strings.Contains(value, "\n")
}

func runRotate(t *testing.T, r RotateSecret) rotateResult {
	t.Helper()

	var stdout, stderr bytes.Buffer

	r.out, r.errOut = &stdout, &stderr
	if r.now == nil {
		r.now = func() time.Time { return rotateNow }
	}

	err := r.Run(nil, "test")

	return rotateResult{stdout: stdout.String(), stderr: stderr.String(), err: err}
}

// listing is every entry of dir by name: a file's SHA-256, never its bytes,
// which hold secrets; a link's target; or "directory".
func listing(t *testing.T, dir string) map[string]string {
	t.Helper()

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)

	out := map[string]string{}

	for _, entry := range entries {
		path := filepath.Join(dir, entry.Name())

		switch {
		case entry.Type()&fs.ModeSymlink != 0:
			target, err := os.Readlink(path)
			require.NoError(t, err)

			out[entry.Name()] = "link to " + target
		case entry.IsDir():
			out[entry.Name()] = "directory"
		default:
			data, err := os.ReadFile(path)
			require.NoError(t, err)

			sum := sha256.Sum256(data)
			out[entry.Name()] = hex.EncodeToString(sum[:])
		}
	}

	return out
}

func names(entries map[string]string) []string { return slices.Sorted(maps.Keys(entries)) }

// generations records what generateSecret is asked for while a test runs;
// during, when set, runs inside each call, between the run's read of the file
// and its write.
type generations struct {
	modes []mtglib.SecretMode
	hosts []string
}

func recordGenerations(t *testing.T, during func()) *generations {
	t.Helper()

	g := &generations{}
	original := generateSecret

	t.Cleanup(func() { generateSecret = original })

	generateSecret = func(mode mtglib.SecretMode, host string) (mtglib.Secret, error) {
		g.modes = append(g.modes, mode)
		g.hosts = append(g.hosts, host)

		if during != nil {
			during()
		}

		return original(mode, host)
	}

	return g
}

// replaceRename makes renameFile rename, and counts the calls.
func replaceRename(t *testing.T, rename func(oldpath, newpath string) error) *int {
	t.Helper()

	calls := 0
	original := renameFile

	t.Cleanup(func() { renameFile = original })

	renameFile = func(oldpath, newpath string) error {
		calls++

		return rename(oldpath, newpath)
	}

	return &calls
}

// readSecrets parses the file the run wrote.
func readSecrets(t *testing.T, path string) *config.Config {
	t.Helper()

	data, err := os.ReadFile(path)
	require.NoError(t, err)

	conf, err := config.Parse(data)
	require.Empty(t, retiringLeaks(errText(err)), "")
	require.NoError(t, err)

	return conf
}

// A rotation: the new key is the name's primary, the old one is kept in a
// block until the overlap ends, stdout is the new value as the file spells it
// and nothing else, stderr says what happened in §7.2's words, the file is a
// new inode, and the directory holds the config and nothing else.
func TestRotateSecretRotatesAName(t *testing.T) {
	t.Parallel()

	for spelling, spell := range map[string]func(mtglib.Secret) string{
		"hex":       mtglib.Secret.Hex,
		"base64url": mtglib.Secret.Base64,
	} {
		t.Run("a value in "+spelling, func(t *testing.T) {
			t.Parallel()

			files := newRotateFiles(t)
			files.rewrite(t, fmt.Sprintf("bind-to = \"127.0.0.1:3128\"\n\n[secrets]\nalice = %q\nbob = %q\n",
				spell(files.alice), spell(files.bob)))

			before, err := os.Stat(files.path)
			require.NoError(t, err)

			// On Windows a FileInfo reads its file's identity by path, the
			// first time it is compared: now, while the path is the old file.
			require.True(t, os.SameFile(before, before))

			res := runRotate(t, RotateSecret{ConfigPath: files.path, Name: "alice", Overlap: "24h"})
			require.Empty(t, retiringLeaks(res.printed(), files.old()...), "stderr carries an old value")
			require.NoError(t, res.err)

			value, oneLine := res.oneLine()
			require.True(t, oneLine, "stdout is exactly one line")
			require.Empty(t, retiringLeaks(res.stdout, files.old()...), "stdout carries an old value")

			renewed, err := mtglib.ParseSecret(value)
			require.NoError(t, err)
			assert.Empty(t, retiringLeaks(res.printed(), renewed), "the new value is printed on stdout only")
			assert.True(t, renewed.Key != files.alice.Key, "the key is new")
			assert.True(t, renewed.Mode == files.alice.Mode && renewed.Host == files.alice.Host, "the mode and host are kept")
			assert.True(t, value == spell(renewed), "the value is printed in the file's spelling")

			data, err := os.ReadFile(files.path)
			require.NoError(t, err)
			assert.True(t, bytes.Contains(data, []byte(`alice = "`+value+`"`)), "stdout is the value as the file holds it")

			conf := readSecrets(t, files.path)
			assert.True(t, conf.Secrets["alice"] == renewed, "the new key is alice's primary")
			assert.True(t, conf.Secrets["bob"] == files.bob, "bob is untouched")

			require.Len(t, conf.RetiringSecrets, 1)
			entry := conf.RetiringSecrets[0]
			assert.Equal(t, "alice", entry.Name)
			assert.Equal(t, rotateUntil, entry.Until)
			assert.True(t, entry.Secret == spell(files.alice), "the block keeps the old value as the file spelled it")

			assert.Equal(t, strings.Join([]string{
				`rotated "alice" in ` + files.path,
				"the previous key is accepted until " + rotateUntil + " (24h0m0s from now)",
				"the running proxy does not know yet: POST /reload on its management API, or restart it",
				"links: mtg-proxy access " + files.path,
			}, "\n")+"\n", res.stderr)

			assert.Equal(t, []string{"config.toml"}, names(listing(t, files.dir)), "a file besides the config is left")

			after, err := os.Stat(files.path)
			require.NoError(t, err)
			assert.False(t, os.SameFile(before, after), "the file was written through its inode, not replaced")
		})
	}
}

// R4. A lock another run holds refuses this one, in words that name the lock,
// its age and the remedy; the lock is never broken, however old, and nothing
// is written.
func TestAHeldLockRefusesTheRun(t *testing.T) {
	generated := recordGenerations(t, nil)

	files := newRotateFiles(t)
	lock := resolved(t, files.path) + ".rotate.lock"

	require.NoError(t, os.WriteFile(lock, []byte("pid 4242\nstarted 2026-10-08T07:30:00Z\n"), 0o600))
	require.NoError(t, os.Chtimes(lock, rotateNow.Add(-2*time.Hour), rotateNow.Add(-2*time.Hour)))

	before := listing(t, files.dir)

	res := runRotate(t, RotateSecret{ConfigPath: files.path, Name: "alice", Overlap: "24h"})
	require.Empty(t, retiringLeaks(res.printed(), files.old()...), "the refusal carries an old value")
	require.Error(t, res.err)

	assert.Contains(t, res.err.Error(), "another rotate-secret holds "+lock+
		" (started 2h0m0s ago); if none is running, remove it and retry")
	assert.Contains(t, res.err.Error(), "nothing was written")
	assert.Empty(t, res.stdout)
	assert.Empty(t, generated.modes, "a key was generated")

	assert.Equal(t, before, listing(t, files.dir), "the lock was broken, or the file written")

	held, err := os.ReadFile(lock)
	require.NoError(t, err)
	assert.Equal(t, "pid 4242\nstarted 2026-10-08T07:30:00Z\n", string(held), "the lock was rewritten")
}

// R4. The run holds its lock while it works -- the lock names its pid and
// start time, and a second run is refused meanwhile -- and removes it at the
// end.
func TestTheLockIsHeldWhileTheRunWorks(t *testing.T) {
	files := newRotateFiles(t)
	lock := resolved(t, files.path) + ".rotate.lock"

	var (
		held   []byte
		second rotateResult
	)

	recordGenerations(t, func() {
		held, _ = os.ReadFile(lock)
		second = runRotate(t, RotateSecret{ConfigPath: files.path, Name: "bob", Overlap: "1h"})
	})

	res := runRotate(t, RotateSecret{ConfigPath: files.path, Name: "alice", Overlap: "24h"})
	require.Empty(t, retiringLeaks(res.printed()+second.printed(), files.old()...), "a run printed an old value")
	require.NoError(t, res.err)

	assert.Equal(t, fmt.Sprintf("pid %d\nstarted 2026-10-08T09:30:00Z\n", os.Getpid()), string(held))

	require.Error(t, second.err, "a second run went ahead while the first held the lock")
	assert.Contains(t, second.err.Error(), "another rotate-secret holds "+lock)
	assert.Empty(t, second.stdout)

	assert.NoFileExists(t, lock, "the lock is left behind")
	assert.Equal(t, []string{"config.toml"}, names(listing(t, files.dir)))
}

// R4. A file that changes between the run's read and its rename is not
// replaced: the other writer's bytes stay, and the run says so.
func TestAFileChangedWhileRotatingIsNotReplaced(t *testing.T) {
	files := newRotateFiles(t)

	original, err := os.ReadFile(files.path)
	require.NoError(t, err)

	edited := append(bytes.Clone(original), []byte("# an edit by someone else\n")...)

	recordGenerations(t, func() { require.NoError(t, os.WriteFile(files.path, edited, 0o600)) })
	renames := replaceRename(t, os.Rename)

	res := runRotate(t, RotateSecret{ConfigPath: files.path, Name: "alice", Overlap: "24h"})
	require.Empty(t, retiringLeaks(res.printed(), files.old()...), "the abort carries an old value")
	require.Error(t, res.err)

	assert.Contains(t, res.err.Error(), "the file changed while rotating; nothing was written")
	assert.Empty(t, res.stdout)
	assert.Zero(t, *renames, "the run renamed over a changed file")

	data, err := os.ReadFile(files.path)
	require.NoError(t, err)
	assert.True(t, bytes.Equal(edited, data), "the other writer's edit is gone")
	assert.Equal(t, []string{"config.toml"}, names(listing(t, files.dir)), "a temporary file or the lock is left")
}

// R5. A file that cannot be opened for writing is refused: a read-only config
// is a statement, even where a rename would succeed.
func TestANonWritableFileIsRefused(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root opens a read-only file for writing")
	}

	generated := recordGenerations(t, nil)
	files := newRotateFiles(t)

	require.NoError(t, os.Chmod(files.path, 0o444))
	t.Cleanup(func() { os.Chmod(files.path, 0o600) })

	before := listing(t, files.dir)

	res := runRotate(t, RotateSecret{ConfigPath: files.path, Name: "alice", Overlap: "24h"})
	require.Empty(t, retiringLeaks(res.printed(), files.old()...), "the refusal carries an old value")
	require.Error(t, res.err)

	assert.Contains(t, res.err.Error(), "the config file is not writable: ")
	assert.Contains(t, res.err.Error(), "nothing was written")
	assert.Empty(t, res.stdout)
	assert.Empty(t, generated.modes)
	assert.Equal(t, before, listing(t, files.dir))
}

// R5. A symlinked config: the link's target is written, and the link stays a
// link to it. The lock and the temporary file go next to the target.
func TestASymlinksTargetIsWritten(t *testing.T) {
	t.Parallel()

	files := newRotateFiles(t)
	links := t.TempDir()
	link := filepath.Join(links, "config.toml")

	if err := os.Symlink(files.path, link); err != nil {
		t.Skipf("this system does not make a symlink here: %v", err)
	}

	res := runRotate(t, RotateSecret{ConfigPath: link, Name: "alice", Overlap: "24h"})
	require.Empty(t, retiringLeaks(res.printed(), files.old()...), "stderr carries an old value")
	require.NoError(t, res.err)

	value, oneLine := res.oneLine()
	require.True(t, oneLine)

	info, err := os.Lstat(link)
	require.NoError(t, err)
	assert.NotZero(t, info.Mode()&fs.ModeSymlink, "the link was replaced by a regular file")

	pointsTo, err := os.Readlink(link)
	require.NoError(t, err)
	assert.Equal(t, files.path, pointsTo)

	data, err := os.ReadFile(files.path)
	require.NoError(t, err)
	assert.True(t, bytes.Contains(data, []byte(`alice = "`+value+`"`)), "the target does not hold the new value")

	assert.Equal(t, []string{"config.toml"}, names(listing(t, links)))
	assert.Equal(t, []string{"config.toml"}, names(listing(t, files.dir)))
}

// R6. A rename onto a mount point (EBUSY, EXDEV) is the §7.4 message: nothing
// is written, the temporary file is removed, and the directory lists exactly
// as before. Another rename failure removes it too.
func TestAFailedRenameWritesNothing(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want string
	}{
		{name: "EBUSY", err: syscall.EBUSY, want: "it is a mount point (a single-file bind mount?); " +
			"run rotate-secret on the host, and mount the config's directory into the container"},
		{name: "EXDEV", err: syscall.EXDEV, want: "it is a mount point (a single-file bind mount?); " +
			"run rotate-secret on the host, and mount the config's directory into the container"},
		{name: "another error", err: errors.New("refused by the test"), want: "refused by the test"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			files := newRotateFiles(t)
			target := resolved(t, files.path)
			before := listing(t, files.dir)

			var tmp string

			replaceRename(t, func(oldpath, newpath string) error {
				tmp = oldpath

				return &os.LinkError{Op: "rename", Old: oldpath, New: newpath, Err: tc.err}
			})

			res := runRotate(t, RotateSecret{ConfigPath: files.path, Name: "alice", Overlap: "24h"})
			require.Empty(t, retiringLeaks(res.printed(), files.old()...), "the refusal carries an old value")
			require.Error(t, res.err)

			assert.Contains(t, res.err.Error(), "cannot replace "+target+": "+tc.want)
			assert.Contains(t, res.err.Error(), "nothing was written")
			assert.Empty(t, res.stdout)

			assert.Equal(t, filepath.Dir(target), filepath.Dir(tmp), "the temporary file is not beside the target")
			assert.Regexp(t, regexp.MustCompile(`^`+regexp.QuoteMeta(filepath.Base(target))+`\.rotate-[0-9a-f]{8}\.tmp$`),
				filepath.Base(tmp))
			assert.NoFileExists(t, tmp, "the temporary file is left behind")
			assert.Equal(t, before, listing(t, files.dir), "the directory changed")
		})
	}
}

// R6. The directory is synced after the rename. A failed sync does not undo a
// written file: the run still prints the new value, and warns.
func TestTheDirectoryIsSyncedAfterTheRename(t *testing.T) {
	for _, fails := range []bool{false, true} {
		t.Run(fmt.Sprintf("the sync fails: %v", fails), func(t *testing.T) {
			files := newRotateFiles(t)
			target := resolved(t, files.path)

			var (
				synced  []string
				renamed bool
			)

			original := syncDir

			t.Cleanup(func() { syncDir = original })

			syncDir = func(dir string) error {
				synced = append(synced, dir)

				data, err := os.ReadFile(target)
				renamed = err == nil && !bytes.Contains(data, []byte(`alice = "`+files.alice.Hex()+`"`))

				if fails {
					return errors.New("the sync is refused by the test")
				}

				return original(dir)
			}

			res := runRotate(t, RotateSecret{ConfigPath: files.path, Name: "alice", Overlap: "24h"})
			require.Empty(t, retiringLeaks(res.printed(), files.old()...), "stderr carries an old value")
			require.NoError(t, res.err)

			_, oneLine := res.oneLine()
			assert.True(t, oneLine, "the new value is not printed")
			assert.Equal(t, []string{filepath.Dir(target)}, synced)
			assert.True(t, renamed, "the directory was synced before the rename")

			if fails {
				assert.Contains(t, res.stderr, "warning: the file is written, but its directory could not be synced: "+
					"the sync is refused by the test")
			} else {
				assert.NotContains(t, res.stderr, "warning")
			}
		})
	}
}

// R7. stdout is the new value and nothing else, and no message the run can
// print -- a success, a dry run, every refusal, the lock, the hash abort, a
// mount point, the parser's error over a scalar retiring-secret that holds
// the old value -- carries any spelling of an old value or key.
func TestNothingPrintsTheOldValue(t *testing.T) {
	for _, tc := range []struct {
		name    string
		blocks  func(f rotateFiles) []mtglib.Secret // the old keys a block holds: retiring values to look for too
		setup   func(t *testing.T, f rotateFiles)
		run     RotateSecret
		rotates bool
	}{
		{name: "a rotation", run: RotateSecret{Name: "alice", Overlap: "24h"}, rotates: true},
		{name: "a rotation with --overlap 0", run: RotateSecret{Name: "alice", Overlap: "0"}, rotates: true},
		{name: "a rotation of a dd secret", run: RotateSecret{Name: "bob", Overlap: "1h"}, rotates: true},
		{name: "a dry run", run: RotateSecret{Name: "alice", Overlap: "24h", DryRun: true}},
		{name: "--end-overlap", run: RotateSecret{Name: "alice", EndOverlap: true}},
		{name: "--prune", run: RotateSecret{Prune: true}},
		{name: "a rotation with --prune", run: RotateSecret{Name: "alice", Overlap: "24h", Prune: true}, rotates: true},
		{
			name: "the lock refusal",
			setup: func(t *testing.T, f rotateFiles) {
				t.Helper()
				require.NoError(t, os.WriteFile(resolved(t, f.path)+".rotate.lock", []byte("pid 1\n"), 0o600))
			},
			run: RotateSecret{Name: "alice", Overlap: "24h"},
		},
		{
			name: "the hash abort",
			setup: func(t *testing.T, f rotateFiles) {
				t.Helper()
				recordGenerations(t, func() {
					data, _ := os.ReadFile(f.path)
					require.NoError(t, os.WriteFile(f.path, append(data, "# edited\n"...), 0o600))
				})
			},
			run: RotateSecret{Name: "alice", Overlap: "24h"},
		},
		{
			name: "a mount point",
			setup: func(t *testing.T, _ rotateFiles) {
				t.Helper()
				replaceRename(t, func(oldpath, newpath string) error {
					return &os.LinkError{Op: "rename", Old: oldpath, New: newpath, Err: syscall.EBUSY}
				})
			},
			run: RotateSecret{Name: "alice", Overlap: "24h"},
		},
		{name: "--host with a dd secret", run: RotateSecret{Name: "bob", Overlap: "24h", Host: "new.example.com"}},
		{name: "a name that is not served", run: RotateSecret{Name: "dave", Overlap: "24h"}},
		{
			name: "a scalar retiring-secret holding the old value",
			setup: func(t *testing.T, f rotateFiles) {
				t.Helper()
				f.rewrite(t, fmt.Sprintf("bind-to = \"127.0.0.1:3128\"\nretiring-secret = %q\n\n[secrets]\nalice = %q\n",
					f.alice.Hex(), f.bob.Hex()))
			},
			run: RotateSecret{Name: "alice", Overlap: "24h"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			older := mustGenerate(t, mtglib.SecretModeFakeTLS, "older.example.com")
			expired := mustGenerate(t, mtglib.SecretModeDD, "")

			files := newRotateFiles(t,
				retiringBlock("alice", older, rfc3339(rotateNow.Add(time.Hour))),
				retiringBlock("bob", expired, rfc3339(rotateNow.Add(-time.Hour))))
			old := append(files.old(), older, expired)

			if tc.setup != nil {
				tc.setup(t, files)
			}

			run := tc.run
			run.ConfigPath = files.path

			res := runRotate(t, run)
			require.Empty(t, retiringLeaks(res.printed(), old...), "a message carries an old value")
			require.Empty(t, retiringLeaks(res.stdout, old...), "stdout carries an old value")

			if !tc.rotates {
				assert.Empty(t, res.stdout, "stdout carries something")

				return
			}

			require.NoError(t, res.err)

			value, oneLine := res.oneLine()
			require.True(t, oneLine, "stdout is not exactly one line")

			renewed, err := mtglib.ParseSecret(value)
			require.NoError(t, err)
			assert.Empty(t, retiringLeaks(res.printed(), renewed), "the new value is printed beyond stdout")
		})
	}
}

// R8. A dry run prints its summary on stderr, generates no key and writes
// nothing: the file and the directory are as they were.
func TestADryRunWritesNothingAndGeneratesNoKey(t *testing.T) {
	for _, tc := range []struct {
		name string
		run  RotateSecret
		want func(path string) []string
	}{
		{
			name: "a rotation",
			run:  RotateSecret{Name: "alice", Overlap: "24h", DryRun: true},
			want: func(path string) []string {
				return []string{
					`dry run: would rotate "alice" in ` + path,
					"dry run: the previous key would be accepted until " + rotateUntil + " (24h0m0s from now)",
					"dry run: nothing was written, and no key was generated",
				}
			},
		},
		{
			name: "--end-overlap",
			run:  RotateSecret{Name: "alice", EndOverlap: true, DryRun: true},
			want: func(path string) []string {
				return []string{
					`dry run: would end the overlap of "alice" in ` + path +
						": its previous keys stop being accepted when the proxy reloads or restarts",
					`dry run: would remove a [[retiring-secret]] block: name "alice", until 2026-10-08T10:30:00Z`,
					"dry run: nothing was written, and no key was generated",
				}
			},
		},
		{
			name: "--prune",
			run:  RotateSecret{Prune: true, DryRun: true},
			want: func(path string) []string {
				return []string{
					"dry run: would prune the expired [[retiring-secret]] blocks of " + path,
					`dry run: would remove a [[retiring-secret]] block: name "bob", until 2026-10-08T08:30:00Z`,
					"dry run: nothing was written, and no key was generated",
				}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			generated := recordGenerations(t, nil)

			files := newRotateFiles(t,
				retiringBlock("alice", mustGenerate(t, mtglib.SecretModeFakeTLS, "older.example.com"),
					rfc3339(rotateNow.Add(time.Hour))),
				retiringBlock("bob", mustGenerate(t, mtglib.SecretModeDD, ""), rfc3339(rotateNow.Add(-time.Hour))))
			before := listing(t, files.dir)

			run := tc.run
			run.ConfigPath = files.path

			res := runRotate(t, run)
			require.Empty(t, retiringLeaks(res.printed(), files.old()...), "stderr carries an old value")
			require.NoError(t, res.err)

			assert.Empty(t, generated.modes, "a dry run generated a key")
			assert.Empty(t, res.stdout)
			assert.Equal(t, before, listing(t, files.dir), "a dry run changed the directory")
			assert.Equal(t, strings.Join(tc.want(files.path), "\n")+"\n", res.stderr)
		})
	}
}

// R9. Every refusal: the flags of §7.1, a name that is not served, "default"
// beside [secrets], a 5th unexpired entry, --host with dd or plain, --reload.
// Each says why, says nothing was written, writes nothing and generates no
// key.
func TestRotateSecretRefuses(t *testing.T) {
	const overlapMissing = "say how long the previous key stays accepted: --overlap 24h, or --overlap 0 to retire it at once"

	fourBlocks := func(t *testing.T) []string {
		t.Helper()

		var blocks []string
		for i := range 4 {
			blocks = append(blocks, retiringBlock("alice", mustGenerate(t, mtglib.SecretModeFakeTLS, "older.example.com"),
				rfc3339(rotateNow.Add(time.Duration(i+1)*time.Hour))))
		}

		return blocks
	}

	for _, tc := range []struct {
		name   string
		blocks func(t *testing.T) []string
		run    RotateSecret
		want   string
	}{
		{name: "a rotation without --overlap", run: RotateSecret{Name: "alice"}, want: overlapMissing},
		{name: "a name with --prune and no --overlap", run: RotateSecret{Name: "alice", Prune: true}, want: overlapMissing},
		{name: "--host without --overlap", run: RotateSecret{Name: "alice", Host: "new.example.com"}, want: overlapMissing},
		{name: "an overlap over 720h", run: RotateSecret{Name: "alice", Overlap: "720h1s"}, want: "--overlap is at most 720h"},
		{name: "an overlap of 31 days", run: RotateSecret{Name: "alice", Overlap: "744h"}, want: "--overlap is at most 720h"},
		{name: "a negative overlap", run: RotateSecret{Name: "alice", Overlap: "-1h"}, want: "--overlap cannot be negative"},
		{name: "an overlap that is not a duration", run: RotateSecret{Name: "alice", Overlap: "a day"}, want: "--overlap takes a Go duration"},
		{
			name: "--overlap with --end-overlap",
			run:  RotateSecret{Name: "alice", Overlap: "24h", EndOverlap: true},
			want: "--overlap and --end-overlap cannot be given together",
		},
		{name: "--overlap without a name", run: RotateSecret{Overlap: "24h"}, want: "a rotation needs a name"},
		{name: "--end-overlap without a name", run: RotateSecret{EndOverlap: true}, want: "--end-overlap needs a name"},
		{name: "nothing asked", run: RotateSecret{}, want: "name the secret to rotate"},
		{name: "--host with --end-overlap", run: RotateSecret{Name: "alice", EndOverlap: true, Host: "new.example.com"}, want: "--host is for a rotation only"},
		{name: "--host with --prune alone", run: RotateSecret{Prune: true, Host: "new.example.com"}, want: "--host is for a rotation only"},
		{
			name: "--host with a dd secret",
			run:  RotateSecret{Name: "bob", Overlap: "24h", Host: "new.example.com"},
			want: `--host is for an ee secret only: "bob" is a dd secret, which carries no hostname`,
		},
		{
			name: "--host with a plain secret",
			run:  RotateSecret{Name: "carol", Overlap: "24h", Host: "new.example.com"},
			want: `--host is for an ee secret only: "carol" is a plain secret, which carries no hostname`,
		},
		{
			name: "default beside [secrets]",
			run:  RotateSecret{Name: "default", Overlap: "24h"},
			want: `"default" is not served while [secrets] is present; rotate a name from [secrets]`,
		},
		{name: "a name that is not served", run: RotateSecret{Name: "dave", Overlap: "24h"}, want: `there is no secret named "dave"`},
		{
			name:   "a 5th unexpired entry",
			blocks: fourBlocks,
			run:    RotateSecret{Name: "alice", Overlap: "24h"},
			want:   `"alice" already has 4 unexpired previous keys`,
		},
		{name: "--reload", run: RotateSecret{Name: "alice", Overlap: "24h", Reload: true}, want: "--reload is not available yet"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			generated := recordGenerations(t, nil)

			var blocks []string
			if tc.blocks != nil {
				blocks = tc.blocks(t)
			}

			files := newRotateFiles(t, blocks...)
			before := listing(t, files.dir)

			run := tc.run
			run.ConfigPath = files.path

			res := runRotate(t, run)
			require.Empty(t, retiringLeaks(res.printed(), files.old()...), "the refusal carries an old value")
			require.Error(t, res.err)

			assert.Contains(t, res.err.Error(), tc.want)
			assert.Contains(t, res.err.Error(), "nothing was written")
			assert.Empty(t, res.stdout)
			assert.Empty(t, generated.modes, "a refused run generated a key")
			assert.Equal(t, before, listing(t, files.dir), "a refused run changed the directory")
		})
	}

	t.Run("720h is accepted", func(t *testing.T) {
		files := newRotateFiles(t)

		res := runRotate(t, RotateSecret{ConfigPath: files.path, Name: "alice", Overlap: "720h"})
		require.Empty(t, retiringLeaks(res.printed(), files.old()...), "stderr carries an old value")
		require.NoError(t, res.err)
		assert.Contains(t, res.stderr, "the previous key is accepted until 2026-11-07T09:30:00Z (720h0m0s from now)")
	})
}

// R11. A file at …/mtproto/mtg-<digits>.toml is the panel's, which would put
// the old key back: refused unless --force. Other paths are not.
func TestAPanelFileIsRefusedUnlessForced(t *testing.T) {
	t.Parallel()

	const refusal = "this looks like a config the Penhoon panel generates (…/mtproto/mtg-N.toml); the panel rewrites " +
		"it from its own records and would make the old key the primary again; re-key the client in the panel instead"

	for _, tc := range []struct {
		dir, file string
		force     bool
		refused   bool
	}{
		{dir: "mtproto", file: "mtg-7.toml", refused: true},
		{dir: "mtproto", file: "mtg-12345.toml", refused: true},
		{dir: "mtproto", file: "mtg-7.toml", force: true},
		{dir: "mtproto", file: "mtg-.toml"},
		{dir: "mtproto", file: "mtg-7a.toml"},
		{dir: "mtproto", file: "config.toml"},
		{dir: "proxies", file: "mtg-7.toml"},
	} {
		t.Run(fmt.Sprintf("%s/%s, --force %v", tc.dir, tc.file, tc.force), func(t *testing.T) {
			t.Parallel()

			files := newRotateFiles(t)
			dir := filepath.Join(files.dir, tc.dir)
			path := filepath.Join(dir, tc.file)

			require.NoError(t, os.Mkdir(dir, 0o700))
			require.NoError(t, os.Rename(files.path, path))

			before := listing(t, dir)

			res := runRotate(t, RotateSecret{ConfigPath: path, Name: "alice", Overlap: "24h", Force: tc.force})
			require.Empty(t, retiringLeaks(res.printed(), files.old()...), "a message carries an old value")

			if !tc.refused {
				require.NoError(t, res.err)

				_, oneLine := res.oneLine()
				assert.True(t, oneLine)

				return
			}

			require.Error(t, res.err)
			assert.Contains(t, res.err.Error(), refusal)
			assert.Contains(t, res.err.Error(), "nothing was written")
			assert.Empty(t, res.stdout)
			assert.Equal(t, before, listing(t, dir))
		})
	}

	t.Run("a link to a panel file", func(t *testing.T) {
		t.Parallel()

		files := newRotateFiles(t)
		dir := filepath.Join(files.dir, "mtproto")
		path := filepath.Join(dir, "mtg-7.toml")

		require.NoError(t, os.Mkdir(dir, 0o700))
		require.NoError(t, os.Rename(files.path, path))

		link := filepath.Join(t.TempDir(), "config.toml")
		if err := os.Symlink(path, link); err != nil {
			t.Skipf("this system does not make a symlink here: %v", err)
		}

		before := listing(t, dir)

		res := runRotate(t, RotateSecret{ConfigPath: link, Name: "alice", Overlap: "24h"})
		require.Empty(t, retiringLeaks(res.printed(), files.old()...), "a message carries an old value")
		require.Error(t, res.err)
		assert.Contains(t, res.err.Error(), refusal)
		assert.Equal(t, before, listing(t, dir))
	})
}

// --overlap 0 is an immediate re-key: no block, and the old value is in no
// file at all afterwards.
func TestOverlapZeroWritesNoBlock(t *testing.T) {
	t.Parallel()

	files := newRotateFiles(t)

	res := runRotate(t, RotateSecret{ConfigPath: files.path, Name: "alice", Overlap: "0"})
	require.Empty(t, retiringLeaks(res.printed(), files.old()...), "stderr carries an old value")
	require.NoError(t, res.err)

	value, oneLine := res.oneLine()
	require.True(t, oneLine)

	data, err := os.ReadFile(files.path)
	require.NoError(t, err)
	assert.Empty(t, retiringLeaks(string(data), files.alice), "the old key is still in the file")
	assert.NotContains(t, string(data), "retiring-secret")
	assert.True(t, bytes.Contains(data, []byte(`alice = "`+value+`"`)))

	conf := readSecrets(t, files.path)
	assert.Empty(t, conf.RetiringSecrets)

	assert.Equal(t, strings.Join([]string{
		`rotated "alice" in ` + files.path,
		"the previous key is not kept (--overlap 0): it stops being accepted when the proxy reloads or restarts",
		"the running proxy does not know yet: POST /reload on its management API, or restart it",
		"links: mtg-proxy access " + files.path,
	}, "\n")+"\n", res.stderr)
	assert.Equal(t, []string{"config.toml"}, names(listing(t, files.dir)))
}

// §7.2: with [web] enabled, a rotation says the WEB links change at once,
// because the WEB transport has no overlap. Without it, or for a run that
// changes no primary, it does not.
func TestAWebEnabledFileSaysWebLinksChangeNow(t *testing.T) {
	t.Parallel()

	const line = `WEB links of "alice" change now; the WEB transport has no overlap (see WEB-Proxy-Setup)`

	webFile := func(alice mtglib.Secret, enabled string, blocks ...string) string {
		return `bind-to = "127.0.0.1:3128"

[[listener]]
bind-to = "127.0.0.1:2398"
accept = ["dd", "plain"]

[web]
enabled = ` + enabled + `
host = "proxy.example.com"
bind-to = "127.0.0.1:8099"
backend = "127.0.0.1:2398"
token-key = "/etc/mtg-proxy/web.key"
cover-dir = "/var/www/site"

` + strings.Join(blocks, "") + `[secrets]
alice = "` + alice.Hex() + `"
`
	}

	for _, tc := range []struct {
		name    string
		enabled string
		run     RotateSecret
		says    bool
	}{
		{name: "a rotation, web enabled", enabled: "true", run: RotateSecret{Name: "alice", Overlap: "24h"}, says: true},
		{name: "--overlap 0, web enabled", enabled: "true", run: RotateSecret{Name: "alice", Overlap: "0"}, says: true},
		{name: "a rotation, web disabled", enabled: "false", run: RotateSecret{Name: "alice", Overlap: "24h"}},
		{name: "--end-overlap, web enabled", enabled: "true", run: RotateSecret{Name: "alice", EndOverlap: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			files := newRotateFiles(t)
			older := mustGenerate(t, mtglib.SecretModeFakeTLS, "older.example.com")
			raw := webFile(files.alice, tc.enabled, retiringBlock("alice", older, rfc3339(rotateNow.Add(time.Hour))))
			files.rewrite(t, raw)

			conf, err := config.Parse([]byte(raw))
			require.NoError(t, err)
			require.NoError(t, conf.Validate())

			if tc.enabled == "true" {
				require.NoError(t, conf.ValidateWeb())
			}

			run := tc.run
			run.ConfigPath = files.path

			res := runRotate(t, run)
			require.Empty(t, retiringLeaks(res.printed(), files.alice, older), "stderr carries an old value")
			require.NoError(t, res.err)

			if tc.says {
				assert.Contains(t, res.stderr, line+"\n")
			} else {
				assert.NotContains(t, res.stderr, "WEB links")
			}
		})
	}
}

// §7.7: a run with nothing to do exits 0, writes nothing, and says so.
func TestANoOpExitsZeroAndSaysSo(t *testing.T) {
	for _, tc := range []struct {
		name string
		run  RotateSecret
		want func(path string) string
	}{
		{
			name: "--prune with nothing expired",
			run:  RotateSecret{Prune: true},
			want: func(path string) string {
				return "nothing to do: no [[retiring-secret]] block has expired in " + path + "; nothing was written"
			},
		},
		{
			name: "--end-overlap for a name without blocks",
			run:  RotateSecret{Name: "bob", EndOverlap: true},
			want: func(path string) string {
				return `nothing to do: "bob" has no [[retiring-secret]] block in ` + path + "; nothing was written"
			},
		},
		{
			name: "--end-overlap and --prune, neither with anything to remove",
			run:  RotateSecret{Name: "bob", EndOverlap: true, Prune: true},
			want: func(path string) string {
				return `nothing to do: "bob" has no [[retiring-secret]] block, and no block has expired, in ` + path +
					"; nothing was written"
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			generated := recordGenerations(t, nil)
			renames := replaceRename(t, os.Rename)

			files := newRotateFiles(t, retiringBlock("alice", mustGenerate(t, mtglib.SecretModeFakeTLS, "older.example.com"),
				rfc3339(rotateNow.Add(time.Hour))))
			before := listing(t, files.dir)

			run := tc.run
			run.ConfigPath = files.path

			res := runRotate(t, run)
			require.Empty(t, retiringLeaks(res.printed(), files.old()...), "stderr carries an old value")
			require.NoError(t, res.err, "a no-op is a success")

			assert.Equal(t, tc.want(files.path)+"\n", res.stderr)
			assert.Empty(t, res.stdout)
			assert.Empty(t, generated.modes)
			assert.Zero(t, *renames, "a no-op wrote the file")
			assert.Equal(t, before, listing(t, files.dir))
		})
	}
}

// D22, §7.2: the new key keeps the old primary's mode and host, or takes
// --host for ee; it is generated once.
func TestTheNewKeyKeepsTheModeAndHost(t *testing.T) {
	for _, tc := range []struct {
		name, secret, host string
		mode               mtglib.SecretMode
		wantHost           string
	}{
		{name: "ee keeps its host", secret: "alice", mode: mtglib.SecretModeFakeTLS, wantHost: "old.example.com"},
		{name: "ee takes --host", secret: "alice", host: "new.example.com", mode: mtglib.SecretModeFakeTLS, wantHost: "new.example.com"},
		{name: "dd", secret: "bob", mode: mtglib.SecretModeDD},
		{name: "plain", secret: "carol", mode: mtglib.SecretModePlain},
	} {
		t.Run(tc.name, func(t *testing.T) {
			generated := recordGenerations(t, nil)
			files := newRotateFiles(t)

			res := runRotate(t, RotateSecret{ConfigPath: files.path, Name: tc.secret, Overlap: "24h", Host: tc.host})
			require.Empty(t, retiringLeaks(res.printed(), files.old()...), "stderr carries an old value")
			require.NoError(t, res.err)

			assert.Equal(t, []mtglib.SecretMode{tc.mode}, generated.modes)
			assert.Equal(t, []string{tc.wantHost}, generated.hosts)

			renewed := readSecrets(t, files.path).Secrets[tc.secret]
			assert.Equal(t, tc.mode, renewed.Mode)
			assert.Equal(t, tc.wantHost, renewed.Host)
		})
	}
}

// §7.3 step 1: a problem the file already has does not block an urgent
// rotation; it is printed on stderr as a warning, without a value.
func TestExistingProblemsAreWarnedNotBlocking(t *testing.T) {
	t.Parallel()

	stray := mustGenerate(t, mtglib.SecretModeFakeTLS, "older.example.com")
	files := newRotateFiles(t, retiringBlock("dave", stray, rfc3339(rotateNow.Add(time.Hour))))

	res := runRotate(t, RotateSecret{ConfigPath: files.path, Name: "alice", Overlap: "24h"})
	require.Empty(t, retiringLeaks(res.printed(), append(files.old(), stray)...), "stderr carries an old value")
	require.NoError(t, res.err)

	assert.Contains(t, res.stderr, `warning: retiring-secret #1 (name "dave"): name is not a configured secret`)

	_, oneLine := res.oneLine()
	assert.True(t, oneLine)

	conf := readSecrets(t, files.path)
	assert.Len(t, conf.RetiringSecrets, 2, "the problem block is kept beside the new one")
}

// The command line reaches the struct: kong's tags are only read when main
// parses, which no build or vet checks.
func TestTheRotateSecretCommandParses(t *testing.T) {
	t.Parallel()

	path := writeConfig(t, "bind-to = \"127.0.0.1:3128\"\n")

	parse := func(t *testing.T, args ...string) RotateSecret {
		t.Helper()

		var cli CLI

		parser, err := kong.New(&cli, kong.Vars{"version": "test"})
		require.NoError(t, err)

		ctx, err := parser.Parse(append([]string{"rotate-secret"}, args...))
		require.NoError(t, err)
		require.Equal(t, "rotate-secret", ctx.Selected().Name)

		return cli.RotateSecret
	}

	got := parse(t, path, "alice", "--overlap", "24h", "--host", "new.example.com", "--prune", "--dry-run", "--force")
	assert.Equal(t, RotateSecret{
		ConfigPath: path, Name: "alice", Overlap: "24h", Host: "new.example.com", Prune: true, DryRun: true, Force: true,
	}, got)

	assert.Equal(t, RotateSecret{ConfigPath: path, Name: "alice", EndOverlap: true, Reload: true},
		parse(t, path, "alice", "--end-overlap", "--reload"))
	assert.Equal(t, RotateSecret{ConfigPath: path, Prune: true}, parse(t, path, "--prune"))
}
