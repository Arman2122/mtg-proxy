//go:build windows

package cli

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

// The Windows half of R5: the file's own access control list survives a
// rotation (I-1 of the review), and a rename refused because another program
// holds the file open says so. The lists are set with icacls, a tool apart
// from the code under test, and compared in SDDL.

// daclOf is path's DACL in SDDL: SIDs and rights, never file content.
func daclOf(t *testing.T, path string) string {
	t.Helper()

	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	require.NoError(t, err)

	return sd.String()
}

// icacls runs icacls with args, or skips the test where there is none.
func icacls(t *testing.T, args ...string) {
	t.Helper()

	tool, err := exec.LookPath("icacls")
	if err != nil {
		t.Skipf("icacls is not available: %v", err)
	}

	out, err := exec.Command(tool, args...).CombinedOutput()
	require.NoError(t, err, string(out))
}

// currentUser is the SID of the user the test runs as.
func currentUser(t *testing.T) string {
	t.Helper()

	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	require.NoError(t, err)

	return user.User.Sid.String()
}

// I-1: a protected list for the owner only, an explicit deny on an inherited
// list, and an inherited list only, are each the file's list after a rotation
// as before it.
func TestTheFilesAccessControlListIsKept(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name  string
		set   func(t *testing.T, path string)
		check func(t *testing.T, sddl string) // that the setup took
	}{
		{
			name: "a protected list for the owner only",
			set: func(t *testing.T, path string) {
				t.Helper()
				icacls(t, path, "/inheritance:r", "/grant:r", "*"+currentUser(t)+":F")
			},
			check: func(t *testing.T, sddl string) {
				t.Helper()
				require.True(t, strings.HasPrefix(sddl, "D:P"), "the list is not protected: %s", sddl)
				require.NotContains(t, sddl, ";ID;", "the list still has inherited entries")
			},
		},
		{
			name: "an explicit deny on an inherited list",
			set: func(t *testing.T, path string) {
				t.Helper()
				icacls(t, path, "/deny", "*S-1-5-32-546:(R)")
			},
			check: func(t *testing.T, sddl string) {
				t.Helper()
				require.False(t, strings.HasPrefix(sddl, "D:P"), "the list is protected: %s", sddl)
				require.Contains(t, sddl, "(D;;", "no deny entry")
				require.Contains(t, sddl, ";ID;", "no inherited entry")
			},
		},
		{
			name: "an inherited list only",
			set:  func(*testing.T, string) {},
			check: func(t *testing.T, sddl string) {
				t.Helper()
				require.NotContains(t, sddl, "(D;;", "a deny entry")
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			files := newRotateFiles(t)
			tc.set(t, files.path)

			before := daclOf(t, files.path)
			tc.check(t, before)

			res := runRotate(t, RotateSecret{ConfigPath: files.path, Name: "alice", Overlap: "24h"})
			require.Empty(t, retiringLeaks(res.printed(), files.old()...), "stderr carries an old value")
			require.NoError(t, res.err)

			_, oneLine := res.oneLine()
			assert.True(t, oneLine)
			assert.Equal(t, before, daclOf(t, files.path), "the access control list changed")
			assert.Equal(t, []string{"config.toml"}, names(listing(t, files.dir)))
		})
	}
}

// I-1: a config moved here from another directory keeps the entries it
// inherited there, while a new file here inherits this directory's. The run
// cannot give the new file that list without changing whether it inherits,
// so it refuses, with nothing written, and says how to give the file a list
// of its own; once it has one, the rotation keeps it.
func TestAListInheritedFromAnotherDirectoryIsRefused(t *testing.T) {
	t.Parallel()

	files := newRotateFiles(t)

	data, err := os.ReadFile(files.path)
	require.NoError(t, err)

	elsewhere := filepath.Join(files.dir, "elsewhere")
	require.NoError(t, os.Mkdir(elsewhere, 0o700))
	icacls(t, elsewhere, "/inheritance:r", "/grant:r", "*"+currentUser(t)+":(OI)(CI)F")

	moved := filepath.Join(elsewhere, "config.toml")
	require.NoError(t, os.WriteFile(moved, data, 0o600))
	require.NoError(t, os.Rename(moved, files.path))
	require.NoError(t, os.Remove(elsewhere))

	before := daclOf(t, files.path)
	require.False(t, strings.HasPrefix(before, "D:P"), "the list is protected: %s", before)
	require.Contains(t, before, ";ID;", "the list inherited nothing")

	listed := listing(t, files.dir)

	res := runRotate(t, RotateSecret{ConfigPath: files.path, Name: "alice", Overlap: "24h"})
	require.Empty(t, retiringLeaks(res.printed(), files.old()...), "the refusal carries an old value")
	require.Error(t, res.err, "a rotation gave the config this directory's inherited list")

	assert.Contains(t, res.err.Error(), "was it moved here from another directory?")
	assert.Contains(t, res.err.Error(), `icacls "`+resolved(t, files.path)+`" /inheritance:d`)
	assert.Contains(t, res.err.Error(), "nothing was written")
	assert.Empty(t, res.stdout)
	assert.Equal(t, listed, listing(t, files.dir))
	assert.Equal(t, before, daclOf(t, files.path))

	// The remedy: the same entries, the file's own.
	icacls(t, files.path, "/inheritance:d")
	own := daclOf(t, files.path)

	res = runRotate(t, RotateSecret{ConfigPath: files.path, Name: "alice", Overlap: "24h"})
	require.Empty(t, retiringLeaks(res.printed(), files.old()...), "stderr carries an old value")
	require.NoError(t, res.err)
	assert.Equal(t, own, daclOf(t, files.path), "the access control list changed")
}

// I-1: a list the new file cannot be given is a refusal, as an owner is on
// Unix: nothing is written, and the temporary file is removed.
func TestAnAccessControlListThatCannotBeKeptIsRefused(t *testing.T) {
	files := newRotateFiles(t)
	icacls(t, files.path, "/inheritance:r", "/grant:r", "*"+currentUser(t)+":F")

	before := listing(t, files.dir)
	original := setNamedSecurityInfo

	t.Cleanup(func() { setNamedSecurityInfo = original })

	setNamedSecurityInfo = func(string, windows.SE_OBJECT_TYPE, windows.SECURITY_INFORMATION,
		*windows.SID, *windows.SID, *windows.ACL, *windows.ACL,
	) error {
		return windows.ERROR_ACCESS_DENIED
	}

	res := runRotate(t, RotateSecret{ConfigPath: files.path, Name: "alice", Overlap: "24h"})
	require.Empty(t, retiringLeaks(res.printed(), files.old()...), "the refusal carries an old value")
	require.Error(t, res.err)

	assert.Contains(t, res.err.Error(), "cannot give the new file the access control list of")
	assert.Contains(t, res.err.Error(), "nothing was written")
	assert.Empty(t, res.stdout)
	assert.Equal(t, before, listing(t, files.dir))
}

// A config another program holds open without sharing its deletion cannot be
// replaced on Windows: the refusal says so, and nothing is written.
func TestAFileOpenElsewhereIsNamed(t *testing.T) {
	t.Parallel()

	files := newRotateFiles(t)
	before := listing(t, files.dir)

	held, err := os.Open(files.path)
	require.NoError(t, err)

	t.Cleanup(func() { held.Close() })

	res := runRotate(t, RotateSecret{ConfigPath: files.path, Name: "alice", Overlap: "24h"})
	require.Empty(t, retiringLeaks(res.printed(), files.old()...), "the refusal carries an old value")
	require.Error(t, res.err)

	assert.Contains(t, res.err.Error(), "cannot replace ")
	assert.Contains(t, res.err.Error(), "(is the file open in another program, or may this user not replace it?)")
	assert.Contains(t, res.err.Error(), "nothing was written")
	assert.Empty(t, res.stdout)
	assert.Equal(t, before, listing(t, files.dir))
}
