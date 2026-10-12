//go:build windows

package cli

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

// The Windows half of R5: the file's own access control list survives a
// rotation exactly, whatever its shape (I-1 of the first review, m-2 of the
// second); no one can open the temporary file while it is written (I-A of
// the second); a config this user could not replace is refused before
// anything is made; and a rename refused because another program holds the
// file open says so. The lists are set with icacls, a tool apart from the
// code under test, and compared in SDDL.

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

// I-1: a protected list for the owner only, an explicit deny and an explicit
// allow on an inherited list, and an inherited list only, are each the
// file's list after a rotation as before it, byte for byte.
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
			name: "an explicit allow on an inherited list",
			set: func(t *testing.T, path string) {
				t.Helper()
				icacls(t, path, "/grant", "*S-1-5-32-546:(R)")
			},
			check: func(t *testing.T, sddl string) {
				t.Helper()
				require.False(t, strings.HasPrefix(sddl, "D:P"), "the list is protected: %s", sddl)
				require.Contains(t, sddl, ";;;BG)", "no entry for Guests")
				require.Contains(t, sddl, ";ID;", "no inherited entry")
			},
		},
		{
			name: "an inherited list only",
			set:  func(*testing.T, string) {},
			check: func(t *testing.T, sddl string) {
				t.Helper()
				require.NotContains(t, sddl, "(D;;", "a deny entry")
				require.NotContains(t, sddl, ";;;BG)", "an entry for Guests")
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

// m-2 of the second review: a config moved here from another directory keeps
// the entries it inherited there, which a new file here would not inherit.
// The rotation gives the new file that list exactly, unprotected as it was.
func TestAListInheritedFromAnotherDirectoryIsKept(t *testing.T) {
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

	// What a new file here inherits instead: the case is not vacuous.
	probe := filepath.Join(files.dir, "probe")
	require.NoError(t, os.WriteFile(probe, nil, 0o600))
	require.NotEqual(t, before, daclOf(t, probe), "a new file here inherits the moved file's list anyway")
	require.NoError(t, os.Remove(probe))

	res := runRotate(t, RotateSecret{ConfigPath: files.path, Name: "alice", Overlap: "24h"})
	require.Empty(t, retiringLeaks(res.printed(), files.old()...), "stderr carries an old value")
	require.NoError(t, res.err)

	assert.Equal(t, before, daclOf(t, files.path), "the access control list changed")
	assert.Equal(t, []string{"config.toml"}, names(listing(t, files.dir)))
}

// switchPrimaryGroup makes another group this process's primary group -- the
// group a new file's CREATOR GROUP entry is for -- until the test ends; it
// skips the test where the token cannot be changed.
func switchPrimaryGroup(t *testing.T) {
	t.Helper()

	var token windows.Token

	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY|windows.TOKEN_ADJUST_DEFAULT,
		&token); err != nil {
		t.Skipf("cannot open this process's token: %v", err)
	}

	t.Cleanup(func() { token.Close() })

	current, err := token.GetTokenPrimaryGroup()
	require.NoError(t, err)

	original, err := current.PrimaryGroup.Copy()
	require.NoError(t, err)

	var other *windows.SID

	for _, known := range []windows.WELL_KNOWN_SID_TYPE{windows.WinBuiltinUsersSid, windows.WinAuthenticatedUserSid} {
		sid, err := windows.CreateWellKnownSid(known)
		require.NoError(t, err)

		if !sid.Equals(original) {
			other = sid

			break
		}
	}

	set := func(sid *windows.SID) error {
		group := windows.Tokenprimarygroup{PrimaryGroup: sid}

		return windows.SetTokenInformation(token, windows.TokenPrimaryGroup,
			(*byte)(unsafe.Pointer(&group)), uint32(unsafe.Sizeof(group)))
	}

	if err := set(other); err != nil {
		t.Skipf("cannot change this process's primary group: %v", err)
	}

	t.Cleanup(func() { assert.NoError(t, set(original), "the primary group is not restored") })
}

// m-2 of the second review: a directory with a CREATOR GROUP entry gives each
// new file an entry for its creator's primary group. A config created under
// one group and rotated under another keeps its own entry -- not a refusal,
// and not the rotating user's group. (CREATOR OWNER works the same way but
// needs a second token, which this test cannot make.)
//
// Not parallel: it changes the process's primary group.
func TestAListWithACreatorGroupEntryIsKept(t *testing.T) {
	files := newRotateFiles(t)

	data, err := os.ReadFile(files.path)
	require.NoError(t, err)

	shared := filepath.Join(files.dir, "shared")
	require.NoError(t, os.Mkdir(shared, 0o700))
	icacls(t, shared, "/inheritance:r", "/grant:r", "*"+currentUser(t)+":(OI)(CI)F", "*S-1-3-1:(OI)(CI)(IO)(R)")

	config := filepath.Join(shared, "config.toml")
	require.NoError(t, os.WriteFile(config, data, 0o600))

	before := daclOf(t, config)
	require.Contains(t, before, "(A;ID;FR;;;", "no entry for the creator's group")

	switchPrimaryGroup(t)

	// What a new file inherits now, the temporary file included: another
	// group's entry. The case is not vacuous.
	probe := filepath.Join(shared, "probe")
	require.NoError(t, os.WriteFile(probe, nil, 0o600))
	require.NotEqual(t, before, daclOf(t, probe), "a new file still gets the config's list")
	require.NoError(t, os.Remove(probe))

	res := runRotate(t, RotateSecret{ConfigPath: config, Name: "alice", Overlap: "24h"})
	require.Empty(t, retiringLeaks(res.printed(), files.old()...), "a message carries an old value")
	require.NoError(t, res.err)

	assert.Equal(t, before, daclOf(t, config), "the access control list changed")
	assert.Equal(t, []string{"config.toml"}, names(listing(t, shared)))
}

// replaceSetKernelObjectSecurity swaps the copy for the test.
func replaceSetKernelObjectSecurity(t *testing.T,
	set func(windows.Handle, windows.SECURITY_INFORMATION, *windows.SECURITY_DESCRIPTOR) error,
) {
	t.Helper()

	original := setKernelObjectSecurity

	t.Cleanup(func() { setKernelObjectSecurity = original })

	setKernelObjectSecurity = set
}

// I-1: a list the new file cannot be given is a refusal, as an owner is on
// Unix: nothing is written, and the temporary file is removed.
func TestAnAccessControlListThatCannotBeKeptIsRefused(t *testing.T) {
	files := newRotateFiles(t)
	icacls(t, files.path, "/inheritance:r", "/grant:r", "*"+currentUser(t)+":F")

	before := listing(t, files.dir)

	replaceSetKernelObjectSecurity(t, func(windows.Handle, windows.SECURITY_INFORMATION, *windows.SECURITY_DESCRIPTOR) error {
		return windows.ERROR_ACCESS_DENIED
	})

	res := runRotate(t, RotateSecret{ConfigPath: files.path, Name: "alice", Overlap: "24h"})
	require.Empty(t, retiringLeaks(res.printed(), files.old()...), "the refusal carries an old value")
	require.Error(t, res.err)

	assert.Contains(t, res.err.Error(), "cannot give the new file the access control list of")
	assert.Contains(t, res.err.Error(), "nothing was written")
	assert.Empty(t, res.stdout)
	assert.Equal(t, before, listing(t, files.dir))
}

// The read-back: a copy that comes out different -- here, one that silently
// does nothing, leaving the directory's inherited list -- is a refusal that
// names no cause it does not know, and gives the remedy; never a wider file.
func TestACopyThatComesOutDifferentIsRefused(t *testing.T) {
	files := newRotateFiles(t)
	icacls(t, files.path, "/inheritance:r", "/grant:r", "*"+currentUser(t)+":F")

	before := listing(t, files.dir)
	list := daclOf(t, files.path)

	replaceSetKernelObjectSecurity(t, func(windows.Handle, windows.SECURITY_INFORMATION, *windows.SECURITY_DESCRIPTOR) error {
		return nil
	})

	res := runRotate(t, RotateSecret{ConfigPath: files.path, Name: "alice", Overlap: "24h"})
	require.Empty(t, retiringLeaks(res.printed(), files.old()...), "the refusal carries an old value")
	require.Error(t, res.err, "a rotation gave the config the directory's inherited list")

	assert.Contains(t, res.err.Error(), "the new file would not get the access control list of "+resolved(t, files.path)+
		": the copy differs from the original")
	assert.Contains(t, res.err.Error(), `icacls "`+resolved(t, files.path)+`" /inheritance:d`)
	assert.NotContains(t, res.err.Error(), "moved")
	assert.Contains(t, res.err.Error(), "nothing was written")
	assert.Empty(t, res.stdout)
	assert.Equal(t, before, listing(t, files.dir))
	assert.Equal(t, list, daclOf(t, files.path))
}

// I-A of the second review: the temporary file is shared with no one while it
// is written. A reader that opened it the moment it appeared -- under the
// directory's inherited list, before the config's narrower one is copied on
// -- would read the whole new config through that handle after the rename.
// Here that open is refused; were it not, what it reads is counted, never
// shown.
func TestTheTempFileIsSharedWithNoOne(t *testing.T) {
	files := newRotateFiles(t)
	icacls(t, files.path, "/inheritance:r", "/grant:r", "*"+currentUser(t)+":F")

	list := daclOf(t, files.path)

	var (
		opened   []windows.Handle
		refusals []error
	)

	original := createTemp

	t.Cleanup(func() {
		createTemp = original

		for _, handle := range opened {
			windows.CloseHandle(handle)
		}
	})

	createTemp = func(path string) (tempFile, error) {
		file, err := original(path)
		if err != nil {
			return file, err
		}

		name, nameErr := windows.UTF16PtrFromString(path)
		require.NoError(t, nameErr)

		handle, openErr := windows.CreateFile(name, windows.GENERIC_READ,
			windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil,
			windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
		if openErr != nil {
			refusals = append(refusals, openErr)
		} else {
			opened = append(opened, handle)
		}

		return file, nil
	}

	res := runRotate(t, RotateSecret{ConfigPath: files.path, Name: "alice", Overlap: "24h"})
	require.Empty(t, retiringLeaks(res.printed(), files.old()...), "stderr carries an old value")
	require.NoError(t, res.err)

	for _, handle := range opened {
		read := 0
		buf := make([]byte, 4096)

		for {
			n, err := windows.Read(handle, buf)
			if n == 0 || err != nil {
				break
			}

			read += n
		}

		assert.Zero(t, read, "a handle opened on the temporary file while it was written read the new config")
	}

	assert.Empty(t, opened, "the temporary file was opened by another handle while it was written")
	require.Len(t, refusals, 1)
	assert.ErrorIs(t, refusals[0], windows.ERROR_SHARING_VIOLATION)
	assert.Equal(t, list, daclOf(t, files.path), "the access control list changed")
}

// A config this user may write but not replace -- no DELETE on the file, and
// the directory denies deleting its entries -- is refused before anything is
// made: the rename would fail, and a temporary file under the copied list
// could not be removed.
func TestAConfigThatCannotBeReplacedIsRefused(t *testing.T) {
	t.Parallel()

	files := newRotateFiles(t)
	user := "*" + currentUser(t)

	icacls(t, files.path, "/inheritance:r", "/grant:r", user+":(R,W)")
	icacls(t, files.dir, "/deny", user+":(DC)")

	// Before the directory goes: its own deny would keep the file.
	t.Cleanup(func() { icacls(t, files.dir, "/remove:d", user) })

	before := listing(t, files.dir)

	res := runRotate(t, RotateSecret{ConfigPath: files.path, Name: "alice", Overlap: "24h"})
	require.Empty(t, retiringLeaks(res.printed(), files.old()...), "the refusal carries an old value")
	require.Error(t, res.err)

	assert.Contains(t, res.err.Error(), "cannot replace "+resolved(t, files.path)+": ")
	assert.Contains(t, res.err.Error(), "(is the file open in another program, or may this user not replace it?)")
	assert.Contains(t, res.err.Error(), "nothing was written")
	assert.NotContains(t, res.err.Error(), "could not be removed")
	assert.Empty(t, res.stdout)
	assert.Equal(t, before, listing(t, files.dir), "a temporary file or the lock is left")
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
