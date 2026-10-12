//go:build windows

package cli

import (
	"fmt"
	"io/fs"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
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
// does nothing, leaving the list the temporary file was born with -- is a
// refusal that names no cause it does not know, and gives the remedy. The
// config's list grants Guests read as well, so the two lists differ in their
// entries, not only in a flag.
func TestACopyThatComesOutDifferentIsRefused(t *testing.T) {
	files := newRotateFiles(t)
	icacls(t, files.path, "/inheritance:r", "/grant:r", "*"+currentUser(t)+":F", "*S-1-5-32-546:(R)")

	before := listing(t, files.dir)
	list := daclOf(t, files.path)
	require.Contains(t, list, ";;;BG)", "no entry for Guests")

	replaceSetKernelObjectSecurity(t, func(windows.Handle, windows.SECURITY_INFORMATION, *windows.SECURITY_DESCRIPTOR) error {
		return nil
	})

	res := runRotate(t, RotateSecret{ConfigPath: files.path, Name: "alice", Overlap: "24h"})
	require.Empty(t, retiringLeaks(res.printed(), files.old()...), "the refusal carries an old value")
	require.Error(t, res.err, "a rotation gave the config another list")

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

// securityOf is path's DACL and mandatory label in SDDL.
func securityOf(t *testing.T, path string) string {
	t.Helper()

	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.LABEL_SECURITY_INFORMATION)
	require.NoError(t, err)

	return sd.String()
}

// icaclsShow is what icacls prints for path: a reading apart from the code
// under test.
func icaclsShow(t *testing.T, path string) string {
	t.Helper()

	tool, err := exec.LookPath("icacls")
	if err != nil {
		t.Skipf("icacls is not available: %v", err)
	}

	out, err := exec.Command(tool, path).CombinedOutput()
	require.NoError(t, err, string(out))

	return string(out)
}

// acesOf is the entries of a DACL in SDDL, without its flags.
func acesOf(sddl string) string {
	if at := strings.IndexByte(sddl, '('); at >= 0 {
		return sddl[at:]
	}

	return ""
}

// setRaw stores sddl's DACL on path as it is, with the low-level call:
// nothing recomputed, no flags added.
func setRaw(t *testing.T, path, sddl string) {
	t.Helper()

	sd, err := windows.SecurityDescriptorFromString(sddl)
	require.NoError(t, err)

	name, err := windows.UTF16PtrFromString(path)
	require.NoError(t, err)

	handle, err := windows.CreateFile(name, windows.READ_CONTROL|windows.WRITE_DAC,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, 0, 0)
	require.NoError(t, err)

	defer windows.CloseHandle(handle)

	require.NoError(t, windows.SetKernelObjectSecurity(handle, windows.DACL_SECURITY_INFORMATION, sd))
}

// I-B of the third review: the temporary file is born private -- a protected
// list for the runner only, the analogue of 0600 -- so that in the moment
// before the config's list is copied on, no one else can open it at all, not
// even for WRITE_DAC or WRITE_OWNER, which no sharing mode refuses. And
// private in integrity (I-C of the fourth review): a mandatory label at the
// runner's own integrity, no-read-up, no-write-up and no-execute-up, in place
// of the directory's.
func TestTheTempFileIsBornPrivate(t *testing.T) {
	files := newRotateFiles(t)
	icacls(t, files.path, "/inheritance:r", "/grant:r", "*"+currentUser(t)+":F")

	private, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;" + currentUser(t) + ")")
	require.NoError(t, err)

	label, err := windows.SecurityDescriptorFromString("S:(ML;;NWNRNX;;;" + currentIntegrity(t) + ")")
	require.NoError(t, err)

	var born []string

	original := createTemp

	t.Cleanup(func() { createTemp = original })

	createTemp = func(path string) (tempFile, error) {
		file, err := original(path)
		if err == nil {
			born = append(born, securityOf(t, path))
		}

		return file, err
	}

	res := runRotate(t, RotateSecret{ConfigPath: files.path, Name: "alice", Overlap: "24h"})
	require.Empty(t, retiringLeaks(res.printed(), files.old()...), "stderr carries an old value")
	require.NoError(t, res.err)

	require.Len(t, born, 1)

	dacl, sacl := splitSecurity(born[0])
	assert.True(t, strings.HasPrefix(dacl, "D:P"), "the temporary file was born with an unprotected list: %s", born[0])
	assert.Equal(t, acesOf(private.String()), acesOf(dacl), "the temporary file was born with another list")
	assert.Equal(t, acesOf(label.String()), acesOf(sacl), "the temporary file was born with another label")
}

// currentIntegrity is this process's integrity level SID, read here apart
// from the code under test.
func currentIntegrity(t *testing.T) string {
	t.Helper()

	var size uint32

	_ = windows.GetTokenInformation(windows.GetCurrentProcessToken(), windows.TokenIntegrityLevel, nil, 0, &size)
	require.NotZero(t, size)

	buf := make([]byte, size)
	require.NoError(t, windows.GetTokenInformation(windows.GetCurrentProcessToken(), windows.TokenIntegrityLevel,
		&buf[0], size, &size))

	return (*windows.Tokenmandatorylabel)(unsafe.Pointer(&buf[0])).Label.Sid.String()
}

// splitSecurity is an SDDL cut into its DACL and its label (SACL) parts.
func splitSecurity(sddl string) (string, string) {
	if at := strings.Index(sddl, "S:"); at >= 0 {
		return sddl[:at], sddl[at:]
	}

	return sddl, ""
}

// lowIntegrityToken is this process's token, duplicated for impersonation
// and lowered to Low integrity: the runner's own user, as a sandboxed process
// of it runs.
func lowIntegrityToken(t *testing.T) windows.Token {
	t.Helper()

	var process windows.Token

	require.NoError(t, windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_DUPLICATE|windows.TOKEN_QUERY,
		&process))

	defer process.Close()

	var low windows.Token

	require.NoError(t, windows.DuplicateTokenEx(process, windows.TOKEN_ALL_ACCESS, nil, windows.SecurityImpersonation,
		windows.TokenImpersonation, &low))

	t.Cleanup(func() { low.Close() })

	sid, err := windows.CreateWellKnownSid(windows.WinLowLabelSid)
	require.NoError(t, err)

	label := windows.Tokenmandatorylabel{Label: windows.SIDAndAttributes{Sid: sid, Attributes: windows.SE_GROUP_INTEGRITY}}
	require.NoError(t, windows.SetTokenInformation(low, windows.TokenIntegrityLevel,
		(*byte)(unsafe.Pointer(&label)), label.Size()))

	return low
}

// opensAs is which of masks token can open path for, by name, sharing all:
// the opens a process running as token could make.
func opensAs(t *testing.T, token windows.Token, path string, masks map[string]uint32) []string {
	t.Helper()

	name, err := windows.UTF16PtrFromString(path)
	require.NoError(t, err)

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	require.NoError(t, windows.SetThreadToken(nil, token))

	defer windows.RevertToSelf()

	var opened []string

	for _, label := range slices.Sorted(maps.Keys(masks)) {
		handle, err := windows.CreateFile(name, masks[label],
			windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, 0, 0)
		if err == nil {
			opened = append(opened, label)
			windows.CloseHandle(handle)
		}
	}

	return opened
}

// I-C of the fourth review: in a directory whose new files get a Low label
// (as AppData\LocalLow's do), a low-integrity process of the runner's own user
// cannot open the temporary file for READ_CONTROL, WRITE_DAC or WRITE_OWNER --
// not when it is born, and not after either step of the copy -- so it cannot
// keep a handle through which to relabel, and then read, the new config,
// which the config's Medium no-read-up label keeps from it.
func TestALowIntegrityProcessCannotOpenTheTemp(t *testing.T) {
	files := newRotateFiles(t)
	icacls(t, files.dir, "/setintegritylevel", "(OI)(CI)L")
	labelMedium(t, files.path)

	low := lowIntegrityToken(t)
	masks := map[string]uint32{
		"READ_CONTROL": windows.READ_CONTROL,
		"WRITE_DAC":    windows.WRITE_DAC,
		"WRITE_OWNER":  windows.WRITE_OWNER,
	}

	// The setup: the low token is kept from the config, and reaches a new
	// file of the directory.
	require.Empty(t, opensAs(t, low, files.path, masks), "the setup: a low-integrity process reaches the config")

	probe := filepath.Join(files.dir, "probe")
	require.NoError(t, os.WriteFile(probe, nil, 0o600))
	require.NotEmpty(t, opensAs(t, low, probe, masks), "the setup: the low-integrity token reaches nothing")
	require.NoError(t, os.Remove(probe))

	before := securityOf(t, files.path)

	var (
		tmp    string
		opened = map[string][]string{}
	)

	original := createTemp

	t.Cleanup(func() { createTemp = original })

	createTemp = func(path string) (tempFile, error) {
		file, err := original(path)
		if err == nil {
			tmp = path
			opened["born"] = opensAs(t, low, path, masks)
		}

		return file, err
	}

	set := setKernelObjectSecurity

	replaceSetKernelObjectSecurity(t, func(handle windows.Handle, info windows.SECURITY_INFORMATION,
		sd *windows.SECURITY_DESCRIPTOR,
	) error {
		err := set(handle, info, sd)
		opened[fmt.Sprintf("after setting %#x", uint32(info))] = opensAs(t, low, tmp, masks)

		return err
	})

	res := runRotate(t, RotateSecret{ConfigPath: files.path, Name: "alice", Overlap: "24h"})
	require.Empty(t, retiringLeaks(res.printed(), files.old()...), "stderr carries an old value")
	require.NoError(t, res.err)

	assert.Equal(t, map[string][]string{
		"born":               nil,
		"after setting 0x4":  nil, // DACL_SECURITY_INFORMATION
		"after setting 0x10": nil, // LABEL_SECURITY_INFORMATION
	}, opened, "a low-integrity process opened the temporary file")

	assert.Empty(t, opensAs(t, low, files.path, masks), "a low-integrity process reaches the new config")
	assert.Equal(t, before, securityOf(t, files.path), "the access control list or the label changed")
}

// m-E of the fourth review: an unlabelled config moved into a directory whose
// new files get a label -- Low, or Medium no-read-up -- rotates and stays
// unlabelled: the label the temporary file would inherit is removed, not
// refused (with a Low one, the new file would be wider than the config).
func TestAnUnlabelledConfigInALabellingDirectoryRotates(t *testing.T) {
	t.Parallel()

	for name, label := range map[string]func(t *testing.T, dir string){
		"(OI)(CI) Low": func(t *testing.T, dir string) {
			t.Helper()
			icacls(t, dir, "/setintegritylevel", "(OI)(CI)L")
		},
		"(ML;OICI;NRNW;;;ME)": func(t *testing.T, dir string) {
			t.Helper()

			sd, err := windows.SecurityDescriptorFromString("S:(ML;OICI;NRNW;;;ME)")
			require.NoError(t, err)

			sacl, _, err := sd.SACL()
			require.NoError(t, err)
			require.NoError(t, windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
				windows.LABEL_SECURITY_INFORMATION, nil, nil, nil, sacl))
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			files := newRotateFiles(t)
			labelling := filepath.Join(files.dir, "labelling")
			require.NoError(t, os.Mkdir(labelling, 0o700))
			label(t, labelling)

			config := filepath.Join(labelling, "config.toml")
			require.NoError(t, os.Rename(files.path, config))

			before := securityOf(t, config)
			require.NotContains(t, before, "(ML;", "the config is labelled")

			probe := filepath.Join(labelling, "probe")
			require.NoError(t, os.WriteFile(probe, nil, 0o600))
			require.Contains(t, securityOf(t, probe), "(ML;", "a new file here gets no label")
			require.NoError(t, os.Remove(probe))

			shown := icaclsShow(t, config)

			res := runRotate(t, RotateSecret{ConfigPath: config, Name: "alice", Overlap: "24h"})
			require.Empty(t, retiringLeaks(res.printed(), files.old()...), "a message carries an old value")
			require.NoError(t, res.err, "an unlabelled config in a labelling directory is refused")

			after := securityOf(t, config)
			beforeDACL, _ := splitSecurity(before)
			afterDACL, afterLabel := splitSecurity(after)

			assert.Equal(t, beforeDACL, afterDACL, "the access control list changed")
			assert.NotContains(t, afterLabel, "(ML;", "the new config is labelled")
			assert.Equal(t, shown, icaclsShow(t, config))
			assert.Equal(t, []string{"config.toml"}, names(listing(t, labelling)))
		})
	}
}

// I-B of the third review: a config with a NULL DACL -- open to everyone --
// keeps it. A temporary file born private must not turn it owner-only, which
// could lock out the account the proxy runs as; the original's own exposure
// widens nothing.
func TestANullDACLIsKept(t *testing.T) {
	t.Parallel()

	files := newRotateFiles(t)
	require.NoError(t, windows.SetNamedSecurityInfo(files.path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, nil, nil))

	before := daclOf(t, files.path)
	require.Contains(t, before, "NO_ACCESS_CONTROL", "the list is not null")

	res := runRotate(t, RotateSecret{ConfigPath: files.path, Name: "alice", Overlap: "24h"})
	require.Empty(t, retiringLeaks(res.printed(), files.old()...), "stderr carries an old value")
	require.NoError(t, res.err)

	assert.Equal(t, before, daclOf(t, files.path), "the access control list changed")
	assert.Equal(t, []string{"config.toml"}, names(listing(t, files.dir)))
}

// labelMedium puts a Medium mandatory label with no-read-up and no-write-up on
// path: low-integrity processes of any user cannot read it.
func labelMedium(t *testing.T, path string) {
	t.Helper()
	labelWith(t, path, "S:(ML;;NRNW;;;ME)")
}

// m-A of the third review: a config's mandatory label survives a rotation, as
// SDDL and as icacls prints it.
func TestAMandatoryLabelIsKept(t *testing.T) {
	t.Parallel()

	files := newRotateFiles(t)
	labelMedium(t, files.path)

	before := securityOf(t, files.path)
	require.Contains(t, before, "S:", "no label")
	require.Contains(t, before, ";;;ME)", "no Medium label")

	shown := icaclsShow(t, files.path)
	require.Contains(t, shown, "Mandatory Label\\Medium Mandatory Level")

	res := runRotate(t, RotateSecret{ConfigPath: files.path, Name: "alice", Overlap: "24h"})
	require.Empty(t, retiringLeaks(res.printed(), files.old()...), "stderr carries an old value")
	require.NoError(t, res.err)

	assert.Equal(t, before, securityOf(t, files.path), "the access control list or the label changed")
	assert.Equal(t, shown, icaclsShow(t, files.path))
	assert.Equal(t, []string{"config.toml"}, names(listing(t, files.dir)))
}

// labelWith gives path the mandatory label in sddl ("S:(ML;...)").
func labelWith(t *testing.T, path, sddl string) {
	t.Helper()

	label, err := windows.SecurityDescriptorFromString(sddl)
	require.NoError(t, err)

	sacl, _, err := label.SACL()
	require.NoError(t, err)

	require.NoError(t, windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.LABEL_SECURITY_INFORMATION, nil, nil, nil, sacl))
}

// The conservative label remedy: no tool suggestion that would drop a
// no-read-up or no-execute-up policy (m-F of the fifth review: icacls
// /setintegritylevel writes no-write-up only).
const keepItsPolicy = "restore the label with a tool that keeps its policy, or run rotate-secret as a user who may set it"

// m-A: a label the new file cannot be given is a refusal that names the
// label as it is and a remedy that does not weaken it -- never "remove the
// label" -- and nothing is written. An unlabelled config, which takes the
// same path now that the label is always set, gets a remedy that fits it.
// (A runner below the config's label never gets here: the token's own
// no-write-up policy refuses it at checkWritable, whatever the label's
// policy; only a file system quirk does.)
func TestALabelThatCannotBeKeptIsRefused(t *testing.T) {
	for _, tc := range []struct {
		name, label, shown, remedy, notRemedy string
	}{
		{
			name: "Medium, no-read-up", label: "S:(ML;;NRNW;;;ME)", shown: "(ML;;NWNR;;;ME))",
			remedy: keepItsPolicy,
		},
		{
			name: "no label", shown: "(no label)",
			remedy: "run rotate-secret as a user who may set it", notRemedy: "restore the label",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			files := newRotateFiles(t)
			if tc.label != "" {
				labelWith(t, files.path, tc.label)
			}

			before := listing(t, files.dir)
			original := setKernelObjectSecurity

			replaceSetKernelObjectSecurity(t, func(handle windows.Handle, info windows.SECURITY_INFORMATION,
				sd *windows.SECURITY_DESCRIPTOR,
			) error {
				if info&windows.LABEL_SECURITY_INFORMATION != 0 {
					return windows.ERROR_ACCESS_DENIED
				}

				return original(handle, info, sd)
			})

			res := runRotate(t, RotateSecret{ConfigPath: files.path, Name: "alice", Overlap: "24h"})
			require.Empty(t, retiringLeaks(res.printed(), files.old()...), "the refusal carries an old value")
			require.Error(t, res.err)

			assert.Contains(t, res.err.Error(), "cannot give the new file the integrity label of "+resolved(t, files.path)+" ")
			assert.Contains(t, res.err.Error(), tc.shown)
			assert.Contains(t, res.err.Error(), tc.remedy)
			assert.NotContains(t, res.err.Error(), "remove the label")
			assert.NotContains(t, res.err.Error(), "elevated prompt")

			if tc.notRemedy != "" {
				assert.NotContains(t, res.err.Error(), tc.notRemedy)
			}

			assert.Contains(t, res.err.Error(), "nothing was written")
			assert.Empty(t, res.stdout)
			assert.Equal(t, before, listing(t, files.dir))
		})
	}
}

// m-A: the read-back covers the label too. A label copy that silently does
// nothing -- the list comes out right, the label not -- is refused. The
// message names the label as it is; icacls is offered only for a label it
// can write back whole -- no-write-up alone, Low, Medium or High -- and never
// for one with no-read-up or no-execute-up, which icacls would drop (m-F of
// the fifth review). Giving the file its own list does not change its label
// (m-E of the fourth).
func TestALabelThatComesOutDifferentIsRefused(t *testing.T) {
	for _, tc := range []struct {
		name, label, shown, remedy string
	}{
		{name: "Medium, no-read-up", label: "S:(ML;;NRNW;;;ME)", shown: "(ML;;NWNR;;;ME))", remedy: keepItsPolicy},
		{name: "Low, no-write-up only", label: "S:(ML;;NW;;;LW)", shown: "(ML;;NW;;;LW))", remedy: `/setintegritylevel L`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			files := newRotateFiles(t)
			labelWith(t, files.path, tc.label)

			before := listing(t, files.dir)
			original := setKernelObjectSecurity

			replaceSetKernelObjectSecurity(t, func(handle windows.Handle, info windows.SECURITY_INFORMATION,
				sd *windows.SECURITY_DESCRIPTOR,
			) error {
				if info&windows.LABEL_SECURITY_INFORMATION != 0 {
					return nil
				}

				return original(handle, info, sd)
			})

			res := runRotate(t, RotateSecret{ConfigPath: files.path, Name: "alice", Overlap: "24h"})
			require.Empty(t, retiringLeaks(res.printed(), files.old()...), "the refusal carries an old value")
			require.Error(t, res.err, "a rotation lost the config's label")

			assert.Contains(t, res.err.Error(), "the new file would not get the integrity label of "+resolved(t, files.path)+" ")
			assert.Contains(t, res.err.Error(), tc.shown+": the copy differs from the original")
			assert.Contains(t, res.err.Error(), tc.remedy)

			if tc.remedy == keepItsPolicy {
				assert.NotContains(t, res.err.Error(), "icacls", "a remedy that would drop the label's no-read-up")
			} else {
				assert.Contains(t, res.err.Error(), `icacls "`+resolved(t, files.path)+`" `+tc.remedy)
			}

			assert.NotContains(t, res.err.Error(), "/inheritance:d")
			assert.Contains(t, res.err.Error(), "nothing was written")
			assert.Equal(t, before, listing(t, files.dir))
		})
	}
}

// m-F of the fifth review: which labels icacls can write back whole. It
// writes no-write-up only, at Low, Medium or High: anything with no-read-up
// or no-execute-up, or at a level icacls cannot set (System, Medium Plus),
// gets the conservative remedy.
func TestTheLabelRemedyNeverWeakensTheLabel(t *testing.T) {
	t.Parallel()

	const target = `C:\mtg\config.toml`

	icacls := func(level string) string {
		return `give the file its own label with icacls "` + target + `" /setintegritylevel ` + level
	}

	for label, want := range map[string]string{
		"":                    icacls("M"),
		"S:(ML;;NW;;;LW)":     icacls("L"),
		"S:AI(ML;;NW;;;ME)":   icacls("M"),
		"S:(ML;;NW;;;HI)":     icacls("H"),
		"S:(ML;;NW;;;SI)":     keepItsPolicy,
		"S:(ML;;NW;;;MP)":     keepItsPolicy,
		"S:AI(ML;;NWNR;;;ME)": keepItsPolicy,
		"S:(ML;;NWNX;;;LW)":   keepItsPolicy,
		"S:(ML;;NR;;;HI)":     keepItsPolicy,
	} {
		assert.Equal(t, want, labelRemedy(target, label), "label %q", label)
	}
}

// m-G of the fifth review: the born descriptor is the given token's -- its
// user, and its own integrity level -- not a constant: a runner at another
// level (an elevated High one) is born at its level. Shown with a Low token.
func TestTheBornDescriptorIsTheTokens(t *testing.T) {
	t.Parallel()

	low := lowIntegrityToken(t)

	level, err := integrityLevel(low)
	require.NoError(t, err)
	assert.Equal(t, "S-1-16-4096", level)

	born, err := privateDescriptor(low)
	require.NoError(t, err)

	want, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;" + currentUser(t) + ")S:(ML;;NWNRNX;;;LW)")
	require.NoError(t, err)

	assert.Equal(t, want.String(), born.String())
}

// m-A: a config encrypted with EFS would come back in plain text, so it is
// refused, with the remedy. The decision is a function of the attribute
// word; real EFS is not tried here.
func TestAnEncryptedConfigIsRefused(t *testing.T) {
	t.Parallel()

	const target = `C:\mtg\config.toml`

	for _, tc := range []struct {
		attributes uint32
		refused    bool
	}{
		{attributes: 0},
		{attributes: windows.FILE_ATTRIBUTE_NORMAL},
		{attributes: windows.FILE_ATTRIBUTE_ARCHIVE | windows.FILE_ATTRIBUTE_HIDDEN | windows.FILE_ATTRIBUTE_COMPRESSED},
		{attributes: windows.FILE_ATTRIBUTE_ENCRYPTED, refused: true},
		{attributes: windows.FILE_ATTRIBUTE_ENCRYPTED | windows.FILE_ATTRIBUTE_ARCHIVE | windows.FILE_ATTRIBUTE_READONLY, refused: true},
	} {
		err := encryptedRefusal(target, tc.attributes)

		if !tc.refused {
			assert.NoError(t, err, "attributes %#x", tc.attributes)

			continue
		}

		require.Error(t, err, "attributes %#x", tc.attributes)
		assert.Equal(t, `rotate-secret cannot keep a file encrypted with EFS; decrypt it with cipher /d "`+target+
			`", rotate, and encrypt it again with cipher /e "`+target+`"`, err.Error())
	}
}

// m-A: the run consults the attributes, before anything is made.
func TestTheRunRefusesAnEncryptedConfig(t *testing.T) {
	files := newRotateFiles(t)
	before := listing(t, files.dir)

	original := attributesOf

	t.Cleanup(func() { attributesOf = original })

	attributesOf = func(info fs.FileInfo) uint32 { return original(info) | windows.FILE_ATTRIBUTE_ENCRYPTED }

	res := runRotate(t, RotateSecret{ConfigPath: files.path, Name: "alice", Overlap: "24h"})
	require.Empty(t, retiringLeaks(res.printed(), files.old()...), "the refusal carries an old value")
	require.Error(t, res.err)

	assert.Contains(t, res.err.Error(), "rotate-secret cannot keep a file encrypted with EFS")
	assert.Contains(t, res.err.Error(), "nothing was written")
	assert.Equal(t, before, listing(t, files.dir))
}

// m-B of the third review: a legacy list -- unprotected, no auto-inherited
// flag, as SetFileSecurity, cacls or old migrations leave it -- rotates with
// the same entries, where it was falsely refused. Windows' own high-level
// reading reports it protected; the new file is stored so, with identical
// access.
func TestALegacyListRotates(t *testing.T) {
	t.Parallel()

	files := newRotateFiles(t)
	setRaw(t, files.path, "D:(A;;FA;;;"+currentUser(t)+")(A;;FR;;;BG)")

	before := daclOf(t, files.path)
	require.Contains(t, before, "(A;;FR;;;BG)")

	res := runRotate(t, RotateSecret{ConfigPath: files.path, Name: "alice", Overlap: "24h"})
	require.Empty(t, retiringLeaks(res.printed(), files.old()...), "a message carries an old value")
	require.NoError(t, res.err, "a legacy list is refused")

	assert.Equal(t, acesOf(before), acesOf(daclOf(t, files.path)), "the entries changed")
	assert.Equal(t, []string{"config.toml"}, names(listing(t, files.dir)))
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
