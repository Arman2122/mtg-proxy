//go:build windows

package cli

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"runtime"

	"golang.org/x/sys/windows"
)

// openTemp creates the temporary file shared with no one (I-A of the second
// review). Windows checks access when a handle is opened, and a list narrowed
// afterwards does not take back a handle opened under the directory's
// inherited one: a reader that opened the file in that moment would read the
// whole new config after the rename. With no sharing, no handle with data
// access can be opened on it until it is closed -- by then its list is the
// target's. The calls that copy the list open it for READ_CONTROL and
// WRITE_DAC only, which sharing does not govern. CREATE_NEW is O_EXCL, and
// the handle is not inherited by child processes, as Go's are not.
func openTemp(path string) (tempFile, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}

	handle, err := windows.CreateFile(name, windows.GENERIC_WRITE|windows.FILE_READ_ATTRIBUTES, 0, nil,
		windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}

	return os.NewFile(uintptr(handle), path), nil
}

// checkReplaceable refuses, before anything is created, a config this user
// could not replace: the rename needs to delete it, through its own list or
// the directory's. The temporary file gets the same list in the same
// directory, so this is also what keeps it deletable on every failure path.
// A config another program holds open without sharing its deletion is
// refused here too.
func checkReplaceable(target string) error {
	name, err := windows.UTF16PtrFromString(target)
	if err != nil {
		return replaceRefusal(target, err)
	}

	handle, err := windows.CreateFile(name, windows.DELETE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		return replaceRefusal(target, err)
	}

	windows.CloseHandle(handle) //nolint: errcheck // a handle with no data access

	return nil
}

// keepPermissions gives the temporary file the target's read-only attribute
// (all a mode is on Windows) and its access control list, before a byte of the
// new file is in it (§7.4 step 5; R5 and §11: the file's own permissions are
// preserved). A new file inherits its directory's list; a config whose own
// list was narrowed -- protected, or with an explicit entry such as a deny --
// would otherwise come back readable by whoever the directory grants.
//
// The list is copied onto the temporary file, which is then renamed as on
// Unix. ReplaceFileW, which keeps the replaced file's list itself, is not
// used: without a backup name its documented failure
// (ERROR_UNABLE_TO_MOVE_REPLACEMENT) leaves the replaced file deleted, and
// with one it makes the copy of the old file §7.4 forbids. The owner is not
// copied: setting another owner takes a privilege, and the owner's implicit
// rights are not what keeps the file private.
func keepPermissions(file tempFile, tmp, target string, info fs.FileInfo) error {
	if err := file.Chmod(info.Mode().Perm()); err != nil {
		return fmt.Errorf("cannot give the temporary file the permissions of %s: %w", target, err)
	}

	return keepDACL(tmp, target)
}

// keepDACL copies the target's DACL onto tmp exactly: its entries as they
// are, the inherited ones included, and protected or not as it is. The
// low-level SetKernelObjectSecurity does that; the high-level
// SetNamedSecurityInfo would recompute the inherited entries from this
// directory, which differ for a config moved here from another one, or one
// created by another user under a CREATOR OWNER or CREATOR GROUP entry. The
// temporary file's list is then read back and must be the target's, so any
// other outcome is a refusal, never a wider file. A failure is a refusal, as
// the owner is on Unix. A config with no list, or a null one -- open to all,
// as on a FAT volume -- has nothing to keep.
func keepDACL(tmp, target string) error {
	sd, err := windows.GetNamedSecurityInfo(target, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("cannot read the access control list of %s: %w", target, err)
	}

	defer runtime.KeepAlive(sd)

	dacl, _, err := sd.DACL()

	switch {
	case errors.Is(err, windows.ERROR_OBJECT_NOT_FOUND) || (err == nil && dacl == nil):
		return nil
	case err != nil:
		return fmt.Errorf("cannot read the access control list of %s: %w", target, err)
	}

	want := sd.String()

	control, _, err := sd.Control()
	if err != nil {
		return fmt.Errorf("cannot read the access control list of %s: %w", target, err)
	}

	// Without the request the copy loses the auto-inherited flag.
	if control&windows.SE_DACL_AUTO_INHERITED != 0 {
		if err := sd.SetControl(windows.SE_DACL_AUTO_INHERIT_REQ, windows.SE_DACL_AUTO_INHERIT_REQ); err != nil {
			return fmt.Errorf("cannot read the access control list of %s: %w", target, err)
		}
	}

	if err := setDACL(tmp, sd); err != nil {
		return fmt.Errorf("cannot give the new file the access control list of %s: %w; "+
			"run as a user who may change the file's permissions, or as an administrator", target, err)
	}

	return sameDACL(tmp, target, want)
}

// setKernelObjectSecurity is windows.SetKernelObjectSecurity, a variable so
// that a test can make the copy fail, or come out different.
var setKernelObjectSecurity = windows.SetKernelObjectSecurity

// setDACL sets sd's DACL on tmp through a handle of its own that asks for
// READ_CONTROL and WRITE_DAC only: the owner always has them, and sharing
// does not govern them, so the exclusive handle the file is written through
// does not stand in the way.
func setDACL(tmp string, sd *windows.SECURITY_DESCRIPTOR) error {
	name, err := windows.UTF16PtrFromString(tmp)
	if err != nil {
		return err //nolint: wrapcheck // worded by the caller
	}

	handle, err := windows.CreateFile(name, windows.READ_CONTROL|windows.WRITE_DAC,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		return err //nolint: wrapcheck // worded by the caller
	}

	defer windows.CloseHandle(handle) //nolint: errcheck // a handle with no data access

	return setKernelObjectSecurity(handle, windows.DACL_SECURITY_INFORMATION, sd)
}

// sameDACL reads the temporary file's DACL back and refuses unless its SDDL
// is want, the target's, byte for byte. The message says what is known --
// the copy came out different -- and the remedy that gives the file the
// simplest list to copy, its own entries, protected.
func sameDACL(tmp, target, want string) error {
	got, err := windows.GetNamedSecurityInfo(tmp, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("cannot read the access control list of the temporary file beside %s: %w", target, err)
	}

	if want == "" || got.String() != want {
		return fmt.Errorf("the new file would not get the access control list of %s: the copy differs from the original; "+
			`give the file a list of its own with icacls "%s" /inheritance:d, and retry`, target, target)
	}

	return nil
}

// linkCount is the number of names the target has: a hard-linked config keeps
// the old file under its other names. 0 when it cannot be read.
func linkCount(target string, _ fs.FileInfo) uint64 {
	name, err := windows.UTF16PtrFromString(target)
	if err != nil {
		return 0
	}

	handle, err := windows.CreateFile(name, windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return 0
	}

	defer windows.CloseHandle(handle) //nolint: errcheck // a read-only handle

	var data windows.ByHandleFileInformation

	if err := windows.GetFileInformationByHandle(handle, &data); err != nil {
		return 0
	}

	return uint64(data.NumberOfLinks)
}

// renameHint is what a rename refused by Windows adds: a file another program
// holds open without sharing its deletion cannot be replaced, and Windows
// says "Access is denied." for that as for a user who may not replace it.
func renameHint(err error) string {
	if errors.Is(err, windows.ERROR_SHARING_VIOLATION) || errors.Is(err, windows.ERROR_ACCESS_DENIED) ||
		errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
		return " (is the file open in another program, or may this user not replace it?)"
	}

	return ""
}

// pipeSignals is empty on Windows, which has no SIGPIPE: a write to a closed
// pipe fails with an error there already.
func pipeSignals() []os.Signal { return nil }

// syncDirectory does nothing on Windows, which cannot open a directory to
// fsync it; the rename is the platform's own.
func syncDirectory(string) error { return nil }
