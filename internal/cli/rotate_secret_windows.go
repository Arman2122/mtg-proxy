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

// keepDACL copies the target's DACL onto tmp, protected or not as the target's
// is. A list of inherited entries only needs nothing: the temporary file sits
// in the same directory and inherits the same. A failure is a refusal, as the
// owner is on Unix.
func keepDACL(tmp, target string) error {
	sd, err := windows.GetNamedSecurityInfo(target, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("cannot read the access control list of %s: %w", target, err)
	}

	defer runtime.KeepAlive(sd)

	control, _, err := sd.Control()
	if err != nil {
		return fmt.Errorf("cannot read the access control list of %s: %w", target, err)
	}

	dacl, _, err := sd.DACL()

	switch {
	case errors.Is(err, windows.ERROR_OBJECT_NOT_FOUND) || (err == nil && dacl == nil):
		// No DACL, or a null one: everyone may do everything. The inherited
		// list is narrower, which errs the safe way.
		return nil
	case err != nil:
		return fmt.Errorf("cannot read the access control list of %s: %w", target, err)
	}

	protected := control&windows.SE_DACL_PROTECTED != 0

	explicit, err := hasExplicitACE(dacl)
	if err != nil {
		return fmt.Errorf("cannot read the access control list of %s: %w", target, err)
	}

	if !protected && !explicit {
		return nil
	}

	flags := windows.SECURITY_INFORMATION(windows.DACL_SECURITY_INFORMATION | windows.UNPROTECTED_DACL_SECURITY_INFORMATION)
	if protected {
		flags = windows.DACL_SECURITY_INFORMATION | windows.PROTECTED_DACL_SECURITY_INFORMATION
	}

	if err := setNamedSecurityInfo(tmp, windows.SE_FILE_OBJECT, flags, nil, nil, dacl, nil); err != nil {
		return fmt.Errorf("cannot give the new file the access control list of %s: %w; "+
			"run as a user who may change the file's permissions, or as an administrator", target, err)
	}

	return nil
}

// setNamedSecurityInfo is windows.SetNamedSecurityInfo, a variable so that a
// test can make it fail.
var setNamedSecurityInfo = windows.SetNamedSecurityInfo

// hasExplicitACE reports whether any entry of dacl was set on the file
// itself rather than inherited.
func hasExplicitACE(dacl *windows.ACL) (bool, error) {
	for i := range uint32(dacl.AceCount) {
		var ace *windows.ACCESS_ALLOWED_ACE

		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return false, err
		}

		if ace.Header.AceFlags&windows.INHERITED_ACE == 0 {
			return true, nil
		}
	}

	return false, nil
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
// holds open without sharing its deletion cannot be replaced.
func renameHint(err error) string {
	if errors.Is(err, windows.ERROR_SHARING_VIOLATION) || errors.Is(err, windows.ERROR_ACCESS_DENIED) ||
		errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
		return " (is the file open in another program?)"
	}

	return ""
}

// pipeSignals is empty on Windows, which has no SIGPIPE: a write to a closed
// pipe fails with an error there already.
func pipeSignals() []os.Signal { return nil }

// syncDirectory does nothing on Windows, which cannot open a directory to
// fsync it; the rename is the platform's own.
func syncDirectory(string) error { return nil }
