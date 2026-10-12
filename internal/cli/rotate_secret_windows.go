//go:build windows

package cli

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"runtime"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// openTemp creates the temporary file born private and shared with no one,
// the Windows analogue of 0600:
//
//   - Its list is protected and grants the runner alone (the token's user, not
//     its default owner, which for an elevated token is Administrators) full
//     control (I-B of the third review). Windows checks access when a handle
//     is opened, and a list narrowed afterwards does not take back a handle
//     opened under a wider one; born with the directory's inherited list, the
//     file would admit, for a moment, a handle with WRITE_DAC or WRITE_OWNER
//     -- rights no sharing mode refuses -- through which the config's list
//     could be rewritten after the rename.
//   - Share mode 0 (I-A of the second review): no handle with data access can
//     be opened on it while it is written.
//
// The runner's full control also keeps the file deletable on every failure
// path until the config's list is copied on. CREATE_NEW is O_EXCL, and the
// handle is not inherited by child processes, as Go's are not. On a file
// system with no security (FAT) the list is ignored.
func openTemp(path string) (tempFile, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}

	private, err := privateDescriptor()
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}

	attributes := windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: private,
	}

	handle, err := windows.CreateFile(name, windows.GENERIC_WRITE|windows.FILE_READ_ATTRIBUTES, 0, &attributes,
		windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)

	runtime.KeepAlive(private)

	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}

	return os.NewFile(uintptr(handle), path), nil
}

// privateDescriptor is a protected list granting the process token's user
// full control, and no one else anything.
func privateDescriptor() (*windows.SECURITY_DESCRIPTOR, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, err //nolint: wrapcheck // worded by the caller
	}

	return windows.SecurityDescriptorFromString("D:P(A;;FA;;;" + user.User.Sid.String() + ")") //nolint: wrapcheck
}

// checkReplaceable refuses, before anything is created:
//   - a config encrypted with EFS, which the new file would not be (it would
//     come back in plain text);
//   - a config this user could not replace: the rename needs to delete it,
//     through its own list or the directory's. The temporary file gets the
//     same list in the same directory, so this is also what keeps it
//     deletable after the list is copied on. A config another program holds
//     open without sharing its deletion is refused here too.
func checkReplaceable(target string, info fs.FileInfo) error {
	if err := encryptedRefusal(target, attributesOf(info)); err != nil {
		return err
	}

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

// attributesOf is the target's Windows file attributes: a variable so that a
// test can mark a config encrypted, which this machine cannot do for real.
var attributesOf = func(info fs.FileInfo) uint32 {
	if data, ok := info.Sys().(*syscall.Win32FileAttributeData); ok {
		return data.FileAttributes
	}

	return 0
}

// encryptedRefusal is the refusal for a config encrypted with EFS, judged on
// its attribute word. The new file is created in the config's directory,
// which need not encrypt new files, so it would come back readable at rest.
func encryptedRefusal(target string, attributes uint32) error {
	if attributes&windows.FILE_ATTRIBUTE_ENCRYPTED == 0 {
		return nil
	}

	return fmt.Errorf(`rotate-secret cannot keep a file encrypted with EFS; decrypt it with cipher /d "%s", `+
		"rotate, and encrypt it again", target)
}

// keepPermissions gives the temporary file the target's read-only attribute
// (all a mode is on Windows), its access control list and its mandatory
// label, before a byte of the new file is in it (§7.4 step 5; R5 and §11:
// the file's own permissions are preserved). A config whose own list was
// narrowed -- protected, or with an explicit entry such as a deny -- or that
// keeps low-integrity processes out with a label, would otherwise come back
// readable by whoever the directory grants.
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

	return keepSecurity(tmp, target)
}

// keepSecurity copies the target's DACL, and its mandatory label when it has
// one, onto tmp exactly: the entries as they are, the inherited ones
// included, and protected or not as the target's are. The low-level
// SetKernelObjectSecurity does that; the high-level SetNamedSecurityInfo
// would recompute the inherited entries from this directory, which differ for
// a config moved here from another one, or one created by another user under
// a CREATOR OWNER or CREATOR GROUP entry. A NULL DACL -- open to everyone --
// is copied too: it is the config's own exposure, and turning it owner-only
// could lock out the account the proxy runs as. The temporary file's
// security is then read back and must be the target's, so any other outcome
// is a refusal, never a wider file. A failure is a refusal, as the owner is
// on Unix. A file system with no security at all (FAT) has nothing to keep.
//
// The descriptor GetNamedSecurityInfo returns is a copy on the Go heap; it is
// passed whole to the system calls below, which keeps it alive for them.
func keepSecurity(tmp, target string) error {
	sd, err := windows.GetNamedSecurityInfo(target, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.LABEL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("cannot read the access control list of %s: %w", target, err)
	}

	if sd == nil {
		return nil
	}

	if _, _, err := sd.DACL(); errors.Is(err, windows.ERROR_OBJECT_NOT_FOUND) {
		return nil
	} else if err != nil {
		return fmt.Errorf("cannot read the access control list of %s: %w", target, err)
	}

	want := sd.String()

	control, _, err := sd.Control()
	if err != nil {
		return fmt.Errorf("cannot read the access control list of %s: %w", target, err)
	}

	// Without the requests the copy loses the auto-inherited flags.
	var requests windows.SECURITY_DESCRIPTOR_CONTROL

	if control&windows.SE_DACL_AUTO_INHERITED != 0 {
		requests |= windows.SE_DACL_AUTO_INHERIT_REQ
	}

	if control&windows.SE_SACL_AUTO_INHERITED != 0 {
		requests |= windows.SE_SACL_AUTO_INHERIT_REQ
	}

	if requests != 0 {
		if err := sd.SetControl(requests, requests); err != nil {
			return fmt.Errorf("cannot read the access control list of %s: %w", target, err)
		}
	}

	if err := setSecurity(tmp, target, sd, hasLabel(sd)); err != nil {
		return err
	}

	return sameSecurity(tmp, target, want)
}

// hasLabel reports whether sd carries a mandatory label.
func hasLabel(sd *windows.SECURITY_DESCRIPTOR) bool {
	sacl, _, err := sd.SACL()

	return err == nil && sacl != nil && sacl.AceCount > 0
}

// setKernelObjectSecurity is windows.SetKernelObjectSecurity, a variable so
// that a test can make the copy fail, or come out different.
var setKernelObjectSecurity = windows.SetKernelObjectSecurity

// setSecurity sets sd's DACL, and its label when label is true, on tmp through
// a handle of its own that asks for READ_CONTROL, WRITE_DAC and (for the
// label) WRITE_OWNER: the born-private list grants them to the runner, and
// sharing does not govern them, so the exclusive handle the file is written
// through does not stand in the way. Rights granted when a handle is opened
// stay with it, so the label is set whatever the copied list says.
func setSecurity(tmp, target string, sd *windows.SECURITY_DESCRIPTOR, label bool) error {
	access := uint32(windows.READ_CONTROL | windows.WRITE_DAC)
	if label {
		access |= windows.WRITE_OWNER
	}

	name, err := windows.UTF16PtrFromString(tmp)
	if err != nil {
		return aclRefusal(target, err)
	}

	handle, err := windows.CreateFile(name, access,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		return aclRefusal(target, err)
	}

	defer windows.CloseHandle(handle) //nolint: errcheck // a handle with no data access

	if err := setKernelObjectSecurity(handle, windows.DACL_SECURITY_INFORMATION, sd); err != nil {
		return aclRefusal(target, err)
	}

	if !label {
		return nil
	}

	if err := setKernelObjectSecurity(handle, windows.LABEL_SECURITY_INFORMATION, sd); err != nil {
		return fmt.Errorf("cannot give the new file the integrity label of %s: %w; run at an integrity level "+
			"that may set it (an elevated prompt for a High label), or remove the label, and retry", target, err)
	}

	return nil
}

// aclRefusal is a list that cannot be given to the new file.
func aclRefusal(target string, err error) error {
	return fmt.Errorf("cannot give the new file the access control list of %s: %w; "+
		"run as a user who may change the file's permissions, or as an administrator", target, err)
}

// sameSecurity reads the temporary file's DACL and label back and refuses
// unless they are want's, the target's. The DACL is compared as its "D:"
// part only: for a legacy list -- unprotected, without the auto-inherited
// flag -- the high-level reading of the target adds an owner and a group that
// were not asked for and reports the list protected, and the new file is
// stored protected, "D:P(...)" where the original was "D:(...)", with
// identical access. The label ("S:") must be the same too. The message says
// what is known -- the copy came out different -- and the remedy that gives
// the file the simplest list to copy: its own entries, protected.
func sameSecurity(tmp, target, want string) error {
	got, err := windows.GetNamedSecurityInfo(tmp, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.LABEL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("cannot read the access control list of the temporary file beside %s: %w", target, err)
	}

	wantDACL, wantLabel := sddlParts(want)

	gotDACL, gotLabel := "", ""
	if got != nil {
		gotDACL, gotLabel = sddlParts(got.String())
	}

	if wantDACL == "" || gotDACL != wantDACL || gotLabel != wantLabel {
		return fmt.Errorf("the new file would not get the access control list of %s: the copy differs from the original; "+
			`give the file a list of its own with icacls "%s" /inheritance:d, and retry`, target, target)
	}

	return nil
}

// sddlParts is a descriptor's SDDL cut into its DACL ("D:" up to any "S:")
// and its SACL, the label ("S:" to the end); an owner or group before them
// ("O:", "G:") is left out. No SID or alias holds a colon, so the markers
// are found where they are.
func sddlParts(sddl string) (string, string) {
	label := ""

	if at := strings.Index(sddl, "S:"); at >= 0 {
		sddl, label = sddl[:at], sddl[at:]
	}

	if at := strings.Index(sddl, "D:"); at >= 0 {
		return sddl[at:], label
	}

	return "", label
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
