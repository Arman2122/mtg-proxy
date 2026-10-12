//go:build !windows

package cli

import (
	"errors"
	"fmt"
	"io/fs"
	"math"
	"os"
	"syscall"
)

// openTemp creates the temporary file 0600 and exclusively: no one but its
// owner can open it before it is given the target's owner and mode.
//
// On failure the returned interface holds a nil *os.File, which is harmless:
// the caller checks the error first and never uses the file then.
func openTemp(path string) (tempFile, error) {
	return os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
}

// checkReplaceable has nothing to check on Unix: a rename needs the
// directory's write permission, which the lock's creation proves.
func checkReplaceable(string) error { return nil }

// chownFile gives the temporary file an owner: its Chown, a variable so that a
// test can make it fail as it does for a user who is neither the file's owner
// nor root.
var chownFile = func(file tempFile, uid, gid int) error { return file.Chown(uid, gid) }

// keepPermissions gives the temporary file the target's owner and group, then
// its permission bits (§7.4 step 5), in that order: a chown by root may clear
// set-id bits, and the mode is the last word.
func keepPermissions(file tempFile, _, target string, info fs.FileInfo) error {
	if err := keepOwner(file, target, info); err != nil {
		return err
	}

	if err := file.Chmod(info.Mode().Perm()); err != nil {
		return fmt.Errorf("cannot give the temporary file the permissions of %s: %w", target, err)
	}

	return nil
}

// keepOwner gives the temporary file the target's owner and group when they
// differ from its own. It cannot be skipped: a root-owned 0640 file whose
// group is the proxy's would otherwise come back owned by whoever ran the
// command, and unreadable to a proxy running as mtg-proxy.
func keepOwner(file tempFile, target string, info fs.FileInfo) error {
	want, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("cannot read the owner of %s", target)
	}

	tmpInfo, err := file.Stat()
	if err != nil {
		return fmt.Errorf("cannot read the owner of the temporary file: %w", err)
	}

	have, ok := tmpInfo.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("cannot read the owner of the temporary file beside %s", target)
	}

	if have.Uid == want.Uid && have.Gid == want.Gid {
		return nil
	}

	// An int cannot hold every uid on a 32-bit system, and Chown reads -1 as
	// "unchanged"; on a 64-bit one this never holds.
	if uint64(want.Uid) > math.MaxInt || uint64(want.Gid) > math.MaxInt {
		return fmt.Errorf("cannot give the new file the owner of %s (uid %d, gid %d); "+
			"run as the file's owner, in the file's group, or as root", target, want.Uid, want.Gid)
	}

	if err := chownFile(file, int(want.Uid), int(want.Gid)); err != nil {
		return fmt.Errorf("cannot give the new file the owner of %s (uid %d, gid %d): %w; "+
			"run as the file's owner, in the file's group, or as root", target, want.Uid, want.Gid, err)
	}

	return nil
}

// linkCount is the number of names the target has: a hard-linked config keeps
// the old file under its other names. 0 when it cannot be read.
func linkCount(_ string, info fs.FileInfo) uint64 {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0
	}

	return uint64(st.Nlink) //nolint: unconvert // its width differs between systems
}

// renameHint has nothing to add on Unix: a mount point is named by
// replaceRefusal itself.
func renameHint(error) string { return "" }

// pipeSignals is SIGPIPE: notified for the duration of a run, a write to a
// closed stdout or stderr fails with EPIPE instead of killing the process,
// so the lock and the temporary file are still removed.
func pipeSignals() []os.Signal { return []os.Signal{syscall.SIGPIPE} }

// syncDirectory fsyncs dir, so that a rename in it survives a crash.
func syncDirectory(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}

	syncErr := d.Sync()
	closeErr := d.Close()

	return errors.Join(syncErr, closeErr)
}
