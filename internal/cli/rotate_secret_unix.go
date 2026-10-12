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

// chownFile gives the temporary file an owner: (*os.File).Chown, a variable
// so that a test can make it fail as it does for a user who is neither the
// file's owner nor root.
var chownFile = func(file *os.File, uid, gid int) error { return file.Chown(uid, gid) }

// keepOwner gives the temporary file the target's owner and group when they
// differ from its own (§7.4 step 5). It cannot be skipped: a root-owned 0640
// file whose group is the proxy's would otherwise come back owned by whoever
// ran the command, and unreadable to a proxy running as mtg-proxy.
func keepOwner(file *os.File, target string, info fs.FileInfo) error {
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

	// A 32-bit int cannot hold every uid, and Chown reads -1 as "unchanged".
	if uint64(want.Uid) > math.MaxInt32 || uint64(want.Gid) > math.MaxInt32 {
		return fmt.Errorf("cannot give the new file the owner of %s (uid %d, gid %d); run as the file's owner or root",
			target, want.Uid, want.Gid)
	}

	if err := chownFile(file, int(want.Uid), int(want.Gid)); err != nil {
		return fmt.Errorf("cannot give the new file the owner of %s (uid %d, gid %d): %w; run as the file's owner or root",
			target, want.Uid, want.Gid, err)
	}

	return nil
}

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
