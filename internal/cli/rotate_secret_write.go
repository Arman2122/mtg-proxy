package cli

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"syscall"
	"time"
)

// How rotate-secret writes the config file (spec §7.4, D24). The only write
// path is an atomic one: a new file beside the target, renamed over it. The
// old inode is never written through, and no copy of the old file is ever
// made -- a backup would be a second file holding every secret with the leaked
// key as the primary (M3 of the review), and restoring it would revive that
// key. A temporary file is removed on every failure before the rename; only a
// crash can leave one behind.

// renameFile replaces the target with the written temporary file: os.Rename,
// a variable so that a test can make it fail as a mount point does.
var renameFile = os.Rename

// syncDir makes the rename durable: an fsync of the directory on Unix,
// nothing on Windows, which cannot open a directory for it. A variable so
// that a test can see it is called, after the rename.
var syncDir = syncDirectory

// errFileChanged is the optimistic check against another writer (§7.4 step 4).
var errFileChanged = errors.New("the file changed while rotating; nothing was written")

// lockSuffix and tempInfix name the files the run puts beside the target:
// <target>.rotate.lock and <target>.rotate-<8 random hex>.tmp.
const (
	lockSuffix = ".rotate.lock"
	tempInfix  = ".rotate-"
	tempSuffix = ".tmp"
)

// checkWritable is §7.4 step 2 for the file: it must be a regular file that
// can be opened for writing. A read-only config is a statement, so this holds
// even where a rename would succeed. The file is closed at once: an open
// handle would stop the rename on Windows.
func checkWritable(target string) (fs.FileInfo, error) {
	info, err := os.Stat(target)
	if err != nil {
		return nil, fmt.Errorf("cannot read %s: %w", target, err)
	}

	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", target)
	}

	file, err := os.OpenFile(target, os.O_WRONLY, 0)
	if err != nil {
		return nil, fmt.Errorf("the config file is not writable: %w", err)
	}

	if err := file.Close(); err != nil {
		return nil, fmt.Errorf("the config file is not writable: %w", err)
	}

	return info, nil
}

// takeLock is §7.4 step 3: <target>.rotate.lock, created with O_EXCL, holding
// the pid and the start time. A lock that exists is refused with its age and
// the remedy, and never broken here: only a person knows that no run holds
// it. Any other failure to create it is a directory that cannot take a new
// file (§7.4 step 2's other half). The caller removes the lock it got.
func takeLock(target string, now time.Time) (string, error) {
	lock := target + lockSuffix

	file, err := os.OpenFile(lock, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)

	switch {
	case errors.Is(err, fs.ErrExist):
		return "", lockHeld(lock, now)
	case err != nil:
		return "", fmt.Errorf("the config's directory cannot take a new file: %w", err)
	}

	_, writeErr := fmt.Fprintf(file, "pid %d\nstarted %s\n", os.Getpid(), now.UTC().Format(time.RFC3339))
	closeErr := file.Close()

	if err := errors.Join(writeErr, closeErr); err != nil {
		os.Remove(lock) //nolint: errcheck // the lock is ours, and empty or partly written

		return "", fmt.Errorf("cannot write the lock %s: %w", lock, err)
	}

	return lock, nil
}

// lockHeld is the refusal for a lock that exists. Its age is from its own
// modification time, which is its creation: the file is written once.
func lockHeld(lock string, now time.Time) error {
	age := "an unknown time"

	if info, err := os.Stat(lock); err == nil {
		age = max(now.Sub(info.ModTime()).Round(time.Second), 0).String()
	}

	return fmt.Errorf("another rotate-secret holds %s (started %s ago); if none is running, remove it and retry",
		lock, age)
}

// writeAtomically is §7.4 steps 4 and 5: a temporary file beside the target,
// created 0600, written, given the target's permission bits and (on Unix) its
// owner, synced and closed; then the target is read again, and if it no
// longer hashes to readSum -- another writer, an editor or the panel, changed
// it since the run read it -- nothing is replaced; otherwise the temporary
// file is renamed over it. Any failure removes the temporary file.
func writeAtomically(target string, info fs.FileInfo, data []byte, readSum [sha256.Size]byte) error {
	tmp, err := tempPath(target)
	if err != nil {
		return err
	}

	file, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("cannot create the temporary file %s: %w", tmp, err)
	}

	closed, renamed := false, false

	// Closed first: Windows cannot remove an open file.
	defer func() {
		if !closed {
			file.Close() //nolint: errcheck // a failure is already being returned
		}

		if !renamed {
			os.Remove(tmp) //nolint: errcheck // nothing more can be done about it
		}
	}()

	if _, err := file.Write(data); err != nil {
		return fmt.Errorf("cannot write the temporary file %s: %w", tmp, err)
	}

	if err := file.Chmod(info.Mode().Perm()); err != nil {
		return fmt.Errorf("cannot give the temporary file %s the permissions of %s: %w", tmp, target, err)
	}

	if err := keepOwner(file, target, info); err != nil {
		return err
	}

	// After the mode and the owner, so that they are durable too.
	if err := file.Sync(); err != nil {
		return fmt.Errorf("cannot sync the temporary file %s: %w", tmp, err)
	}

	closed = true

	if err := file.Close(); err != nil {
		return fmt.Errorf("cannot close the temporary file %s: %w", tmp, err)
	}

	current, err := os.ReadFile(target)
	if err != nil {
		return fmt.Errorf("cannot read %s again before replacing it: %w", target, err)
	}

	if sum := sha256.Sum256(current); !bytes.Equal(sum[:], readSum[:]) {
		return errFileChanged
	}

	if err := renameFile(tmp, target); err != nil {
		if errors.Is(err, syscall.EBUSY) || errors.Is(err, syscall.EXDEV) {
			return fmt.Errorf("cannot replace %s: it is a mount point (a single-file bind mount?); "+
				"run rotate-secret on the host, and mount the config's directory into the container", target)
		}

		// The paths are in the message already.
		if linkErr := (*os.LinkError)(nil); errors.As(err, &linkErr) {
			err = linkErr.Err
		}

		return fmt.Errorf("cannot replace %s: %w", target, err)
	}

	renamed = true

	return nil
}

// tempPath is <target>.rotate-<8 random hex>.tmp, beside the target.
func tempPath(target string) (string, error) {
	var random [4]byte

	if _, err := rand.Read(random[:]); err != nil {
		return "", fmt.Errorf("cannot name the temporary file: %w", err)
	}

	return target + tempInfix + hex.EncodeToString(random[:]) + tempSuffix, nil
}
