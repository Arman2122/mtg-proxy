package cli

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"
)

// How rotate-secret writes the config file (spec §7.4, D24). The only write
// path is an atomic one: a new file beside the target, renamed over it. The
// old inode is never written through, and no copy of the old file is ever
// made -- a backup would be a second file holding every secret with the leaked
// key as the primary (M3 of the review), and restoring it would revive that
// key. A temporary file is removed on every failure before the rename, and a
// removal that fails is said; only a crash can leave one behind unsaid.

// tempFile is what the run writes the new file through: an *os.File, behind
// an interface so that a test can make each step fail.
type tempFile interface {
	io.Writer
	Chmod(mode fs.FileMode) error
	Chown(uid, gid int) error
	Stat() (fs.FileInfo, error)
	Sync() error
	Close() error
}

// createTemp creates the temporary file exclusively, so that no one else can
// open it while it is written: 0600 on Unix, shared with no one on Windows
// (openTemp). A variable so that a test can see how it is created, and hand
// back a file whose write, sync or close fails.
var createTemp = openTemp

// removeTemp removes the temporary file after a failure: os.Remove, a
// variable so that a test can make it fail.
var removeTemp = os.Remove

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
// can be opened for writing, and (on Windows) one this user can replace. A
// read-only config is a statement, so this holds even where a rename would
// succeed. The file is closed at once: an open handle would stop the rename
// on Windows.
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
		return nil, notWritable(err)
	}

	if err := file.Close(); err != nil {
		return nil, notWritable(err)
	}

	if err := checkReplaceable(target); err != nil {
		return nil, err
	}

	return info, nil
}

// notWritable is the refusal for a file that cannot be opened for writing,
// with mountHint's remedy for a read-only file system.
func notWritable(err error) error {
	return fmt.Errorf("the config file is not writable: %w%s", err, mountHint(err))
}

// cannotTakeAFile is the refusal for a directory in which the lock cannot be
// created, with mountHint's remedy for a read-only file system: a writable
// single-file mount in a read-only container (docker run --read-only).
func cannotTakeAFile(err error) error {
	return fmt.Errorf("the config's directory cannot take a new file: %w%s", err, mountHint(err))
}

// mountHint is §7.4's remedy for a read-only file system, which is most often
// a container's: a single-file bind mount with :ro, or a read-only container
// around a writable file.
func mountHint(err error) string {
	if errors.Is(err, syscall.EROFS) {
		return " (a read-only mount? run rotate-secret on the host, and mount the config's directory into the container)"
	}

	return ""
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
		return "", lockHeld(target, lock, now)
	case err != nil:
		return "", cannotTakeAFile(err)
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
// modification time, which is its creation: the file is written once. A
// temporary file beside the target is named too: a run that held the lock and
// died -- killed, or stopped by a second interrupt -- left it, and it holds
// every secret of the config. A run still at work has one for milliseconds,
// hence the condition; deleting that one is harmless, as its rename then
// fails and nothing is written.
func lockHeld(target, lock string, now time.Time) error {
	age := "an unknown time"

	if info, err := os.Stat(lock); err == nil {
		age = max(now.Sub(info.ModTime()).Round(time.Second), 0).String()
	}

	var leftovers strings.Builder

	for _, tmp := range leftoverTemps(target) {
		fmt.Fprintf(&leftovers, "; if no rotate-secret is running, %s was left by a crashed run "+
			"and holds the config's secrets: delete it", tmp)
	}

	return fmt.Errorf("another rotate-secret holds %s (started %s ago); if none is running, remove it and retry%s",
		lock, age, leftovers.String())
}

// leftoverTemps are the temporary files beside target, by the name the run
// gives them, in order.
func leftoverTemps(target string) []string {
	entries, err := os.ReadDir(filepath.Dir(target))
	if err != nil {
		return nil
	}

	prefix := filepath.Base(target) + tempInfix

	var found []string

	for _, entry := range entries {
		random, ok := strings.CutPrefix(entry.Name(), prefix)
		if !ok {
			continue
		}

		random, ok = strings.CutSuffix(random, tempSuffix)
		if _, err := hex.DecodeString(random); ok && err == nil && len(random) == 8 {
			found = append(found, filepath.Join(filepath.Dir(target), entry.Name()))
		}
	}

	slices.Sort(found)

	return found
}

// writeAtomically is §7.4 steps 4 and 5: a temporary file beside the target,
// created 0600 and given the target's permissions -- on Unix its owner, then
// its mode bits; on Windows its access control list -- before a byte of the
// new file is in it; then written, synced and closed. Just before the rename,
// beforeRename may stop the run (an interrupt), and the target is read again:
// if it no longer hashes to readSum -- another writer, an editor or the panel,
// changed it since the run read it -- nothing is replaced. Otherwise the
// temporary file is renamed over it. Any failure removes the temporary file,
// and a removal that fails is added to the error.
func writeAtomically(target string, info fs.FileInfo, data []byte, readSum [sha256.Size]byte,
	beforeRename func() error,
) (err error) {
	tmp, err := tempPath(target)
	if err != nil {
		return err
	}

	file, err := createTemp(tmp)
	if err != nil {
		return fmt.Errorf("cannot create the temporary file %s: %w", tmp, err)
	}

	closed, renamed := false, false

	// Closed first: Windows cannot remove an open file.
	defer func() {
		if !closed {
			file.Close() //nolint: errcheck // a failure is already being returned
		}

		if renamed {
			return
		}

		if rmErr := removeTemp(tmp); rmErr != nil && !errors.Is(rmErr, fs.ErrNotExist) {
			err = errors.Join(err, fmt.Errorf("the temporary file %s could not be removed (%w): "+
				"delete it (it holds the config's secrets)", tmp, rmErr))
		}
	}()

	if err := keepPermissions(file, tmp, target, info); err != nil {
		return err
	}

	if _, err := file.Write(data); err != nil {
		return fmt.Errorf("cannot write the temporary file %s: %w", tmp, err)
	}

	if err := file.Sync(); err != nil {
		return fmt.Errorf("cannot sync the temporary file %s: %w", tmp, err)
	}

	closed = true

	if err := file.Close(); err != nil {
		return fmt.Errorf("cannot close the temporary file %s: %w", tmp, err)
	}

	if err := beforeRename(); err != nil {
		return err
	}

	current, err := os.ReadFile(target)
	if err != nil {
		return fmt.Errorf("cannot read %s again before replacing it: %w", target, err)
	}

	if sum := sha256.Sum256(current); !bytes.Equal(sum[:], readSum[:]) {
		return errFileChanged
	}

	if err := renameFile(tmp, target); err != nil {
		return replaceRefusal(target, err)
	}

	renamed = true

	return nil
}

// replaceRefusal is a failed rename in words: a mount point (EBUSY, EXDEV) is
// §7.4's message; anything else is the error itself, with the platform's hint
// (on Windows, a file another program holds open).
func replaceRefusal(target string, err error) error {
	if errors.Is(err, syscall.EBUSY) || errors.Is(err, syscall.EXDEV) {
		return fmt.Errorf("cannot replace %s: it is a mount point (a single-file bind mount?); "+
			"run rotate-secret on the host, and mount the config's directory into the container", target)
	}

	// The paths are in the message already.
	if linkErr := (*os.LinkError)(nil); errors.As(err, &linkErr) {
		err = linkErr.Err
	}

	return fmt.Errorf("cannot replace %s: %w%s", target, err, renameHint(err))
}

// tempPath is <target>.rotate-<8 random hex>.tmp, beside the target.
func tempPath(target string) (string, error) {
	var random [4]byte

	if _, err := rand.Read(random[:]); err != nil {
		return "", fmt.Errorf("cannot name the temporary file: %w", err)
	}

	return target + tempInfix + hex.EncodeToString(random[:]) + tempSuffix, nil
}
