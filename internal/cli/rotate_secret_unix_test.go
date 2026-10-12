//go:build !windows

package cli

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The parts of R5 and R6 only a Unix system has: mode bits, the owner, a
// directory that cannot take a new file, and an old descriptor that still
// reads the old file. They run on the bench box in Task 13's session; on the
// Windows machine this was written on they do not build.

// statOf is the uid and gid of path.
func statOf(t *testing.T, path string) *syscall.Stat_t {
	t.Helper()

	info, err := os.Stat(path)
	require.NoError(t, err)

	st, ok := info.Sys().(*syscall.Stat_t)
	require.True(t, ok, "no Stat_t")

	return st
}

// R5. The file keeps its permission bits, whatever the temporary file was
// created with.
func TestTheFilesModeIsKept(t *testing.T) {
	t.Parallel()

	for _, mode := range []fs.FileMode{0o600, 0o640, 0o644, 0o660, 0o400} {
		t.Run(mode.String(), func(t *testing.T) {
			t.Parallel()

			if mode&0o200 == 0 && os.Geteuid() != 0 {
				t.Skip("only root may rotate a file its owner cannot write")
			}

			files := newRotateFiles(t)
			require.NoError(t, os.Chmod(files.path, mode))

			res := runRotate(t, RotateSecret{ConfigPath: files.path, Name: "alice", Overlap: "24h"})
			require.Empty(t, retiringLeaks(res.printed(), files.old()...), "stderr carries an old value")
			require.NoError(t, res.err)

			info, err := os.Stat(files.path)
			require.NoError(t, err)
			assert.Equal(t, mode, info.Mode().Perm())
		})
	}
}

// R5. The file keeps its owner and group. Giving another owner takes root.
func TestTheFilesOwnerIsKept(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("giving the file another owner takes root")
	}

	ids := []int{65534}

	// An id of 2^31 or more fits an int on a 64-bit system, and is kept there
	// (M-3 of the review); a 32-bit int cannot hold it, and refuses.
	if strconv.IntSize == 64 {
		var high uint64 = 1 << 31 // a variable: the constant does not fit a 32-bit int, where this does not run

		ids = append(ids, int(high))
	}

	for _, id := range ids {
		t.Run(strconv.Itoa(id), func(t *testing.T) {
			files := newRotateFiles(t)
			require.NoError(t, os.Chown(files.path, id, id))
			require.NoError(t, os.Chmod(files.path, 0o640))

			res := runRotate(t, RotateSecret{ConfigPath: files.path, Name: "alice", Overlap: "24h"})
			require.Empty(t, retiringLeaks(res.printed(), files.old()...), "stderr carries an old value")
			require.NoError(t, res.err)

			st := statOf(t, files.path)
			assert.Equal(t, uint64(id), uint64(st.Uid))
			assert.Equal(t, uint64(id), uint64(st.Gid))
			assert.Equal(t, fs.FileMode(0o640), statMode(t, files.path))
			assert.Equal(t, []string{"config.toml"}, names(listing(t, files.dir)))
		})
	}
}

// statMode is path's permission bits.
func statMode(t *testing.T, path string) fs.FileMode {
	t.Helper()

	info, err := os.Stat(path)
	require.NoError(t, err)

	return info.Mode().Perm()
}

// R5. An owner the new file cannot be given is a refusal, not a file a proxy
// running as that owner can no longer read: nothing is written, and the
// temporary file is removed.
func TestAnOwnerThatCannotBeKeptIsRefused(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("giving the file another owner takes root")
	}

	files := newRotateFiles(t)
	require.NoError(t, os.Chown(files.path, 65534, 65534))

	before := listing(t, files.dir)

	original := chownFile

	t.Cleanup(func() { chownFile = original })

	chownFile = func(tempFile, int, int) error { return syscall.EPERM }

	res := runRotate(t, RotateSecret{ConfigPath: files.path, Name: "alice", Overlap: "24h"})
	require.Empty(t, retiringLeaks(res.printed(), files.old()...), "the refusal carries an old value")
	require.Error(t, res.err)

	assert.Contains(t, res.err.Error(), "run as the file's owner, in the file's group, or as root")
	assert.Contains(t, res.err.Error(), "nothing was written")
	assert.Empty(t, res.stdout)
	assert.Equal(t, before, listing(t, files.dir))
}

// R5. A directory that cannot take a new file is refused before anything is
// written.
func TestADirectoryThatCannotTakeANewFileIsRefused(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root writes into a read-only directory")
	}

	files := newRotateFiles(t)
	before := listing(t, files.dir)

	require.NoError(t, os.Chmod(files.dir, 0o555))
	t.Cleanup(func() { os.Chmod(files.dir, 0o755) })

	res := runRotate(t, RotateSecret{ConfigPath: files.path, Name: "alice", Overlap: "24h"})
	require.Empty(t, retiringLeaks(res.printed(), files.old()...), "the refusal carries an old value")
	require.Error(t, res.err)

	assert.Contains(t, res.err.Error(), "the config's directory cannot take a new file")
	assert.Contains(t, res.err.Error(), "nothing was written")
	assert.Empty(t, res.stdout)
	assert.Equal(t, before, listing(t, files.dir))
}

// R6. The run writes a new inode and never through the old one: a reader that
// opened the file before the run still reads the old bytes after it.
func TestAnOpenReaderKeepsTheOldFile(t *testing.T) {
	t.Parallel()

	files := newRotateFiles(t)

	original, err := os.ReadFile(files.path)
	require.NoError(t, err)

	reader, err := os.Open(files.path)
	require.NoError(t, err)

	t.Cleanup(func() { reader.Close() })

	res := runRotate(t, RotateSecret{ConfigPath: files.path, Name: "alice", Overlap: "24h"})
	require.Empty(t, retiringLeaks(res.printed(), files.old()...), "stderr carries an old value")
	require.NoError(t, res.err)

	held, err := io.ReadAll(reader)
	require.NoError(t, err)
	assert.True(t, string(held) == string(original), "the old inode was written through")
}

// M-5 (a) of the review: the temporary file is created 0600, whatever the
// target's mode -- it is seen the moment it exists, under a umask of 0, before
// it is given the target's mode.
func TestTheTempFileIsCreatedPrivate(t *testing.T) {
	umask := syscall.Umask(0)

	t.Cleanup(func() { syscall.Umask(umask) })

	files := newRotateFiles(t)
	require.NoError(t, os.Chmod(files.path, 0o644))

	var modes []fs.FileMode

	original := createTemp

	t.Cleanup(func() { createTemp = original })

	createTemp = func(path string) (tempFile, error) {
		file, err := original(path)
		if err == nil {
			info, statErr := os.Stat(path)
			require.NoError(t, statErr)

			modes = append(modes, info.Mode().Perm())
		}

		return file, err
	}

	res := runRotate(t, RotateSecret{ConfigPath: files.path, Name: "alice", Overlap: "24h"})
	require.Empty(t, retiringLeaks(res.printed(), files.old()...), "stderr carries an old value")
	require.NoError(t, res.err)

	assert.Equal(t, []fs.FileMode{0o600}, modes, "the temporary file was created readable by others")

	info, err := os.Stat(files.path)
	require.NoError(t, err)
	assert.Equal(t, fs.FileMode(0o644), info.Mode().Perm(), "the config did not get its mode back")
}

// rotateChildEnv names the config TestRotateSecretChild rotates, when it runs
// as the child of TestAClosedStdoutDoesNotKillTheRun.
const rotateChildEnv = "MTG_PROXY_ROTATE_SECRET_CHILD"

// TestRotateSecretChild is not a test of its own: it is the child process of
// TestAClosedStdoutDoesNotKillTheRun, a rotation whose stdout is a closed
// pipe. Its exit code is 0 for a success, 3 for an error.
func TestRotateSecretChild(t *testing.T) {
	path := os.Getenv(rotateChildEnv)
	if path == "" {
		t.Skip("the child of TestAClosedStdoutDoesNotKillTheRun")
	}

	if err := (&RotateSecret{ConfigPath: path, Name: "alice", Overlap: "24h"}).Run(nil, "test"); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(3)
	}

	os.Exit(0)
}

// M-1 (a) of the review: a rotation whose stdout is a closed pipe is not
// killed by SIGPIPE at the value's write, after the rename: the write fails
// with EPIPE, the run says the file is written, and its lock is removed.
func TestAClosedStdoutDoesNotKillTheRun(t *testing.T) {
	files := newRotateFiles(t)
	lock := resolved(t, files.path) + ".rotate.lock"

	reader, writer, err := os.Pipe()
	require.NoError(t, err)
	require.NoError(t, reader.Close())

	var stderr bytes.Buffer

	child := exec.Command(os.Args[0], "-test.run=^TestRotateSecretChild$", "-test.count=1")
	child.Env = append(os.Environ(), rotateChildEnv+"="+files.path)
	child.Stdout = writer
	child.Stderr = &stderr

	err = child.Run()
	writer.Close()

	require.Empty(t, retiringLeaks(stderr.String(), files.old()...), "the child's stderr carries an old value")

	var exit *exec.ExitError

	require.True(t, errors.As(err, &exit), "the child did not run: %v", err)

	status, ok := exit.Sys().(syscall.WaitStatus)
	require.True(t, ok)
	require.False(t, status.Signaled(), "the child was killed by %v", status.Signal())

	assert.Equal(t, 3, exit.ExitCode())
	assert.Contains(t, stderr.String(), "the file is written, but the new value could not be printed")
	assert.NoFileExists(t, lock, "the lock is left behind")
	assert.Equal(t, []string{"config.toml"}, names(listing(t, files.dir)))
}
