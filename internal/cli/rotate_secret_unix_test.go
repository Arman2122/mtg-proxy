//go:build !windows

package cli

import (
	"io"
	"io/fs"
	"os"
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

	files := newRotateFiles(t)
	require.NoError(t, os.Chown(files.path, 65534, 65534))
	require.NoError(t, os.Chmod(files.path, 0o640))

	res := runRotate(t, RotateSecret{ConfigPath: files.path, Name: "alice", Overlap: "24h"})
	require.Empty(t, retiringLeaks(res.printed(), files.old()...), "stderr carries an old value")
	require.NoError(t, res.err)

	st := statOf(t, files.path)
	assert.Equal(t, uint32(65534), st.Uid)
	assert.Equal(t, uint32(65534), st.Gid)
	assert.Equal(t, []string{"config.toml"}, names(listing(t, files.dir)))
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

	chownFile = func(*os.File, int, int) error { return syscall.EPERM }

	res := runRotate(t, RotateSecret{ConfigPath: files.path, Name: "alice", Overlap: "24h"})
	require.Empty(t, retiringLeaks(res.printed(), files.old()...), "the refusal carries an old value")
	require.Error(t, res.err)

	assert.Contains(t, res.err.Error(), "run as the file's owner or root")
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
