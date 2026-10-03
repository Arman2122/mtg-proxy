//go:build linux

package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// If mtgbench itself is killed -- SIGKILL, which runs no deferred Close -- the
// kernel kills its children: nothing it started outlives it on a shared box.
func TestChildrenDieWithMtgbench(t *testing.T) {
	t.Parallel()

	parent := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestHelperProcess$") //nolint: gosec // this test binary
	parent.Env = append(os.Environ(), "MTGBENCH_HELPER=parent", "MTGBENCH_DIR="+t.TempDir())

	out, err := parent.StdoutPipe()
	require.NoError(t, err)
	require.NoError(t, parent.Start())

	t.Cleanup(func() {
		parent.Process.Kill() //nolint: errcheck
		parent.Wait()         //nolint: errcheck
	})

	var child int

	_, err = fmt.Fscan(out, &child)
	require.NoError(t, err)
	require.True(t, alive(child), "the child is running before its parent dies")

	require.NoError(t, parent.Process.Kill())
	parent.Wait() //nolint: errcheck

	require.Eventually(t, func() bool { return !alive(child) }, 5*time.Second, 20*time.Millisecond,
		"the child outlived a SIGKILLed parent")
}

// alive reports whether pid is a process that has not exited. Gone from /proc
// and a zombie waiting to be reaped both count as dead.
func alive(pid int) bool {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return false
	}

	rest := bytes.TrimSpace(b[bytes.LastIndexByte(b, ')')+1:])

	return len(rest) > 0 && rest[0] != 'Z'
}
