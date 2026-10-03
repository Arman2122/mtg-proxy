package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestHelperProcess is not a test: it is the stand-in process the runner tests
// start, re-running this test binary, in the mode MTGBENCH_HELPER names.
func TestHelperProcess(t *testing.T) { //nolint: paralleltest
	switch os.Getenv("MTGBENCH_HELPER") {
	case "sleep":
		time.Sleep(time.Hour)
		os.Exit(0)
	case "env":
		for _, kv := range os.Environ() {
			os.Stdout.WriteString(kv + "\n") //nolint: errcheck
		}

		os.Exit(0)
	case "parent":
		// A stand-in mtgbench: it starts a child, says its pid, and waits to
		// be killed.
		r, err := StartProcesses(context.Background(), os.Getenv("MTGBENCH_DIR"), helperSpec("child"))
		if err != nil {
			os.Exit(2)
		}

		fmt.Println(r.PIDs()[0]) //nolint: forbidigo
		time.Sleep(time.Hour)
		os.Exit(0)
	}
}

func helperSpec(name string) ProcSpec {
	return ProcSpec{
		Name: name,
		Path: os.Args[0],
		Args: []string{"-test.run=^TestHelperProcess$"},
		Env:  []string{"MTGBENCH_HELPER=sleep"},
	}
}

func requireAllExited(t *testing.T, r *Runner) {
	t.Helper()

	for _, p := range r.procs {
		select {
		case <-p.exited:
		case <-time.After(10 * time.Second):
			t.Fatalf("%s is still running", p.spec.Name)
		}
	}
}

// mtgbench shares a box with other people's services: whatever it starts, it
// stops, on every way a run can end -- an explicit Close, a cancelled context
// (SIGINT arrives as one), and a panic unwinding through the caller's defer.
func TestRunnerKillsChildrenOnEveryExit(t *testing.T) {
	t.Parallel()

	t.Run("close", func(t *testing.T) {
		t.Parallel()

		r, err := StartProcesses(t.Context(), t.TempDir(), helperSpec("a"), helperSpec("b"))
		require.NoError(t, err)
		require.NoError(t, r.Close())
		requireAllExited(t, r)
		require.NoError(t, r.Close(), "Close twice is harmless")
	})

	t.Run("cancel", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithCancel(t.Context())
		r, err := StartProcesses(ctx, t.TempDir(), helperSpec("a"))
		require.NoError(t, err)

		cancel()
		requireAllExited(t, r)
	})

	t.Run("panic", func(t *testing.T) {
		t.Parallel()

		var r *Runner

		func() {
			defer func() { assert.NotNil(t, recover()) }()

			var err error

			r, err = StartProcesses(t.Context(), t.TempDir(), helperSpec("a"))
			require.NoError(t, err)

			defer r.Close() //nolint: errcheck

			panic("a scenario blew up")
		}()

		requireAllExited(t, r)
	})
}

// A child that dies at once is reported with its output, not waited on.
func TestRunnerReportsAnEarlyExit(t *testing.T) {
	t.Parallel()

	spec := ProcSpec{Name: "broken", Path: os.Args[0], Args: []string{"-test.run=^$", "-no-such-flag"}}

	r, err := StartProcesses(t.Context(), t.TempDir(), spec)
	require.NoError(t, err)

	t.Cleanup(func() { r.Close() }) //nolint: errcheck

	err = r.WaitReady(t.Context(), []string{"127.0.0.1:1"}, 5*time.Second)
	require.ErrorContains(t, err, "broken exited")
}

// Neither mtgbench nor testclient may reach the release binary, which is built
// from the root package alone.
func TestReleaseBinaryDoesNotLinkTheTools(t *testing.T) {
	t.Parallel()

	root, err := filepath.Abs(filepath.Join("..", ".."))
	require.NoError(t, err)

	cmd := exec.CommandContext(t.Context(), "go", "list", "-deps", ".")
	cmd.Dir = root

	out, err := cmd.Output()
	require.NoError(t, err)

	deps := string(out)
	assert.True(t, strings.Contains(deps, "github.com/Arman2122/mtg-proxy/mtglib\n"), "the listing is the binary's")
	assert.NotContains(t, deps, "internal/testclient")
	assert.NotContains(t, deps, "tools/mtgbench")
}
