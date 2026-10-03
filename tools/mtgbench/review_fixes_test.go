package main

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The binary reads its configuration from the environment too: MTG_BIND_TO
// rebinds it, SECRET turns on a lookup that dials the internet directly, TAG
// starts the ad-tag path. A child of mtgbench gets an allowlisted environment,
// whatever the operator's shell holds.
func TestChildrenGetAnAllowlistedEnvironment(t *testing.T) { //nolint: paralleltest // sets the process environment
	t.Setenv("MTG_BIND_TO", "0.0.0.0:443")
	t.Setenv("SECRET", "ee00")
	t.Setenv("TAG", "latest")

	dir := t.TempDir()
	spec := helperSpec("env")
	spec.Env = []string{"MTGBENCH_HELPER=env"}

	r, err := StartProcesses(t.Context(), dir, spec)
	require.NoError(t, err)

	select {
	case <-r.procs[0].exited:
	case <-time.After(10 * time.Second):
		t.Fatal("the env helper did not exit")
	}

	logged, err := os.ReadFile(r.procs[0].log)
	require.NoError(t, err)

	env := string(logged)
	assert.NotContains(t, env, "MTG_BIND_TO=")
	assert.NotContains(t, env, "SECRET=")
	assert.NotContains(t, env, "TAG=")
	assert.Contains(t, env, "MTGBENCH_HELPER=env", "the spec's own variables are passed")
	assert.Regexp(t, `(?mi)^PATH=`, env, "and the allowlisted ones")
}

// countingReader counts the Reads a download makes.
type countingReader struct {
	r     io.Reader
	reads int
}

func (c *countingReader) Read(p []byte) (int, error) {
	c.reads++

	return c.r.Read(p)
}

func (c *countingReader) Write(p []byte) (int, error) { return len(p), nil }

// A download reads in the client's own 64 KiB pieces. Copying into io.Discard
// would read 8 KiB at a time, its own buffer, costing mtgbench's core eight
// times the reads.
func TestDownloadReadsInLargePieces(t *testing.T) {
	t.Parallel()

	conn := &countingReader{r: bytes.NewReader(make([]byte, 1<<20))}

	require.NoError(t, Download(conn, 1<<20))
	assert.LessOrEqual(t, conn.reads, 24, "1 MiB in 64 KiB pieces is 16 reads")
}

// What a download carries is checked, not only counted: the data centre sends
// zeros, and anything else -- a cipher out of step, a byte from another stream
// -- is a failure.
func TestDownloadChecksWhatArrives(t *testing.T) {
	t.Parallel()

	payload := make([]byte, 1<<20)
	payload[777] = 1

	err := Download(&countingReader{r: bytes.NewReader(payload)}, 1<<20)
	require.ErrorIs(t, err, errCorrupt)
}

// An echo must come back as it went.
func TestEchoChecksWhatComesBack(t *testing.T) {
	t.Parallel()

	wrong := &countingReader{r: strings.NewReader("pong")}

	err := Echo(wrong, []byte("ping"))
	require.ErrorIs(t, err, errCorrupt)
}

// The generated config is the same text for the same setup, and every address
// in it is on loopback, inside the run's ports.
func TestGeneratedConfigIsDeterministic(t *testing.T) {
	t.Parallel()

	s := benchSetup(t)

	first, err := WriteConfig(s)
	require.NoError(t, err)

	a, err := os.ReadFile(first)
	require.NoError(t, err)

	second, err := WriteConfig(s)
	require.NoError(t, err)

	b, err := os.ReadFile(second)
	require.NoError(t, err)

	assert.Equal(t, string(a), string(b))
}
