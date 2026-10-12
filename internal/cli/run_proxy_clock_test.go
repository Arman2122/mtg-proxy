package cli

import (
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The run's one rotation clock is built on the time runProxyWith is given and
// handed to the proxy. What proves it end to end -- one clock for the reloader
// and the proxy, through a behind-clock episode -- is
// TestOneRotationClockServesTheReloaderAndTheProxy.

// TestRunProxyWithBuildsItsClockOnTheTimeItIsGiven: the proxy's first set is
// built by reading the clock, so a run whose clock is on the given time reads it
// before it serves, and one whose proxy built a clock of its own would not.
func TestRunProxyWithBuildsItsClockOnTheTimeItIsGiven(t *testing.T) {
	t.Parallel()

	ports, held := holdPorts(t, 2)
	conf, path := runLoopConfig(t, held[0], held[1])

	var reads atomic.Int64

	now := func() time.Time {
		reads.Add(1)

		return time.Now()
	}

	stop := make(chan struct{})
	done := make(chan error, 1)

	go func() { done <- runProxyWith(stop, conf, "test", path, ports.listen, now) }()

	requireServed(t, fmt.Sprintf("127.0.0.1:%d", held[0]))

	assert.Positive(t, reads.Load(), "the proxy built its first set from the run's clock")

	close(stop)

	require.NoError(t, requireReturned(t, done))
}

// TestTheRunsClockReportsABehindEpisodeThroughTheRunsLogger: the Warning the
// run's clock writes is the one the spec gives, with the gap as a duration.
func TestTheRunsClockReportsABehindEpisodeThroughTheRunsLogger(t *testing.T) {
	t.Parallel()

	log, sink := newFieldLogger()

	clockBehindReporter(log)(3 * time.Second)

	warnings := sink.recorded()
	require.Len(t, warnings, 1)
	assert.Equal(t, "the wall clock is behind the latest time seen; rotation overlaps are judged by the latest time", warnings[0].msg)
	assert.Equal(t, map[string]string{"behind_by": "3s"}, warnings[0].fields)
}
