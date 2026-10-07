package mtglib

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// client-fair, the work-conserving share, as the proxy runs it: fair share's
// ticker (fair_share.go decides, the proxy drives it once a second under its
// own context), and the reload that puts a fair limiter on, or takes it off,
// every entry a secret has -- the rest entry and the idle ones included -- so
// that a change reaches the streams already open.

// countFairPasses has the proxy's fair-share ticker report each pass it
// finishes. It must be called before the ticker starts: the hook is read
// without a lock.
func countFairPasses(p *Proxy) <-chan struct{} {
	passes := make(chan struct{}, 1)

	p.afterFairPass = func() {
		select {
		case passes <- struct{}{}:
		default:
		}
	}

	return passes
}

// awaitFairPass waits for the next pass the ticker reports, bounded.
func awaitFairPass(passes <-chan struct{}, within time.Duration) bool {
	timer := time.NewTimer(within)
	defer timer.Stop()

	select {
	case <-passes:
		return true
	case <-timer.C:
		return false
	}
}

// The ticker is part of the maintenance loop: whatever starts that -- NewProxy,
// under the proxy's own context -- starts fair share's ticker with it, at its
// one-second period.
func TestTheFairShareTickerRunsWithTheMaintenanceLoop(t *testing.T) {
	t.Parallel()

	probe := newClientTableProbe(t, false)
	passes := countFairPasses(probe.proxy)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	probe.proxy.startMaintenanceEvery(ctx, time.Hour, time.Hour, time.Hour)

	assert.True(t, awaitFairPass(passes, 3*fairTickInterval), "the maintenance loop starts fair share's ticker")
}

// The ticker stops with the context it runs under, and the proxy can wait for
// it: once its goroutine has returned, nothing ticks any more.
func TestTheFairShareTickerStopsWithItsContext(t *testing.T) {
	t.Parallel()

	probe := newClientTableProbe(t, false)
	p := probe.proxy
	passes := countFairPasses(p)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	p.startFairShare(ctx, 5*time.Millisecond)
	require.True(t, awaitFairPass(passes, 2*time.Second), "the ticker passes")

	cancel()

	stopped := make(chan struct{})

	go func() {
		defer close(stopped)

		p.fairWaitGroup.Wait()
	}()

	require.True(t, govAwait(stopped, 2*time.Second), "the ticker's goroutine returns once its context ends")

	// A pass that was already under way when the context ended has reported
	// by now; nothing after it may.
	select {
	case <-passes:
	default:
	}

	assert.False(t, awaitFairPass(passes, 100*time.Millisecond), "and it passes no more")
}

// Task 7's C1, for fair share: a reload that takes away the last per-address
// control leaves a set that wants no entries, and the backfill skips its walk.
// The entries made while the control was there are still held -- a stream, an
// idle address within retention, the rest entry -- and their fair limiters
// must come off all the same, in the walk over the entries that exist, not in
// the backfill that returns early.
func TestAReloadThatWantsNoEntriesTakesEveryFairShareOff(t *testing.T) {
	t.Parallel()

	probe := newClientTableProbe(t, false)
	p := probe.proxy

	reload := func(limits map[string]SecretLimits) {
		t.Helper()

		cfg := p.secrets.Load().toConfig()
		cfg.Limits = limits

		require.NoError(t, p.ReplaceSecrets(cfg))
	}

	reload(map[string]SecretLimits{"alice": {ClientConns: 8}})

	live := admitFrom(t, probe, tcpFrom("203.0.113.61", 50001))
	idle := admitFrom(t, probe, tcpFrom("203.0.113.62", 50002))
	local := admitFrom(t, probe, tcpFrom("127.0.0.1", 50003))

	idleEntry := idle.addrEntry.Load()
	require.NotNil(t, idleEntry)
	p.unregisterConn(idle)
	require.Equal(t, 0, clientRefs(p.clients, idleEntry), "an entry no stream holds")

	rest := local.addrEntry.Load()
	require.NotNil(t, rest)
	require.True(t, rest.rest)

	// Shares as a fair secret's entries carry them, on each of the three.
	for _, entry := range []*clientEntry{live.addrEntry.Load(), idleEntry, rest} {
		for b := range fairBucketCount {
			entry.fairLimiter(b).install(fairTestTotal, fairBurst(fairTestTotal))
		}
	}

	reload(nil)

	require.False(t, p.clientEntriesWantedBy(p.secrets.Load()),
		"nothing asks for entries any more: the backfill has no walk to do")
	assert.True(t, assertFairInvariant(t, p.clients, "alice", fairTotals{}),
		"every fair limiter is off, on the held, the idle and the rest entry alike")
	assert.Same(t, rest, local.addrEntry.Load(), "the streams keep their entries")
}
