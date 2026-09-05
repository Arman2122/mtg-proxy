package mtglib

import (
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The accept loop is the one loop in the process that must never end on its
// own. Before this file it did: any accept error returned, the caller discarded
// the error, and the listener was off the air for good while the process
// stayed up and reported itself healthy. A full descriptor table or a peer
// resetting mid-accept -- both routine under load -- was enough.

// transientAcceptError is what accept(2) returns when the descriptor table is
// full: an error the net package classifies as temporary.
type transientAcceptError struct{}

func (transientAcceptError) Error() string   { return "accept: too many open files" }
func (transientAcceptError) Temporary() bool { return true }
func (transientAcceptError) Timeout() bool   { return false }

// stutteringListener wraps a real listener and fails a set number of accepts
// with a chosen error before handing over to it. It counts every attempt, so a
// test can tell a retry from a return.
type stutteringListener struct {
	net.Listener

	failuresLeft atomic.Int32
	attempts     atomic.Int32
	failWith     error
}

func (l *stutteringListener) Accept() (net.Conn, error) {
	l.attempts.Add(1)

	if l.failuresLeft.Add(-1) >= 0 {
		return nil, l.failWith
	}

	return l.Listener.Accept()
}

// allowAllList and blockNoneList are the two lists a proxy needs before it will
// accept anyone: an allowlist that answers yes and a blocklist that answers no.
type allowAllList struct{}

func (allowAllList) Contains(net.IP) bool { return true }
func (allowAllList) Run(time.Duration)    {}
func (allowAllList) Shutdown()            {}

type blockNoneList struct{}

func (blockNoneList) Contains(net.IP) bool { return false }
func (blockNoneList) Run(time.Duration)    {}
func (blockNoneList) Shutdown()            {}

// newServingProxy builds a proxy through the public constructor -- the accept
// loop needs the worker pool and the lists, which the entry harness leaves nil
// -- with every dependency that could reach a network replaced.
func newServingProxy(t *testing.T) (*Proxy, *recordingEventStream) {
	t.Helper()

	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { upstream.Close() }) //nolint: errcheck

	events := &recordingEventStream{}

	proxy, err := NewProxy(ProxyOpts{
		Network:          &fakeNetwork{upstream: upstream},
		AntiReplayCache:  newMemAntiReplay(),
		IPBlocklist:      blockNoneList{},
		IPAllowlist:      allowAllList{},
		EventStream:      events,
		Logger:           testLogger(),
		Secrets:          map[string]Secret{"alice": GenerateSecret("alice.example.com")},
		HandshakeTimeout: time.Second,
	})
	require.NoError(t, err)
	t.Cleanup(proxy.Shutdown)

	return proxy, events
}

func (r *recordingEventStream) starts() int {
	return r.count(func(evt Event) bool {
		_, ok := evt.(EventStart)

		return ok
	})
}

// serveInBackground runs the accept loop and hands back the channel its return
// value arrives on.
func serveInBackground(proxy *Proxy, listener net.Listener) <-chan error {
	done := make(chan error, 1)

	go func() { done <- proxy.ServeWithPolicy(listener, DefaultListenerPolicy) }()

	return done
}

func awaitReturn(t *testing.T, done <-chan error) error {
	t.Helper()

	select {
	case err := <-done:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("the accept loop did not return")

		return nil
	}
}

// A run of transient accept errors is ridden out: the loop keeps accepting,
// and the connection that arrives after them is served. The elapsed time
// proves the pause between attempts -- without it the retries are instant and
// the loop would spin flat out on a full descriptor table.
func TestAcceptLoopRidesOutTransientErrors(t *testing.T) {
	t.Parallel()

	proxy, events := newServingProxy(t)

	base, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	const failures = 3

	listener := &stutteringListener{Listener: base, failWith: transientAcceptError{}}
	listener.failuresLeft.Store(failures)

	started := time.Now()
	done := serveInBackground(proxy, listener)

	client, err := net.DialTimeout("tcp", base.Addr().String(), 5*time.Second)
	require.NoError(t, err)

	defer client.Close() //nolint: errcheck

	require.Eventually(t, func() bool { return events.starts() == 1 },
		5*time.Second, 10*time.Millisecond,
		"the connection after the transient errors was never served")

	assert.GreaterOrEqual(t, listener.attempts.Load(), int32(failures+1),
		"every failure must have been followed by another attempt")

	// 5ms, 10ms, 20ms: the three pauses add to 35ms before the fourth attempt.
	assert.GreaterOrEqual(t, time.Since(started), 35*time.Millisecond,
		"the retries were not paused between; the loop would spin on a full descriptor table")

	require.NoError(t, base.Close())
	require.NoError(t, awaitReturn(t, done), "a closed listener is not an error")
}

// A listener that has been closed ends the loop quietly. It is the caller's
// own doing, on the way to shutdown, and was previously reported as a failure.
func TestAcceptLoopReturnsQuietlyWhenTheListenerCloses(t *testing.T) {
	t.Parallel()

	proxy, _ := newServingProxy(t)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	done := serveInBackground(proxy, listener)

	require.NoError(t, listener.Close())
	require.NoError(t, awaitReturn(t, done))
}

// A socket that is broken rather than busy is reported, not retried. The
// caller is the one who knows whether that listener was the public port.
func TestAcceptLoopReportsABrokenListener(t *testing.T) {
	t.Parallel()

	proxy, _ := newServingProxy(t)

	base, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { base.Close() }) //nolint: errcheck

	broken := errors.New("accept: bad file descriptor")
	listener := &stutteringListener{Listener: base, failWith: broken}
	listener.failuresLeft.Store(1 << 30)

	err = awaitReturn(t, serveInBackground(proxy, listener))

	require.ErrorIs(t, err, broken)
	assert.Equal(t, int32(1), listener.attempts.Load(), "a broken listener must not be retried")
}

// The pause doubles from the floor to the ceiling and stays there.
func TestAcceptRetryBacksOffToACeiling(t *testing.T) {
	t.Parallel()

	var (
		current time.Duration
		seen    []time.Duration
	)

	for range 12 {
		current = nextAcceptRetry(current)
		seen = append(seen, current)
	}

	assert.Equal(t, acceptRetryMin, seen[0])
	assert.Equal(t, 2*acceptRetryMin, seen[1])
	assert.Equal(t, acceptRetryMax, seen[len(seen)-1])

	for i := 1; i < len(seen); i++ {
		assert.LessOrEqual(t, seen[i-1], seen[i], "the pause must never shrink between failures")
		assert.LessOrEqual(t, seen[i], acceptRetryMax, "the pause must never pass the ceiling")
	}
}

// The classification behind the retry: only what the net package calls
// temporary is retried, and a closed listener is neither.
func TestTransientAcceptErrorClassification(t *testing.T) {
	t.Parallel()

	assert.True(t, isTransientAcceptError(transientAcceptError{}))
	assert.True(t, isTransientAcceptError(&net.OpError{Op: "accept", Err: transientAcceptError{}}),
		"the net package wraps accept errors, and the wrapper must be looked through")
	assert.False(t, isTransientAcceptError(errors.New("bad file descriptor")))
	assert.False(t, isTransientAcceptError(net.ErrClosed))
}
