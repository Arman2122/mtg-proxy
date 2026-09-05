package middleproxy

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// quietLogger says nothing. The manager's background loop can log after a test
// has returned, and a test logger that is written to then panics.
type quietLogger struct{}

func (quietLogger) Info(string)    {}
func (quietLogger) Warning(string) {}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

var errUnreachable = errors.New("dial tcp 149.154.167.99:443: i/o timeout")

// failingClient is a network on which core.telegram.org is blocked, counting
// how many times anyone tried.
func failingClient(calls *atomic.Int32) *http.Client {
	return &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
		calls.Add(1)

		return nil, errUnreachable
	})}
}

func okResponse(body string) *http.Response {
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{},
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

// recoveringClient fails the first requests and then serves a usable secret
// and config, as a network that was blocking Telegram and then stopped.
func recoveringClient(calls *atomic.Int32, failures int32) *http.Client {
	return &http.Client{Transport: roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		if calls.Add(1) <= failures {
			return nil, errUnreachable
		}

		if r.URL.String() == secretURL {
			return okResponse(strings.Repeat("s", 128)), nil
		}

		return okResponse("proxy_for 2 149.154.175.50:8888;"), nil
	})}
}

// A dial after a failed fetch is answered at once, from memory, and does not
// go back to the network. Before this, every ad-tagged dial on a network that
// could not reach Telegram re-ran the whole fetch -- three requests of up to
// thirty seconds each -- one client after another, before letting each one
// through direct. Remove the lastErr branch from ensureReady and this fails on
// the call count, not on the clock.
func TestAFailedFetchDoesNotStallTheNextDial(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var calls atomic.Int32

	mgr := NewManager(ctx, failingClient(&calls), quietLogger{}, "only-ipv4")
	mgr.retryPeriod = time.Hour

	require.Error(t, mgr.ensureReady())
	require.Equal(t, int32(1), calls.Load(), "precondition: the first attempt reached the network once")

	started := time.Now()
	err := mgr.ensureReady()

	require.ErrorIs(t, err, errUnreachable, "the dial must be told why, not just that")
	require.Less(t, time.Since(started), time.Second, "a dial after a failed fetch waited for something")
	require.Equal(t, int32(1), calls.Load(), "a dial after a failed fetch went back to the network")
}

// blockingFirstFetch is a network on which the first request hangs until the
// test releases it. It is what Warm() runs into at boot on a blocked network.
func blockingFirstFetch(t *testing.T, mgr *Manager) (release chan struct{}) {
	t.Helper()

	var (
		enteredOnce sync.Once
		entered     = make(chan struct{})
	)

	release = make(chan struct{})

	mgr.httpClient = &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
		enteredOnce.Do(func() { close(entered) })
		<-release

		return nil, errUnreachable
	})}

	mgr.Warm()

	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("Warm never started a fetch")
	}

	return release
}

// A dial that arrives while the first fetch is still in flight waits for it
// only briefly, and is not queued behind it. Warm() starts that fetch at boot;
// a client connecting a moment later used to sit on the fetch lock for the
// whole of it, up to three times fetchTimeout.
func TestADialDuringTheFirstFetchDoesNotQueue(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	mgr := NewManager(ctx, nil, quietLogger{}, "only-ipv4")
	mgr.retryPeriod = time.Hour
	mgr.firstFetchGrace = 50 * time.Millisecond

	release := blockingFirstFetch(t, mgr)
	defer close(release)

	started := time.Now()
	err := mgr.ensureReady()

	require.ErrorIs(t, err, errFetching)
	require.Less(t, time.Since(started), time.Second, "a dial queued behind the fetch in flight")
}

// The wait ends when the fetch does, not when the grace runs out: a client
// reconnecting after a restart on a healthy network gets the fetch's answer --
// here a failure, in life a sponsored channel -- rather than a shrug.
func TestADialDuringTheFirstFetchGetsItsAnswer(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	mgr := NewManager(ctx, nil, quietLogger{}, "only-ipv4")
	mgr.retryPeriod = time.Hour
	mgr.firstFetchGrace = 10 * time.Second

	release := blockingFirstFetch(t, mgr)

	answered := make(chan error, 1)

	go func() { answered <- mgr.ensureReady() }()

	// Not answered while the fetch is in flight and the grace is long.
	select {
	case err := <-answered:
		t.Fatalf("the dial was answered before the fetch finished: %v", err)
	case <-time.After(100 * time.Millisecond):
	}

	close(release)

	select {
	case err := <-answered:
		require.ErrorIs(t, err, errUnreachable, "the dial must get the fetch's own answer")
	case <-time.After(5 * time.Second):
		t.Fatal("the dial was not released when the fetch finished")
	}
}

// A fetch that returned nothing usable with no error -- a 200 with an empty
// body -- is a failure like any other: recorded, retried in the background, and
// not a reason to put every dial back on the synchronous path.
func TestAnEmptyConfigIsAFailure(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var calls atomic.Int32

	client := &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
		calls.Add(1)

		return okResponse(""), nil
	})}

	mgr := NewManager(ctx, client, quietLogger{}, "only-ipv4")
	mgr.retryPeriod = time.Hour

	require.ErrorIs(t, mgr.ensureReady(), errEmptyConfig)

	before := calls.Load()

	require.ErrorIs(t, mgr.ensureReady(), errEmptyConfig)
	require.Equal(t, before, calls.Load(), "a dial after an empty fetch went back to the network")
}

// The refresh loop starts whether or not the first fetch succeeded, so a proxy
// that came up while Telegram was unreachable becomes ready by itself once the
// network allows it -- with no client ever having paid for the outage.
func TestTheBackgroundRetryRecoversWithoutADial(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var calls atomic.Int32

	mgr := NewManager(ctx, recoveringClient(&calls, 2), quietLogger{}, "only-ipv4")
	mgr.retryPeriod = 10 * time.Millisecond

	require.Error(t, mgr.ensureReady())
	require.False(t, mgr.Ready())

	require.Eventually(t, mgr.Ready, 5*time.Second, 5*time.Millisecond,
		"the manager never recovered without a dial to prompt it")

	require.NoError(t, mgr.ensureReady())
	require.Equal(t,
		[]middleAddress{{network: "tcp4", addr: "149.154.175.50:8888"}},
		mgr.orderedAddresses(2),
		"the recovered config is not the one that was served")
}
