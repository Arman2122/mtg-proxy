package mtglib

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/Arman2122/mtg-proxy/essentials"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A speed limit is a promise about a number, and a test of it has to measure
// the number. Every test here writes an amount through the throttled wrapper
// and times it. The bucket starts full with one second of the rate in it, so
// the first second's worth passes at once and only what follows is paced:
// writing twice the rate takes about one second, and that is what is asserted.
// The tolerances are loose enough for a loaded CI runner and tight enough that
// a cap which did nothing fails -- an unthrottled megabyte through a pipe is
// milliseconds, not the better part of a second.

// throttledPair is a wrapped writer and a reader that drains it, over a
// user's stats. Whatever is written is timed by the caller.
func throttledPair(t *testing.T, ctx context.Context, stats *ProxyStats, user string) (*countingConn, *sync.WaitGroup) {
	t.Helper()

	client, server := net.Pipe()
	t.Cleanup(func() { client.Close(); server.Close() }) //nolint: errcheck

	var drained sync.WaitGroup

	drained.Go(func() { io.Copy(io.Discard, server) }) //nolint: errcheck

	return newCountingConn(ctx, essentials.WrapNetConn(client), stats, user), &drained
}

// writeTimed pushes n bytes through conn the way the relay does, in 32 KiB
// pieces, and returns how long it took.
func writeTimed(t *testing.T, conn io.Writer, n int) time.Duration {
	t.Helper()

	piece := make([]byte, 32<<10)
	started := time.Now()

	for written := 0; written < n; {
		size := min(len(piece), n-written)

		w, err := conn.Write(piece[:size])
		require.NoError(t, err)

		written += w
	}

	return time.Since(started)
}

func TestParseSpeed(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		in   string
		want int64
	}{
		{in: "", want: 0},
		{in: "5mbit", want: 625_000},
		{in: "5 Mbit/s", want: 625_000},
		{in: "5mbps", want: 625_000},
		{in: "500kbit", want: 62_500},
		{in: "1gbit", want: 125_000_000},
		{in: "64kbit", want: 8_000},
		{in: "1MB/s", want: 1 << 20},
		{in: "1MiB", want: 1 << 20},
		{in: "500KB", want: 500 << 10},
		{in: "2.5MB/s", want: 2621440},
		{in: "8192", want: 8192},
		{in: "8192B/s", want: 8192},
	} {
		t.Run(tc.in, func(t *testing.T) {
			t.Parallel()

			got, err := ParseSpeed(tc.in)
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}

	for _, in := range []string{"0", "0mbit", "-5mbit", "63kbit", "7999", "fast", "5", "mbit", "5 parsecs", "5mb/h"} {
		t.Run("refuses "+in, func(t *testing.T) {
			t.Parallel()

			_, err := ParseSpeed(in)
			require.Error(t, err)
		})
	}

	t.Run("names the rule on the floor", func(t *testing.T) {
		t.Parallel()

		_, err := ParseSpeed("32kbit")
		require.ErrorContains(t, err, "64kbit")
	})
}

// The cap holds. Twice the rate takes about a second; unlimited takes nothing
// measurable. Remove the wait from countingConn.Write and this fails.
func TestSpeedLimitHoldsSustainedThroughput(t *testing.T) {
	t.Parallel()

	const rateBytes = 1 << 20

	stats := NewProxyStats()
	stats.SetSpeedLimit("alice", rateBytes)

	capped, _ := throttledPair(t, t.Context(), stats, "alice")
	elapsed := writeTimed(t, capped, 2*rateBytes)

	assert.GreaterOrEqual(t, elapsed, 800*time.Millisecond, "2x the rate must take about a second at the cap")
	assert.Less(t, elapsed, 3*time.Second, "the cap paced far below the rate")

	free, _ := throttledPair(t, t.Context(), stats, "bob")
	assert.Less(t, writeTimed(t, free, 2*rateBytes), 300*time.Millisecond, "an unlimited user must not be paced at all")

	assert.Positive(t, stats.getOrCreate("alice").speed.throttledNanos.Load(), "time held to the cap must be counted")
	assert.Zero(t, stats.getOrCreate("bob").speed.throttledNanos.Load())
}

// One user, two connections, one allowance: together they cannot exceed the
// cap. Two users each get their own, so the same load in parallel across two
// users is not paced. This is the difference between a per-user limit and a
// per-connection one, and the assertion that would catch a bucket created per
// connection by mistake.
func TestSpeedLimitIsSharedByAUsersConnections(t *testing.T) {
	t.Parallel()

	const rateBytes = 1 << 20

	stats := NewProxyStats()
	stats.SetSpeedLimit("alice", rateBytes)
	stats.SetSpeedLimit("bob", rateBytes)

	timeBoth := func(first, second *countingConn) time.Duration {
		started := time.Now()

		var wg sync.WaitGroup

		wg.Go(func() { writeTimed(t, first, rateBytes) })
		wg.Go(func() { writeTimed(t, second, rateBytes) })
		wg.Wait()

		return time.Since(started)
	}

	aliceOne, _ := throttledPair(t, t.Context(), stats, "alice")
	aliceTwo, _ := throttledPair(t, t.Context(), stats, "alice")
	assert.GreaterOrEqual(t, timeBoth(aliceOne, aliceTwo), 800*time.Millisecond,
		"two connections of one user must share one allowance")

	stats2 := NewProxyStats()
	stats2.SetSpeedLimit("alice", rateBytes)
	stats2.SetSpeedLimit("bob", rateBytes)

	alice, _ := throttledPair(t, t.Context(), stats2, "alice")
	bob, _ := throttledPair(t, t.Context(), stats2, "bob")
	assert.Less(t, timeBoth(alice, bob), 500*time.Millisecond,
		"two users' allowances must be independent")
}

// A limit changed while a connection is moving takes effect on that
// connection: it does not have to reconnect, and it is not dropped.
func TestSpeedLimitChangesReachLiveConnections(t *testing.T) {
	t.Parallel()

	stats := NewProxyStats()
	stats.SetSpeedLimit("alice", 256<<10)

	conn, _ := throttledPair(t, t.Context(), stats, "alice")

	done := make(chan time.Duration, 1)

	// 4 MiB at 256 KiB/s would be fifteen seconds.
	go func() { done <- writeTimed(t, conn, 4<<20) }()

	time.Sleep(300 * time.Millisecond)
	stats.SetSpeedLimit("alice", 0)

	select {
	case elapsed := <-done:
		assert.Less(t, elapsed, 2*time.Second, "lifting the limit must free the connection in flight")
	case <-time.After(10 * time.Second):
		t.Fatal("the connection stayed paced after its limit was lifted")
	}

	// And the other way: tightened under a write in flight. The write started
	// unlimited and is held from the moment the limit lands.
	stats.SetSpeedLimit("bob", 0)
	bobConn, _ := throttledPair(t, t.Context(), stats, "bob")

	started := time.Now()
	stats.SetSpeedLimit("bob", 1<<20)
	writeTimed(t, bobConn, 2<<20)
	assert.GreaterOrEqual(t, time.Since(started), 800*time.Millisecond, "a limit set on a live user must hold at once")
}

// A connection asleep on the bucket wakes up when its context ends. Without
// this, the proxy stopping would wait for the slowest capped user to drain.
func TestSpeedLimitWaitEndsWithTheContext(t *testing.T) {
	t.Parallel()

	stats := NewProxyStats()
	stats.SetSpeedLimit("alice", MinSpeedBytesPerSecond)

	ctx, cancel := context.WithCancel(t.Context())
	conn, _ := throttledPair(t, ctx, stats, "alice")

	result := make(chan error, 1)

	// A megabyte at 8 KiB/s is two minutes.
	go func() {
		_, err := conn.Write(make([]byte, 1<<20))
		result <- err
	}()

	time.Sleep(200 * time.Millisecond)
	cancel()

	select {
	case err := <-result:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(5 * time.Second):
		t.Fatal("the write stayed asleep on the bucket after its context ended")
	}
}

// The API sets a limit with a human spelling and reads it back as a number,
// on the single view, the collection and /stats alike, and the running bucket
// is re-rated by the same call. Omitting it clears it.
func TestSpeedLimitThroughTheAPI(t *testing.T) {
	t.Parallel()

	alice := GenerateSecret("alice.example.com")
	p := newAPITestProxy(map[string]Secret{"alice": alice})

	body := `{"secrets":{"alice":{"secret":"` + alice.Hex() + `","speed":"5mbit"}}}`
	require.Equal(t, http.StatusOK, doAPI(t, p, "", http.MethodPut, "/secrets", body).Code)

	assert.Equal(t, int64(625_000), p.stats.getOrCreate("alice").speed.bytesPerSecond(),
		"the live bucket must carry the rate the API set")

	var one map[string]any
	require.NoError(t, json.Unmarshal(doAPI(t, p, "", http.MethodGet, "/secrets/alice", "").Body.Bytes(), &one))
	assert.Equal(t, float64(625_000), one["speed_limit"])

	users, _ := statsRaw(t, doAPI(t, p, "", http.MethodGet, "/stats", "").Body.Bytes())["users"].(map[string]any)
	user, _ := users["alice"].(map[string]any)
	assert.Equal(t, float64(625_000), user["speed_limit"])
	assert.NotContains(t, user, "throttled_ms", "nothing has been held yet, so nothing is reported")

	// A spelling the config would refuse is refused here too, by the same
	// parser, and the running limit is untouched.
	rec := doAPI(t, p, "", http.MethodPut, "/secrets", `{"secrets":{"alice":{"secret":"`+alice.Hex()+`","speed":"32kbit"}}}`)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "64kbit")
	assert.Equal(t, int64(625_000), p.stats.getOrCreate("alice").speed.bytesPerSecond())

	// Omitted is unlimited.
	require.Equal(t, http.StatusOK,
		doAPI(t, p, "", http.MethodPut, "/secrets", `{"secrets":{"alice":{"secret":"`+alice.Hex()+`"}}}`).Code)
	assert.Zero(t, p.stats.getOrCreate("alice").speed.bytesPerSecond())

	// A fresh map: Unmarshal into a populated one merges, and a key the server
	// stopped sending would survive from the decode above.
	var cleared map[string]any

	require.NoError(t, json.Unmarshal(doAPI(t, p, "", http.MethodGet, "/secrets/alice", "").Body.Bytes(), &cleared))
	assert.NotContains(t, cleared, "speed_limit")
}

// A reload from the file carries the limit the same way, through the same
// swap, so the file and the API cannot disagree about what a user is held to.
func TestSpeedLimitThroughAReload(t *testing.T) {
	t.Parallel()

	alice := GenerateSecret("alice.example.com")
	p := newReloadTestProxy(map[string]Secret{"alice": alice})
	p.reloader = func() (SecretConfig, error) {
		return SecretConfig{
			Secrets: map[string]Secret{"alice": alice},
			Limits:  map[string]SecretLimits{"alice": {SpeedBytesPerSecond: 1 << 20}},
		}, nil
	}

	require.NoError(t, p.ReloadSecrets())
	assert.Equal(t, int64(1<<20), p.stats.getOrCreate("alice").speed.bytesPerSecond())

	p.reloader = func() (SecretConfig, error) {
		return SecretConfig{Secrets: map[string]Secret{"alice": alice}}, nil
	}

	require.NoError(t, p.ReloadSecrets())
	assert.Zero(t, p.stats.getOrCreate("alice").speed.bytesPerSecond(), "a limit gone from the file is gone from the user")
}

// The whole path: a real client on the FakeTLS door, a real stream through
// ServeConn, and Telegram pushing bytes down it. The capped user receives them
// at the cap; the uncapped one does not wait. This is the test that fails if
// the wrapper is wired anywhere but on the client side of every stream.
func TestSpeedLimitAppliesThroughTheProxy(t *testing.T) {
	t.Parallel()

	// A quarter-megabyte rate: twice it is still about a second for the capped
	// user, while half a megabyte through the real relay under the race
	// detector is far under the bound for the uncapped one.
	const rateBytes = 256 << 10

	// Minted for the cover host: the FakeTLS entry forges a ClientHello with
	// that name in SNI, and the proxy admits a key only under its own host.
	alice := GenerateSecret(govCoverHost)
	bob := GenerateSecret(govCoverHost)

	entry := govEntryCases()[0]
	require.Equal(t, SecretModeFakeTLS, entry.mode, "the first case is the FakeTLS door")

	// The case's own harness: it runs the doppelganger, which the FakeTLS door
	// cannot get past without, and pins the idle and handshake timeouts so
	// nothing but the cap can pace these streams.
	h := entry.harness(t,
		map[string]Secret{"alice": alice, "bob": bob},
		map[string]SecretLimits{"alice": {SpeedBytesPerSecond: rateBytes}})

	timeDownload := func(name string, key [SecretKeyLength]byte) time.Duration {
		client, done := h.dialProxy(t, entry.policy)
		upstream := connectThrough(t, entry, h, client, name, key)

		defer endStream(client, upstream, done)

		go func() { upstream.Write(make([]byte, 2*rateBytes)) }() //nolint: errcheck

		// The client sees the bytes wrapped in TLS records, which are only
		// larger, so counting raw bytes up to the payload size is enough.
		require.NoError(t, client.SetReadDeadline(time.Now().Add(15*time.Second)))

		started := time.Now()
		buf := make([]byte, 64<<10)

		for received := 0; received < 2*rateBytes; {
			n, err := client.Read(buf)
			require.NoError(t, err)

			received += n
		}

		return time.Since(started)
	}

	capped := timeDownload("alice", alice.Key)
	assert.GreaterOrEqual(t, capped, 800*time.Millisecond,
		"alice is capped and must receive twice her rate in about a second")

	free := timeDownload("bob", bob.Key)
	assert.Less(t, free, 500*time.Millisecond, "bob is unlimited and must not be paced")
	assert.Less(t, free, capped/2, "the same transfer must be far faster without the cap than with it")

	var throttled int64

	require.Eventually(t, func() bool {
		throttled = h.proxy.stats.getOrCreate("alice").speed.throttledNanos.Load()

		return throttled > 0
	}, time.Second, 10*time.Millisecond, "time held to the cap must be counted for the capped user")
	assert.Zero(t, h.proxy.stats.getOrCreate("bob").speed.throttledNanos.Load())
}

// An unlimited user pays nothing: the wrapper is the same single read and
// single write it was before there was a limit. Asserted on the counting, so
// a chunking loop that split unlimited writes would show up as extra calls.
func TestUnlimitedUserWritesOnce(t *testing.T) {
	t.Parallel()

	stats := NewProxyStats()
	counter := &writeCounter{}

	conn := newCountingConn(t.Context(), counter, stats, "alice")

	n, err := conn.Write(make([]byte, 1<<20))
	require.NoError(t, err)
	assert.Equal(t, 1<<20, n)
	assert.Equal(t, 1, counter.calls, "an unlimited write must be one write")
}

// writeCounter is an essentials.Conn that only counts writes; anything else
// panics, the same way frameSink works elsewhere in these tests.
type writeCounter struct {
	essentials.Conn

	calls int
}

func (w *writeCounter) Write(p []byte) (int, error) {
	w.calls++

	return len(p), nil
}
