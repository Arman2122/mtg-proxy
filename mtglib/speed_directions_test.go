package mtglib

import (
	"encoding/json"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/Arman2122/mtg-proxy/essentials"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// readTimed drains n bytes through the throttled reader the way the relay
// reads a client, fed by a writer that is never the bottleneck, and returns
// how long it took.
func readTimed(t *testing.T, stats *ProxyStats, user string, n int) time.Duration {
	t.Helper()

	client, proxySide := net.Pipe()
	t.Cleanup(func() { client.Close(); proxySide.Close() }) //nolint: errcheck

	reader := newCountingConn(t.Context(), nil, essentials.WrapNetConn(proxySide), stats, user)

	go func() {
		piece := make([]byte, 32<<10)
		for written := 0; written < n; written += len(piece) {
			if _, err := client.Write(piece); err != nil {
				return
			}
		}
	}()

	started := time.Now()
	buf := make([]byte, 64<<10)

	for received := 0; received < n; {
		got, err := reader.Read(buf)
		require.NoError(t, err)

		received += got
	}

	return time.Since(started)
}

// A cap on one direction paces that direction alone: the download cap holds
// what the proxy writes to the client and leaves what it reads at wire speed,
// and the upload cap the other way round. Each is its own bucket, and the
// combined cap still applies on top of both.
func TestSpeedLimitPerDirection(t *testing.T) {
	t.Parallel()

	const rateBytes = 1 << 20

	t.Run("download cap paces writes and not reads", func(t *testing.T) {
		t.Parallel()

		stats := NewProxyStats()
		stats.SetDirectionalSpeedLimits("alice", 0, rateBytes)

		capped, _ := throttledPair(t, t.Context(), stats, "alice")
		elapsed := writeTimed(t, capped, 2*rateBytes)
		assert.GreaterOrEqual(t, elapsed, 800*time.Millisecond, "2x the download rate must take about a second")
		assert.Less(t, elapsed, 3*time.Second)

		assert.Less(t, readTimed(t, stats, "alice", 2*rateBytes), 300*time.Millisecond, "the upload direction is uncapped")
		assert.Positive(t, stats.getOrCreate("alice").speedDown.throttledNanos.Load())
		assert.Zero(t, stats.getOrCreate("alice").speedUp.throttledNanos.Load())
	})

	t.Run("upload cap paces reads and not writes", func(t *testing.T) {
		t.Parallel()

		stats := NewProxyStats()
		stats.SetDirectionalSpeedLimits("alice", rateBytes, 0)

		elapsed := readTimed(t, stats, "alice", 2*rateBytes)
		assert.GreaterOrEqual(t, elapsed, 800*time.Millisecond, "2x the upload rate must take about a second")
		assert.Less(t, elapsed, 3*time.Second)

		free, _ := throttledPair(t, t.Context(), stats, "alice")
		assert.Less(t, writeTimed(t, free, 2*rateBytes), 300*time.Millisecond, "the download direction is uncapped")
	})

	t.Run("the combined cap still applies on top", func(t *testing.T) {
		t.Parallel()

		stats := NewProxyStats()
		stats.SetSpeedLimit("alice", rateBytes)
		stats.SetDirectionalSpeedLimits("alice", 0, 8*rateBytes)

		capped, _ := throttledPair(t, t.Context(), stats, "alice")
		assert.GreaterOrEqual(t, writeTimed(t, capped, 2*rateBytes), 800*time.Millisecond,
			"the tighter of the two caps is the one that holds")
	})
}

// The two caps travel the API under their own names and read back under their
// own names, beside the combined one; a refused value leaves the running limit
// alone.
func TestSpeedDirectionsThroughTheAPI(t *testing.T) {
	t.Parallel()

	alice := GenerateSecret("alice.example.com")
	p := newAPITestProxy(map[string]Secret{"alice": alice})

	body := `{"secrets":{"alice":{"secret":"` + alice.Hex() + `","speed_up":"1mbit","speed_down":"2MB/s"}}}`
	require.Equal(t, http.StatusOK, doAPI(t, p, "", http.MethodPut, "/secrets", body).Code)

	lim := p.secrets.Load().limits[0]
	assert.Equal(t, int64(125_000), lim.SpeedUpBytesPerSecond)
	assert.Equal(t, int64(2<<20), lim.SpeedDownBytesPerSecond)
	assert.Zero(t, lim.SpeedBytesPerSecond)

	st := p.stats.getOrCreate("alice")
	assert.Equal(t, int64(125_000), st.speedUp.bytesPerSecond(), "the swap re-rates the upload bucket")
	assert.Equal(t, int64(2<<20), st.speedDown.bytesPerSecond())
	assert.Zero(t, st.speed.bytesPerSecond())

	var info SecretInfo
	require.NoError(t, json.Unmarshal(doAPI(t, p, "", http.MethodGet, "/secrets/alice", "").Body.Bytes(), &info))
	assert.Equal(t, int64(125_000), info.SpeedLimitUp)
	assert.Equal(t, int64(2<<20), info.SpeedLimitDown)
	assert.Zero(t, info.SpeedLimit)

	users, _ := statsRaw(t, doAPI(t, p, "", http.MethodGet, "/stats", "").Body.Bytes())["users"].(map[string]any)
	user, _ := users["alice"].(map[string]any)
	assert.Equal(t, float64(125_000), user["speed_limit_up"])
	assert.Equal(t, float64(2<<20), user["speed_limit_down"])
	assert.NotContains(t, user, "speed_limit")

	rec := doAPI(t, p, "", http.MethodPost, "/secrets", `{"name":"alice","secret":"`+alice.Hex()+`","speed_down":"32kbit"}`)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "speed_down")
	assert.Equal(t, int64(2<<20), p.secrets.Load().limits[0].SpeedDownBytesPerSecond,
		"a refused request leaves the running limit alone")
}
