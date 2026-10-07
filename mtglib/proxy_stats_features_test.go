package mtglib

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// statsRaw decodes the /stats body loosely (map, not StatsResponse) so the test
// sees the wire shape - field names and JSON types - rather than whatever the
// struct happens to accept today.
func statsRaw(t *testing.T, body []byte) map[string]any {
	t.Helper()

	raw := map[string]any{}
	require.NoError(t, json.Unmarshal(body, &raw))

	return raw
}

func serveStats(t *testing.T, stats *ProxyStats) *httptest.ResponseRecorder {
	t.Helper()

	rec := httptest.NewRecorder()
	stats.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/stats", nil))
	require.Equal(t, http.StatusOK, rec.Code)

	return rec
}

func TestStatsFeatures(t *testing.T) {
	t.Parallel()

	t.Run("the array names exactly the capabilities this build has", func(t *testing.T) {
		t.Parallel()

		var resp StatsResponse
		require.NoError(t, json.Unmarshal(serveStats(t, NewProxyStats()).Body.Bytes(), &resp))

		assert.Equal(t,
			[]string{
				FeatureClientIPActivity, FeatureClientIPs, FeatureClientLimits, FeatureClientStats, FeatureFakeTLS,
				FeatureHandshakeBudget, FeatureIPLimits, FeatureKick, FeatureListeners, FeatureQuotaCeiling,
				FeatureQuotaReset, FeatureSecretModes, FeatureSecretRead, FeatureSecretsAPI, FeatureSpeedDirections,
				FeatureSpeedLimits, FeatureWebRelay, FeatureWebRelayWatch,
			},
			resp.Features)
	})

	t.Run("the capability names are the strings downstream matches on", func(t *testing.T) {
		t.Parallel()

		assert.Equal(t, "client-ips", FeatureClientIPs)
		assert.Equal(t, "client-limits", FeatureClientLimits)
		assert.Equal(t, "client-stats", FeatureClientStats)
		assert.Equal(t, "faketls", FeatureFakeTLS)
		assert.Equal(t, "handshake-budget", FeatureHandshakeBudget)
		assert.Equal(t, "listeners", FeatureListeners)
		assert.Equal(t, "quota-reset", FeatureQuotaReset)
		assert.Equal(t, "secret-modes", FeatureSecretModes)
		assert.Equal(t, "secrets-api", FeatureSecretsAPI)
		assert.Equal(t, "web-relay", FeatureWebRelay)
		assert.Equal(t, "web-relay-watch", FeatureWebRelayWatch)
		assert.Equal(t, "speed-limits", FeatureSpeedLimits)
		assert.Equal(t, "ip-limits", FeatureIPLimits)
		assert.Equal(t, "speed-directions", FeatureSpeedDirections)
		assert.Equal(t, "kick", FeatureKick)
		assert.Equal(t, "client-ip-activity", FeatureClientIPActivity)
		assert.Equal(t, "quota-ceiling", FeatureQuotaCeiling)
		assert.Equal(t, "secret-read", FeatureSecretRead)
	})

	t.Run("every advertised route actually exists", func(t *testing.T) {
		t.Parallel()

		p := newAPITestProxy(map[string]Secret{"alice": GenerateSecret("alice.example.com")})

		assert.Equal(t, http.StatusOK, doAPI(t, p, "", http.MethodGet, "/secrets", "").Code)
		assert.Equal(t, http.StatusOK,
			doAPI(t, p, "", http.MethodPost, "/secrets/alice/reset-quota", "").Code)
		assert.Equal(t, http.StatusOK,
			doAPI(t, p, "", http.MethodGet, "/secrets/alice/external-ips", "").Code)
		assert.Equal(t, http.StatusOK, doAPI(t, p, "", http.MethodGet, "/secrets/alice", "").Code)
		assert.Equal(t, http.StatusOK,
			doAPI(t, p, "", http.MethodPost, "/secrets/alice/kick", `{"ips":["203.0.113.9"]}`).Code)
		assert.Equal(t, http.StatusOK,
			doAPI(t, p, "", http.MethodGet, "/secrets/alice/clients?limit=10", "").Code)

		// client-limits adds no route; what it advertises is a field the strict
		// decoder accepts.
		assert.Equal(t, http.StatusOK, doAPI(t, p, "", http.MethodPost, "/secrets",
			`{"name":"alice","secret":"`+GenerateSecret("alice.example.com").Hex()+`","client_conns":4}`).Code)
	})

	t.Run("it serializes as a sorted array, never null", func(t *testing.T) {
		t.Parallel()

		raw := statsRaw(t, serveStats(t, NewProxyStats()).Body.Bytes())

		features, ok := raw["features"].([]any)
		require.True(t, ok, "features must be a JSON array")
		assert.Equal(t,
			[]any{
				"client-ip-activity", "client-ips", "client-limits", "client-stats", "faketls", "handshake-budget",
				"ip-limits", "kick", "listeners", "quota-ceiling", "quota-reset", "secret-modes", "secret-read",
				"secrets-api", "speed-directions", "speed-limits", "web-relay", "web-relay-watch",
			},
			features)
		// Asserted independently of the literal above, so appending a capability
		// out of order cannot be "fixed" by editing the expectation to match.
		assert.True(t, slices.IsSorted(supportedFeatures))
	})

	t.Run("a mutated response cannot poison the next one", func(t *testing.T) {
		t.Parallel()

		stats := NewProxyStats()

		first := stats.buildResponse()
		require.Len(t, first.Features, len(supportedFeatures))
		first.Features[0] = "tampered"

		assert.Equal(t,
			[]string{
				FeatureClientIPActivity, FeatureClientIPs, FeatureClientLimits, FeatureClientStats, FeatureFakeTLS,
				FeatureHandshakeBudget, FeatureIPLimits, FeatureKick, FeatureListeners, FeatureQuotaCeiling,
				FeatureQuotaReset, FeatureSecretModes, FeatureSecretRead, FeatureSecretsAPI, FeatureSpeedDirections,
				FeatureSpeedLimits, FeatureWebRelay, FeatureWebRelayWatch,
			},
			stats.buildResponse().Features)
	})

	t.Run("the whole management API reports it too", func(t *testing.T) {
		t.Parallel()

		p := newAPITestProxy(map[string]Secret{"alice": GenerateSecret("alice.example.com")})
		rec := doAPI(t, p, "", http.MethodGet, "/stats", "")
		require.Equal(t, http.StatusOK, rec.Code)

		var resp StatsResponse
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
		assert.Equal(t,
			[]string{
				FeatureClientIPActivity, FeatureClientIPs, FeatureClientLimits, FeatureClientStats, FeatureFakeTLS,
				FeatureHandshakeBudget, FeatureIPLimits, FeatureKick, FeatureListeners, FeatureQuotaCeiling,
				FeatureQuotaReset, FeatureSecretModes, FeatureSecretRead, FeatureSecretsAPI, FeatureSpeedDirections,
				FeatureSpeedLimits, FeatureWebRelay, FeatureWebRelayWatch,
			},
			resp.Features)
	})
}

// TestStatsResponseShapeUnchanged is the regression guard for the contract: the
// panel decodes this JSON, so adding "features" must not have renamed or
// retyped anything that was already there. Types are the ones encoding/json
// produces for an untyped decode - float64 for every number, string for a
// time.Time.
func TestStatsResponseShapeUnchanged(t *testing.T) {
	t.Parallel()

	stats := NewProxyStats()
	stats.SetThrottle(10, time.Second)
	stats.PreRegister("alice")
	stats.OnConnect("alice")
	stats.AddBytesIn("alice", 1024)
	stats.AddBytesOut("alice", 512)
	stats.UpdateLastSeen("alice")

	raw := statsRaw(t, serveStats(t, stats).Body.Bytes())

	for field, want := range map[string]any{
		"started_at":        "",
		"uptime_seconds":    float64(0),
		"total_connections": float64(0),
		"users":             map[string]any{},
		"throttle":          map[string]any{},
	} {
		require.Contains(t, raw, field)
		assert.IsType(t, want, raw[field], "field %q changed type", field)
	}

	throttle, _ := raw["throttle"].(map[string]any)
	for field, want := range map[string]any{
		"active": false,
		"limit":  float64(0),
	} {
		require.Contains(t, throttle, field)
		assert.IsType(t, want, throttle[field], "throttle.%s changed type", field)
	}

	users, _ := raw["users"].(map[string]any)
	require.Contains(t, users, "alice")

	alice, _ := users["alice"].(map[string]any)
	for field, want := range map[string]any{
		"connections": float64(0),
		"bytes_in":    float64(0),
		"bytes_out":   float64(0),
		"last_seen":   "",
		"quota_used":  float64(0),
	} {
		require.Contains(t, alice, field)
		assert.IsType(t, want, alice[field], "users.alice.%s changed type", field)
	}

	// Values, not just shape: the counters must still carry what was recorded.
	assert.Equal(t, float64(1), alice["connections"])
	assert.Equal(t, float64(1024), alice["bytes_in"])
	assert.Equal(t, float64(512), alice["bytes_out"])
	assert.Equal(t, float64(1), raw["total_connections"])
	assert.Equal(t, float64(10), throttle["limit"])
}

// TestStatsOmitemptyShapeUnchanged covers the fields the base response leaves
// out: the governance limits handleStats overlays, and throttle.caps, which only
// appears once throttling actually engages. They are checked on the raw wire
// shape because a typed decode round-trips a renamed json tag silently.
func TestStatsOmitemptyShapeUnchanged(t *testing.T) {
	t.Parallel()

	t.Run("the per-secret limit overlay", func(t *testing.T) {
		t.Parallel()

		alice := GenerateSecret("alice.example.com")
		p := newAPITestProxy(map[string]Secret{"alice": alice})
		body := `{"secrets":{"alice":{"secret":"` + alice.Hex() +
			`","quota":"1000","quota_reset":"monthly","expires":"2030-01-01","disabled":true}}}`
		require.Equal(t, http.StatusOK, doAPI(t, p, "", http.MethodPut, "/secrets", body).Code)

		rec := doAPI(t, p, "", http.MethodGet, "/stats", "")
		require.Equal(t, http.StatusOK, rec.Code)

		users, _ := statsRaw(t, rec.Body.Bytes())["users"].(map[string]any)
		require.Contains(t, users, "alice")

		user, _ := users["alice"].(map[string]any)
		for field, want := range map[string]any{
			"quota":           float64(0),
			"quota_remaining": float64(0),
			"quota_reset":     "",
			"expires_at":      "",
			"disabled":        false,
		} {
			require.Contains(t, user, field)
			assert.IsType(t, want, user[field], "users.alice.%s changed type", field)
		}
	})

	t.Run("the throttle caps map", func(t *testing.T) {
		t.Parallel()

		stats := NewProxyStats()
		stats.SetThrottle(1, time.Second)
		stats.OnConnect("alice")
		stats.OnConnect("bob")
		stats.recomputeCaps(testLogger())

		throttle, _ := statsRaw(t, serveStats(t, stats).Body.Bytes())["throttle"].(map[string]any)
		require.Contains(t, throttle, "caps")
		assert.IsType(t, map[string]any{}, throttle["caps"])
	})
}
