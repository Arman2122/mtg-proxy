package mtglib

import (
	"encoding/json"
	"net/http"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// handshakeStatsKey is the top-level key the FakeTLS door's counters are
// reported under.
const handshakeStatsKey = "faketls_handshake"

// handshakeStatsOf serves GET /stats through the whole management API and returns the
// body as a loose map, so a test sees the wire shape and not whatever the struct
// happens to accept.
func handshakeStatsOf(t *testing.T, p *Proxy) map[string]any {
	t.Helper()

	rec := doAPI(t, p, "", http.MethodGet, "/stats", "")
	require.Equal(t, http.StatusOK, rec.Code)

	return statsRaw(t, rec.Body.Bytes())
}

// handshakeObject is the faketls_handshake object of a /stats body, or nil when
// the body has none.
func handshakeObject(t *testing.T, raw map[string]any) map[string]any {
	t.Helper()

	value, found := raw[handshakeStatsKey]
	if !found {
		return nil
	}

	object, ok := value.(map[string]any)
	require.True(t, ok, "%s must be a JSON object, got %T", handshakeStatsKey, value)

	return object
}

// newHandshakeStatsProxy is a hand-built proxy with a budget of the given mode
// whose block cost is the constant a test injects.
func newHandshakeStatsProxy(mode budgetMode, nsPerBlock float64) *Proxy {
	p := newAPITestProxy(map[string]Secret{"alice": GenerateSecret("alice.example.com")})
	p.scanBudget = newScanBudget(scanBudgetConfig{Mode: mode, NsPerBlock: nsPerBlock}, time.Now)

	return p
}

// A proxy whose door has counted nothing reports no faketls_handshake at all,
// the way a deployment with no [[listener]] reports no obfuscated block: a panel
// that decodes /stats sees the response it always saw until there is something
// to say.
func TestFakeTLSHandshakeIsAbsentUntilTheDoorCountsSomething(t *testing.T) {
	t.Parallel()

	t.Run("a hand-built proxy", func(t *testing.T) {
		t.Parallel()

		p := newAPITestProxy(map[string]Secret{"alice": GenerateSecret("alice.example.com")})

		assert.NotContains(t, handshakeStatsOf(t, p), handshakeStatsKey)
	})

	t.Run("one with a budget that has not been asked anything", func(t *testing.T) {
		t.Parallel()

		p := newHandshakeStatsProxy(budgetEnforce, 325)

		assert.NotContains(t, handshakeStatsOf(t, p), handshakeStatsKey)
	})

	t.Run("a proxy NewProxy built", func(t *testing.T) {
		t.Parallel()

		p, _ := newServingProxy(t)

		assert.NotContains(t, handshakeStatsOf(t, p), handshakeStatsKey)

		p.fakeStats.OnScanned()

		assert.Contains(t, handshakeStatsOf(t, p), handshakeStatsKey, "and it appears with the first thing counted")
	})
}

// The seven counters carry seven different numbers, so a mapping that put one
// under another's name fails; and the object has exactly the keys the panel's
// decoder is told about, no more.
func TestFakeTLSHandshakeReportsEachCounterUnderItsOwnName(t *testing.T) {
	t.Parallel()

	p := newHandshakeStatsProxy(budgetEnforce, 325)

	p.fakeStats.hinted.Add(1)
	p.fakeStats.scanned.Add(2)
	p.fakeStats.unmatched.Add(3)
	p.fakeStats.deniedIP.Add(4)
	p.fakeStats.deniedGlobal.Add(5)
	p.fakeStats.oversized.Add(6)
	p.fakeStats.overBudgetMatched.Add(7)

	assert.Equal(t,
		map[string]any{
			"hinted":              float64(1),
			"scanned":             float64(2),
			"unmatched":           float64(3),
			"denied_ip":           float64(4),
			"denied_global":       float64(5),
			"oversized":           float64(6),
			"over_budget_matched": float64(7),
			"enforced":            true,
			"ns_per_block":        float64(325),
		},
		handshakeObject(t, handshakeStatsOf(t, p)))

	var resp StatsResponse

	rec := doAPI(t, p, "", http.MethodGet, "/stats", "")
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	require.NotNil(t, resp.FakeTLSHandshake)
	assert.Equal(t,
		FakeTLSJSON{
			Hinted: 1, Scanned: 2, Unmatched: 3, DeniedIP: 4, DeniedGlobal: 5, Oversized: 6,
			OverBudgetMatched: 7, Enforced: true, NsPerBlock: 325,
		},
		*resp.FakeTLSHandshake)
}

// Any one counter is enough to make the object appear, and it then carries that
// counter and zeros for the others.
func TestFakeTLSHandshakeAppearsOnAnySingleCounter(t *testing.T) {
	t.Parallel()

	for name, count := range map[string]func(*fakeTLSCounters){
		"hinted":              (*fakeTLSCounters).OnHinted,
		"scanned":             (*fakeTLSCounters).OnScanned,
		"unmatched":           (*fakeTLSCounters).OnUnmatched,
		"denied_ip":           (*fakeTLSCounters).OnDeniedIP,
		"denied_global":       (*fakeTLSCounters).OnDeniedGlobal,
		"oversized":           (*fakeTLSCounters).OnOversized,
		"over_budget_matched": (*fakeTLSCounters).OnOverBudgetMatched,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			p := newHandshakeStatsProxy(budgetEnforce, 325)
			count(&p.fakeStats)

			object := handshakeObject(t, handshakeStatsOf(t, p))
			require.NotNil(t, object, "one %s is something the door counted", name)

			for _, field := range []string{
				"hinted", "scanned", "unmatched", "denied_ip", "denied_global", "oversized", "over_budget_matched",
			} {
				want := float64(0)
				if field == name {
					want = 1
				}

				assert.Equal(t, want, object[field], field)
			}
		})
	}
}

// enforced is whether a refusal is acted on, so only enforce mode says true; a
// proxy with no budget at all is not enforcing. ns_per_block is what the budget
// believes a block costs.
func TestFakeTLSHandshakeEnforcedReflectsTheMode(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name     string
		proxy    func() *Proxy
		enforced bool
		ns       float64
	}{
		{"enforce", func() *Proxy { return newHandshakeStatsProxy(budgetEnforce, 412.5) }, true, 412.5},
		{"observe", func() *Proxy { return newHandshakeStatsProxy(budgetObserve, 77) }, false, 77},
		{"off", func() *Proxy { return newHandshakeStatsProxy(budgetOff, 12) }, false, 12},
		{"no budget", func() *Proxy {
			return newAPITestProxy(map[string]Secret{"alice": GenerateSecret("alice.example.com")})
		}, false, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			p := tc.proxy()
			p.fakeStats.OnUnmatched()

			object := handshakeObject(t, handshakeStatsOf(t, p))
			require.NotNil(t, object)

			assert.Equal(t, tc.enforced, object["enforced"])
			assert.Equal(t, tc.ns, object["ns_per_block"])
		})
	}
}

// The same through NewProxy, from the option strings a config produces: the
// mode a proxy was built with is the one /stats reports, and ns_per_block is the
// process's one calibrated reading.
func TestFakeTLSHandshakeOfARealProxyFollowsItsOpts(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		mode     string
		enforced bool
	}{
		{"", true},
		{"enforce", true},
		{"observe", false},
		{"off", false},
	} {
		t.Run("mode "+tc.mode, func(t *testing.T) {
			t.Parallel()

			opts, _ := servingOpts(t)
			opts.HandshakeBudgetMode = tc.mode

			p, err := NewProxy(opts)
			require.NoError(t, err)
			t.Cleanup(p.Shutdown)

			p.fakeStats.OnHinted()

			object := handshakeObject(t, handshakeStatsOf(t, p))
			require.NotNil(t, object)

			assert.Equal(t, tc.enforced, object["enforced"])
			assert.Equal(t, blockNanos(), object["ns_per_block"])
		})
	}
}

// The panel bills and polices every key under users as a client. Whatever the
// door has counted, users stays exactly what it was.
func TestFakeTLSHandshakeAddsNothingUnderUsers(t *testing.T) {
	t.Parallel()

	p := newHandshakeStatsProxy(budgetEnforce, 325)

	before := handshakeStatsOf(t, p)

	p.fakeStats.hinted.Add(1)
	p.fakeStats.deniedIP.Add(2)
	p.fakeStats.overBudgetMatched.Add(3)

	after := handshakeStatsOf(t, p)

	require.NotNil(t, handshakeObject(t, after))
	assert.Equal(t, before["users"], after["users"])
	assert.NotContains(t, after["users"], handshakeStatsKey)

	users, ok := after["users"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, []string{"alice"}, mapKeys(users))
}

func mapKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}

	slices.Sort(keys)

	return keys
}

// The capability name a panel matches on, and where it sits in the sorted list.
func TestHandshakeBudgetFeatureIsAdvertised(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "handshake-budget", FeatureHandshakeBudget)
	assert.Contains(t, supportedFeatures, FeatureHandshakeBudget)
	assert.True(t, slices.IsSorted(supportedFeatures), "the list is sorted so /stats is byte-stable")

	idx := slices.Index(supportedFeatures, FeatureHandshakeBudget)

	require.GreaterOrEqual(t, idx, 1)
	require.Less(t, idx, len(supportedFeatures)-1)
	assert.Equal(t, FeatureFakeTLS, supportedFeatures[idx-1])
	assert.Equal(t, FeatureIPLimits, supportedFeatures[idx+1])

	p := newAPITestProxy(map[string]Secret{"alice": GenerateSecret("alice.example.com")})

	features, ok := handshakeStatsOf(t, p)["features"].([]any)
	require.True(t, ok)
	assert.Contains(t, features, "handshake-budget")
}
