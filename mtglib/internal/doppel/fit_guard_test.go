package doppel

import (
	"math"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// weibull draws n delays from the model, at full nanosecond precision.
func weibull(k, lambda float64, n int, seed uint64) []time.Duration {
	rng := rand.New(rand.NewPCG(seed, 0))
	samples := make([]time.Duration, n)

	for i := range samples {
		u := 1.0 - rng.Float64()
		samples[i] = time.Duration(lambda * math.Pow(-math.Log(u), 1.0/k) * float64(time.Millisecond))
	}

	return samples
}

// Records that arrive in one read are measured as no gap at all -- on Windows
// almost every one. A zero cannot be fitted (log 0 is -Inf, which pins the
// shape to its lowest bound and the scale to nothing); it carries no timing
// either, so the fit leaves it out and recovers the rest.
func TestNewStatsIgnoresZeroDurations(t *testing.T) {
	t.Parallel()

	samples := append(weibull(0.6, 100, 5000, 7), 0, 0, 0)

	stats := NewStats(samples, false)

	assert.InDelta(t, 0.6, stats.k, 0.05)
	assert.InDelta(t, 100, stats.lambda, 5)
	assert.True(t, stats.usable())
}

// Sub-microsecond gaps are real gaps, kept at their own precision rather than
// truncated to zero.
func TestNewStatsKeepsSubMicrosecondDurations(t *testing.T) {
	t.Parallel()

	samples := weibull(0.6, 0.002, 5000, 11) // λ = 2 µs: many gaps under 1 µs

	stats := NewStats(samples, false)

	assert.InDelta(t, 0.6, stats.k, 0.05)
	assert.True(t, stats.usable())
}

// The ganger asks for MinDurationsToCalculate gaps before fitting, but counts
// them before the zeros are left out: a raid of 97 zeros and 3 real gaps must
// not be fitted to those three.
func TestTooFewRealGapsAreNotUsable(t *testing.T) {
	t.Parallel()

	samples := append(make([]time.Duration, MinDurationsToCalculate-3), weibull(0.6, 100, 3, 1)...)

	assert.False(t, NewStats(samples, false).usable())
}

// A fit that lands on a search bound, or has no finite scale, would pace
// connections with nonsense -- minutes between records, or none. It is not
// usable.
func TestDegenerateFitsAreNotUsable(t *testing.T) {
	t.Parallel()

	identical := make([]time.Duration, 200)
	for i := range identical {
		identical[i] = 5 * time.Millisecond
	}

	zeros := make([]time.Duration, 200)

	assert.False(t, NewStats(identical, false).usable(), "identical gaps pin the shape to its upper bound")
	assert.False(t, NewStats(zeros, false).usable(), "nothing to fit")
	assert.False(t, Stats{k: StatsLowK, lambda: 1}.usable())
	assert.False(t, Stats{k: 0.5, lambda: math.Inf(1)}.usable())
	assert.False(t, Stats{k: 0.5, lambda: math.NaN()}.usable())
	assert.True(t, Stats{k: StatsDefaultK, lambda: StatsDefaultLambda}.usable())
}

// The ganger keeps the model it has when a raid's fit is not usable, rather
// than handing every new connection a broken one.
func TestGangerKeepsItsModelWhenAFitIsUnusable(t *testing.T) {
	t.Parallel()

	g := NewGanger(t.Context(), SimpleNetwork{}, quietLogger(), time.Hour, 1, nil, false, ShapingRecord, false)
	before := g.stats

	g.adopt(NewStats(make([]time.Duration, 200), false))
	assert.Equal(t, before, g.stats, "an unusable fit must be refused")

	fitted := NewStats(weibull(0.6, 100, 5000, 3), false)

	g.adopt(fitted)
	assert.Equal(t, fitted, g.stats, "a usable fit is taken")
}

// However wide the model, no delay is longer than MaxDelay, and none is
// negative: a draw past what a Duration holds would otherwise overflow.
func TestDelayIsCapped(t *testing.T) {
	t.Parallel()

	wide := Stats{k: 0.05, lambda: 1e6}

	for range 10000 {
		d := wide.Delay()

		require.GreaterOrEqual(t, d, time.Duration(0))
		require.LessOrEqual(t, d, MaxDelay)
	}
}

// The default model is not changed by the cap in any way that matters: it
// waits longer than MaxDelay about once in sixty thousand records.
func TestDelayCapLeavesTheDefaultModelAlone(t *testing.T) {
	t.Parallel()

	stats := Stats{k: StatsDefaultK, lambda: StatsDefaultLambda}
	capped := 0

	for range 100000 {
		if stats.Delay() == MaxDelay {
			capped++
		}
	}

	assert.Less(t, capped, 20)
}

// A cover raid measures what the cover sites' certificates weigh, and nothing
// else: their record timing would replace the model every connection is paced
// by -- a change a censor can see, which ships only behind shaping and the
// canary, never as a side effect of naming a cover host.
func TestCoverRaidsMeasureCertificatesNotTiming(t *testing.T) {
	t.Parallel()

	site := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		chunk := make([]byte, 16<<10)

		for range 16 {
			w.Write(chunk)           //nolint: errcheck
			w.(http.Flusher).Flush() //nolint: forcetypeassert
		}
	}))
	site.TLS = newCoverServer(t, 0).TLS
	site.StartTLS()
	t.Cleanup(site.Close)

	cover := CoverHost{Host: "a.test", Addr: site.Listener.Addr().String()}

	g := NewGanger(t.Context(), SimpleNetwork{}, quietLogger(), time.Hour, 2, nil, false, ShapingRecord, true)
	results := make(chan scoutRaidResult, 1)

	go g.runScoutRaid(results, []CoverHost{cover})

	result := <-results

	require.NotEmpty(t, result.hostCertSizes["a.test"], "precondition: the cover site was measured")
	assert.Empty(t, result.durations, "a cover raid must not feed the timing model")
}
