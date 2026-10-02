package doppel

import (
	"math"
	"math/rand/v2"
	"time"
)

const (
	StatsBisectTimes = 70
	StatsLowK        = 0.01
	StatsHighK       = 10.0

	// do not calculate statistics if we have < than this number of durations
	MinDurationsToCalculate = 100

	// these values are taken from ok.ru. measured from moscow site.
	StatsDefaultK      = 0.37846373895785335
	StatsDefaultLambda = 1.73177086015485

	// how many bytes should we drift
	DRSNoise = 100

	// MaxDelay is the longest wait Delay draws. No web server pauses that
	// long between the records of one response, and the default model waits
	// longer about once in sixty thousand records; the cap is there so a wide
	// fitted model cannot stall a connection for minutes, or overflow a
	// Duration into a negative wait.
	MaxDelay = time.Second
)

// Stats is responsible for generating values that are distributed according
// to some statistical distribution.
//
// It follows several ideas:
//  1. Based on nginx and Cloudflare behaviour, even if server is eager
//     to send a lot, they all start with small TLS packets that are
//     approximately MTU-sized. After
//  2. After ~40 TLS records, server considers TCP session as somewhat solid
//     and reliable and ramps up to 4096.
//  3. After ~20 TLS records more it jumps to the max 16384 bytes and keep
//     this size as long as it can
//  4. If there is no any byte within a connection for a longer time period,
//     this counter resets.
//
// This is called Dynamic TLS Record Sizing
//   - https://blog.cloudflare.com/optimizing-tls-over-tcp-to-reduce-latency/
//   - https://community.f5.com/kb/technicalarticles/boosting-tls-performance-with-dynamic-record-sizing-on-big-ip/280798
//   - https://www.igvita.com/2013/10/24/optimizing-tls-record-size-and-buffering-latency/
//
// And this optimized for the very first byte, so web browsers could start to
// render as early as possible, showing user some preliminary results, optimizing
// for perceived latency.
//
// Since this is very typical for the website, we also aim for that.
//
// Another important idea is how delays between TLS packets are distributed.
// In case of sending huge heavy content with max sized record, delays have
// lognormal distribution. But a nature of a typical website shows that
// it eagers to deliver as fast as it can in a few very first records and
// could possibly slow down later.
//
// This is perfectly described by Weibull distribution:
//   - https://en.wikipedia.org/wiki/Weibull_distribution
//   - https://ieeexplore.ieee.org/document/6662948
//   - https://www.researchgate.net/publication/224621285_Traffic_modelling_and_cost_optimization_for_transmitting_traffic_messages_over_a_hybrid_broadcast_and_cellular_network
//   - https://ir.uitm.edu.my/id/eprint/105386/1/105386.pdf
//
// In other word, a combination of Dynamic TLS Record Sizing hints us for
// Weibull distribution.
//
// But we also have to keep in mind that DRS is not well spread yet. In most cases
// users still rely on OpenSSL or webserver defaults. OpenSSL chunks with
// biggest packet sizes, nginx relies on static setting that is 16k by default.
// Thus, dynamic sizing has to be present but we cannot oblige users to use that.
type Stats struct {
	sizeLastRequested time.Time
	sizeCounter       int

	// https://en.wikipedia.org/wiki/Shape_parameter
	k float64
	// https://en.wikipedia.org/wiki/Scale_parameter
	lambda float64

	// Dynamic Record Sizing
	drs bool
}

func (d *Stats) Delay() time.Duration {
	// u ∈ (0, 1], avoids ln(0)
	u := 1.0 - rand.Float64()

	// X = λ·(-ln U)^(1/k)
	generated := d.lambda * math.Pow(-math.Log(u), 1.0/d.k)

	// generated is in milliseconds
	if limit := float64(MaxDelay) / float64(time.Millisecond); math.IsNaN(generated) || generated >= limit {
		return MaxDelay
	}

	return time.Duration(generated * float64(time.Millisecond))
}

// usable reports whether a fitted model can pace connections: a shape inside
// the search bounds, not pinned to one, and a finite, positive scale. Gaps
// that are all the same pin the shape to its upper bound; nothing to fit
// leaves the scale NaN.
func (d Stats) usable() bool {
	const margin = 1e-6

	return d.k > StatsLowK*(1+margin) && d.k < StatsHighK*(1-margin) &&
		d.lambda > 0 && !math.IsInf(d.lambda, 0)
}

func (d *Stats) Size() int {
	if time.Since(d.sizeLastRequested) > TLSRecordSizeResetAfter {
		d.sizeCounter = 0
	}

	if !d.drs {
		return TLSRecordSizeMax
	}

	d.sizeLastRequested = time.Now()
	d.sizeCounter++

	switch {
	case d.sizeCounter <= TLSCounterAccelAfter:
		return TLSRecordSizeStart - rand.IntN(DRSNoise)
	case d.sizeCounter <= TLSCounterMaxAfter:
		return TLSRecordSizeAccel - rand.IntN(DRSNoise)
	}

	return TLSRecordSizeMax
}

// NewStats fits the model to measured gaps between records. A gap of zero --
// records that arrived in one read, as nearly all do on Windows -- carries no
// timing and cannot be fitted (log 0 is -Inf), so it is left out; the rest are
// kept at full precision rather than truncated to whole microseconds, which
// would turn every sub-microsecond gap into such a zero. Fewer than
// MinDurationsToCalculate real gaps give no fit at all. The result can be
// unusable; see usable.
func NewStats(durations []time.Duration, drs bool) Stats {
	// in milliseconds
	durFloats := make([]float64, 0, len(durations))

	for _, v := range durations {
		if v > 0 {
			durFloats = append(durFloats, float64(v)/float64(time.Millisecond))
		}
	}

	// Too few real gaps once the zeros are out: the zero model, which is not
	// usable, rather than a fit to a handful.
	if len(durFloats) < MinDurationsToCalculate {
		return Stats{drs: drs}
	}

	n := float64(len(durFloats))

	// The bisection solves the standard Weibull MLE equation for shape
	// parameter k. There is no any good formula for doing that so we
	// approximate it by several bisections. The number of operations
	// is statically defined by a constant.

	sumLog := 0.0
	for _, v := range durFloats {
		sumLog += math.Log(v)
	}

	lowK := StatsLowK
	highK := StatsHighK

	for range StatsBisectTimes {
		midK := (lowK + highK) / 2.0
		sumXK := 0.0
		sumXKLog := 0.0

		for _, v := range durFloats {
			xk := math.Pow(v, midK)
			sumXK += xk
			sumXKLog += xk * math.Log(v)
		}

		if (1.0/midK)+(sumLog/n)-(sumXKLog/sumXK) > 0 {
			lowK = midK
		} else {
			highK = midK
		}
	}

	k := (lowK + highK) / 2

	sumXK := 0.0
	for _, v := range durFloats {
		sumXK += math.Pow(v, k)
	}

	// λ = (Σxᵢᵏ / n)^(1/k)
	lambda := math.Pow(sumXK/n, 1.0/k)

	return Stats{
		k:      k,
		lambda: lambda,
		drs:    drs,
	}
}
