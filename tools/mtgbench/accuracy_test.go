package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The speed limiter starts a user with one second of burst, so the first
// second of a capped transfer runs above the cap by design. Accuracy is the
// seconds after it.
func TestCapAccuracyIgnoresTheBurstSecond(t *testing.T) {
	t.Parallel()

	const target = 1 << 20

	perSecond := []float64{2 * target, target, 0.9 * target, 1.1 * target, target}

	a := capAccuracy(perSecond, target)

	assert.InDelta(t, 1.0, a.mean, 1e-9, "the burst second would have made it 1.2")
	assert.InDelta(t, 0.9, a.p10, 1e-9)
	assert.InDelta(t, 1.1, a.p90, 1e-9)
}

// Jain's fairness index: (Σx)² / (n·Σx²). One for equal shares, 1/n when one
// connection has everything.
func TestJainIndex(t *testing.T) {
	t.Parallel()

	assert.InDelta(t, 1.0, jain([]float64{5, 5, 5, 5}), 1e-9)
	assert.InDelta(t, 0.25, jain([]float64{8, 0, 0, 0}), 1e-9)
	assert.InDelta(t, 36.0/42, jain([]float64{1, 2, 3}), 1e-9)
	assert.InDelta(t, 1.0, jain([]float64{0, 0}), 1e-9, "nobody got anything: equally")
}

// A client that vanishes mid-download leaves bytes in buffers the proxy has
// already counted: counted may exceed received, and that is a bound, not an
// error. Counting less than the client received, or more than the data
// centre ever sent (give or take one of its writes), is an error.
func TestAccountingBoundsAnAbruptDisconnect(t *testing.T) {
	t.Parallel()

	const received, sent = 4 << 20, 9 << 20

	require.NoError(t, abruptVerdict(received, received, sent), "nothing in flight")
	require.NoError(t, abruptVerdict(received, received+3<<20, sent), "3 MiB in buffers is the bound at work")
	require.NoError(t, abruptVerdict(received, sent+dcChunk, sent), "one data-centre write may be half counted")

	require.ErrorIs(t, abruptVerdict(received, received-1, sent), errUndercounted)
	require.ErrorIs(t, abruptVerdict(received, sent+dcChunk+1, sent), errOvercounted)
}

// A clean transfer is counted exactly, by the proxy and, for WEB, by the
// relay, which also carries the client's 64-byte obfuscated2 frame.
func TestCleanAccountingMatchesExactly(t *testing.T) {
	t.Parallel()

	client := traffic{written: 1000, read: 2000}

	exact := accountingDiff(client, traffic{written: 1000, read: 2000}, nil)
	assert.Equal(t, Sample{"in-diff": 0, "out-diff": 0}, exact.sample)
	require.NoError(t, exact.err)

	relay := traffic{written: 1064, read: 2000}
	web := accountingDiff(client, traffic{written: 1000, read: 2000}, &relay)
	assert.Equal(t, Sample{"in-diff": 0, "out-diff": 0, "up-diff": 0, "down-diff": 0}, web.sample)
	require.NoError(t, web.err)

	short := accountingDiff(client, traffic{written: 1000, read: 1999}, nil)
	assert.InDelta(t, -1, short.sample["out-diff"], 0)
	require.ErrorIs(t, short.err, errMiscounted)
}
