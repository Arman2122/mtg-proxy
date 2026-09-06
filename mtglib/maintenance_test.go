package mtglib

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// awaitClosed waits for a stream to be cancelled, bounded.
func awaitClosed(sc *streamContext, within time.Duration) bool {
	timer := time.NewTimer(within)
	defer timer.Stop()

	select {
	case <-sc.Done():
		return true
	case <-timer.C:
		return false
	}
}

// An expiry is a deadline, not a hint: a user connected when it passes is
// disconnected by the clock, with nothing else touching the secret set. A
// user whose deadline has not passed is left alone by the same sweep.
func TestExpiryEndsALiveSessionOnTheClock(t *testing.T) {
	t.Parallel()

	secrets := map[string]Secret{
		"soon":  GenerateSecret("s.example.com"),
		"later": GenerateSecret("l.example.com"),
	}
	limits := map[string]SecretLimits{
		"soon":  {ExpiresAt: time.Now().Add(150 * time.Millisecond)},
		"later": {ExpiresAt: time.Now().Add(time.Hour)},
	}

	p := newLimitTestProxy(secrets, limits)
	p.logger = testLogger()

	soon := registerFakeStream(p, "soon")
	later := registerFakeStream(p, "later")

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	p.startMaintenance(ctx, 20*time.Millisecond, time.Hour)

	require.True(t, awaitClosed(soon, 3*time.Second),
		"a stream must be closed once its user's expiry passes, without a reload")
	assert.NoError(t, later.Err(), "a stream whose user has not expired is left alone")
}

// The loop runs whether or not a usage file is configured. It used to run
// only with one, so an expiry on a deployment without quotas was never
// enforced on the clock at all.
func TestMaintenanceRunsWithoutAUsageFile(t *testing.T) {
	t.Parallel()

	opts, _ := servingOpts(t)
	opts.SecretLimits = map[string]SecretLimits{"alice": {ExpiresAt: time.Now().Add(time.Second)}}
	require.Empty(t, opts.UsageStateFile)

	proxy, err := NewProxy(opts)
	require.NoError(t, err)
	t.Cleanup(proxy.Shutdown)

	stream := registerFakeStream(proxy, "alice")

	require.True(t, awaitClosed(stream, 3*denySweepInterval),
		"a proxy with no usage file must still sweep expired users off on the clock")
}
