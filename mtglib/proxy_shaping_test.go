package mtglib

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A shaping the doppelganger does not know is refused when the proxy is built,
// naming what would work, instead of quietly falling back to a default.
func TestNewProxyRefusesUnknownShaping(t *testing.T) {
	t.Parallel()

	opts, _ := servingOpts(t)
	opts.DoppelGangerShaping = "pace"

	_, err := NewProxy(opts)
	require.Error(t, err)
	assert.ErrorContains(t, err, `"record"`)
	assert.ErrorContains(t, err, `"burst"`)

	for _, shaping := range []string{"", "record", "burst"} {
		opts.DoppelGangerShaping = shaping

		proxy, err := NewProxy(opts)
		require.NoError(t, err, "shaping %q", shaping)
		proxy.Shutdown()
	}
}
