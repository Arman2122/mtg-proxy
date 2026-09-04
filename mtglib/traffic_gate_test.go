package mtglib

import (
	"bytes"
	"io"
	"testing"
	"time"

	"github.com/Arman2122/mtg-proxy/internal/testlib"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestWrapTrafficGating verifies that connTraffic (and thus per-read/write
// EventTraffic allocation) is only added when metrics are configured.
func TestWrapTrafficGating(t *testing.T) {
	t.Parallel()

	conn := &testlib.EssentialsConnMock{}
	ctx := &streamContext{streamID: "s"}

	t.Run("emitTraffic=false returns the bare conn", func(t *testing.T) {
		t.Parallel()

		p := &Proxy{emitTraffic: false}
		got := p.wrapTraffic(conn, ctx)

		_, wrapped := got.(connTraffic)
		assert.False(t, wrapped, "must not wrap when no metrics observer is configured")
		assert.True(t, got == conn, "must return the same conn unchanged")
	})

	t.Run("emitTraffic=true wraps in connTraffic", func(t *testing.T) {
		t.Parallel()

		p := &Proxy{emitTraffic: true}
		got := p.wrapTraffic(conn, ctx)

		_, wrapped := got.(connTraffic)
		assert.True(t, wrapped, "must wrap so traffic events reach the observers")
	})
}

// TestGovernanceBillsMatchedSecretAcrossEntries runs the relay's byte counter
// over both doors, in both directions.
//
// countingConn is constructed from ctx.secretName, and on the plaintext door
// that name exists only because attribution was moved ahead of accounting. If
// it were still resolved where the ee path used to resolve it, every dd user's
// traffic would be billed to the "" bucket -- invisible on /stats, and, because
// quota is metered off the very same counter, an unlimited quota for everybody
// who came in that door.
//
// Both directions, because on a proxy the download half is the bigger half: a
// quota that only meters uploads is barely a quota at all. The Read and Write
// halves of countingConn are separate code, and only traffic that actually
// flows telegram->client exercises the second one.
func TestGovernanceBillsMatchedSecretAcrossEntries(t *testing.T) {
	t.Parallel()

	for _, ec := range govEntryCases() {
		t.Run(ec.name, func(t *testing.T) {
			t.Parallel()

			target := ec.secret(t)
			other := ec.secret(t)

			h := ec.harness(t, map[string]Secret{"alice": target, "bob": other}, nil)

			// Resolve the counters BEFORE the stream runs: a mutation that bills
			// the wrong name calls getOrCreate on it, which writes the users map,
			// and an unlocked read here would surface as a data race instead of
			// the assertion going red.
			h.proxy.stats.mu.RLock()
			aliceStats := h.proxy.stats.users["alice"]
			bobStats := h.proxy.stats.users["bob"]
			h.proxy.stats.mu.RUnlock()

			stream := ec.connect(t, h, "alice", target.Key)

			payload := bytes.Repeat([]byte{0x7e}, 1024)
			want := int64(len(payload))

			_, err := stream.client.Write(ec.framePayload(payload))
			require.NoError(t, err)

			// Reading the relayed bytes at the Telegram end is the
			// synchronisation for this direction: every byte that arrives there
			// has already been counted on the way through.
			require.NoError(t, stream.upstream.SetReadDeadline(time.Now().Add(5*time.Second)))

			relayed := make([]byte, len(payload))

			_, err = io.ReadFull(stream.upstream, relayed)
			require.NoError(t, err)

			// Exact, not "at least": counting sits above both length-preserving
			// layers (the TLS record reader on ee, the CTR stream on dd) and the
			// 64-byte handshake frame is consumed before countingConn exists on
			// either path. A discrepancy between the two rows would be a real
			// divergence, not a tolerance to widen.
			assert.Equal(t, want, aliceStats.bytesIn.Load(),
				"the relay must bill the secret this door matched")

			// Now telegram->client, through the Write half.
			_, err = stream.upstream.Write(payload)
			require.NoError(t, err)

			// This direction has no downstream observation point: both Adds run
			// AFTER Conn.Write has already handed the bytes to the client, so
			// seeing them arrive would prove nothing. Poll instead. The client
			// deliberately never reads -- 1KiB fits in the socket buffer, and on
			// ee the bytes are inside faketls records it has no reader for.
			require.Eventually(t, func() bool {
				return aliceStats.bytesIn.Load()+aliceStats.bytesOut.Load() == 2*want
			}, 3*time.Second, 5*time.Millisecond,
				"the egress direction must reach the byte counter at all")

			require.Eventually(t, func() bool {
				return aliceStats.quotaUsed.Load() == 2*want
			}, 3*time.Second, 5*time.Millisecond,
				"both directions must be charged against the user's quota")

			// Which counter the egress landed in, now that it is known to have
			// landed in one of them.
			assert.Equal(t, want, aliceStats.bytesOut.Load(),
				"egress must be billed as bytesOut")
			assert.Equal(t, want, aliceStats.bytesIn.Load(),
				"and must not be folded into the ingress counter")

			assert.Equal(t, int64(0), bobStats.quotaUsed.Load(),
				"no other configured user may be charged for it")

			stream.close()
		})
	}
}
