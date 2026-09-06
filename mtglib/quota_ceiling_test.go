package mtglib

import (
	"context"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/Arman2122/mtg-proxy/essentials"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// quotaPair is a countingConn over one end of a TCP pair, with the other end
// in hand, for a user with the given quota. The counter starts at used.
func quotaPair(t *testing.T, quota, used int64) (*countingConn, net.Conn, *ProxyStats) {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	defer listener.Close() //nolint: errcheck

	far, err := net.Dial("tcp", listener.Addr().String())
	require.NoError(t, err)
	t.Cleanup(func() { far.Close() }) //nolint: errcheck

	near, err := listener.Accept()
	require.NoError(t, err)
	t.Cleanup(func() { near.Close() }) //nolint: errcheck

	stats := NewProxyStats()
	stats.SetQuotaCeiling("alice", quota)
	stats.getOrCreate("alice").quotaUsed.Store(used)

	return newCountingConn(context.Background(), nil, essentials.WrapNetConn(near), stats, "alice"), far, stats
}

// The ceiling is exact in the write direction: a write that would cross it
// delivers exactly up to the cap and ends the stream there, and the next
// write from any stream of that user ends at once.
func TestQuotaCeilingEndsAWriteAtTheCap(t *testing.T) {
	t.Parallel()

	const quota = 10 << 10

	conn, far, stats := quotaPair(t, quota, 0)

	received := make(chan int, 1)

	go func() {
		n, _ := io.Copy(io.Discard, far)
		received <- int(n)
	}()

	n, err := conn.Write(make([]byte, 4<<10))
	require.NoError(t, err)
	assert.Equal(t, 4<<10, n)

	// 4 KiB more than the cap: the write stops at the byte that reaches it.
	n, err = conn.Write(make([]byte, 10<<10))
	require.ErrorIs(t, err, errQuotaExhausted)
	assert.Equal(t, 6<<10, n, "exactly what was left")
	assert.EqualValues(t, quota, stats.getOrCreate("alice").quotaUsed.Load(), "not a byte past the cap")

	// Another stream of the same user, on its first byte.
	other, _, _ := quotaPair(t, quota, quota)

	n, err = other.Write([]byte("x"))
	require.ErrorIs(t, err, errQuotaExhausted)
	assert.Zero(t, n)

	// Counted once for this stream, however often it hits the ceiling.
	_, err = conn.Write([]byte("x"))
	require.ErrorIs(t, err, errQuotaExhausted)
	assert.EqualValues(t, 1, stats.getOrCreate("alice").quotaCutoffs.Load())

	require.NoError(t, conn.Close())
	assert.Equal(t, quota, <-received, "the far end got exactly the quota")
}

// The same in the read direction: an upload is read up to the cap and no
// further, so nothing past it is consumed, let alone forwarded.
func TestQuotaCeilingEndsAReadAtTheCap(t *testing.T) {
	t.Parallel()

	const quota = 10 << 10

	conn, far, stats := quotaPair(t, quota, 0)

	go func() {
		far.Write(make([]byte, 16<<10)) //nolint: errcheck
	}()

	require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))

	var got int

	buf := make([]byte, 64<<10)

	for {
		n, err := conn.Read(buf)
		got += n

		if err != nil {
			require.ErrorIs(t, err, errQuotaExhausted)

			break
		}
	}

	assert.Equal(t, quota, got, "read exactly up to the cap")
	assert.EqualValues(t, quota, stats.getOrCreate("alice").quotaUsed.Load())
	assert.EqualValues(t, 1, stats.getOrCreate("alice").quotaCutoffs.Load())

	_, err := conn.Read(buf)
	require.ErrorIs(t, err, errQuotaExhausted, "nothing more is ever read")
}

// Without a quota the path is what it was: a single read, a single write,
// no allowance arithmetic in the way.
func TestNoQuotaIsNoCeiling(t *testing.T) {
	t.Parallel()

	conn, far, stats := quotaPair(t, 0, 1<<40)

	go func() {
		io.Copy(io.Discard, far) //nolint: errcheck
	}()

	n, err := conn.Write(make([]byte, 1<<20))
	require.NoError(t, err)
	assert.Equal(t, 1<<20, n)
	assert.Zero(t, stats.getOrCreate("alice").quotaCutoffs.Load())
}

// Through the proxy, on every door: a user whose remaining quota is smaller
// than what Telegram sends gets exactly the remainder, the stream ends, the
// cutoff is counted, and their next connection is refused at the door.
func TestQuotaEndsTheStreamThatCrossesItAcrossEntries(t *testing.T) {
	t.Parallel()

	for _, ec := range govEntryCases() {
		t.Run(ec.name, func(t *testing.T) {
			t.Parallel()

			const quota = 8 << 10

			secret := ec.secret(t)
			h := ec.harness(t, map[string]Secret{"alice": secret},
				map[string]SecretLimits{"alice": {QuotaBytes: quota}})

			stream := ec.connect(t, h, "alice", secret.Key)

			// Telegram sends twice what alice has left.
			_, err := stream.upstream.Write(make([]byte, 2*quota))
			require.NoError(t, err)

			require.True(t, govAwait(stream.done, govDenyBudget),
				"the stream must end at the cap, not carry on past it")

			alice := h.proxy.stats.users["alice"]
			assert.EqualValues(t, quota, alice.quotaUsed.Load(), "not a byte past the cap")
			assert.EqualValues(t, 1, alice.quotaCutoffs.Load())

			// And the door is shut: the next connection is refused at entry,
			// disposed of the way this door disposes of a denied user.
			client, done := h.dialProxy(t, ec.policy)
			ec.openEntry(t, client, secret.Key)
			require.True(t, govAwait(done, govDenyBudget), "an exhausted user must be refused")
			assert.Equal(t, ec.frontingsOnEntryDeny, h.events.frontings())
		})
	}
}

// The ceiling follows the secret set: set through the API it binds the live
// counter at once, and removed it frees it.
func TestQuotaCeilingFollowsTheAPI(t *testing.T) {
	t.Parallel()

	alice := GenerateSecret("alice.example.com")
	p := newAPITestProxy(map[string]Secret{"alice": alice})

	require.Equal(t, http.StatusOK, doAPI(t, p, "", http.MethodPut, "/secrets",
		`{"secrets":{"alice":{"secret":"`+alice.Hex()+`","quota":"10MB"}}}`).Code)
	assert.EqualValues(t, 10<<20, p.stats.getOrCreate("alice").quotaCeiling.Load())

	require.Equal(t, http.StatusOK, doAPI(t, p, "", http.MethodPut, "/secrets",
		`{"secrets":{"alice":{"secret":"`+alice.Hex()+`"}}}`).Code)
	assert.Zero(t, p.stats.getOrCreate("alice").quotaCeiling.Load())
}
