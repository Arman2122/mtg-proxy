package mtglib

import (
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Arman2122/mtg-proxy/essentials"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Each connected address carries the second it last moved a byte: the latest
// stamp across the streams sharing it, so a device that fell silent reads as
// silent while its sibling on the same address talks. A stream never stamped
// is listed with no time, and a stream with no address is not listed at all.
func TestClientAddressActivity(t *testing.T) {
	t.Parallel()

	stamped := func(ip string, unix int64) *streamContext {
		sc := &streamContext{clientSocket: remoteAddrConn{addr: tcpFrom(ip, 40000)}}
		sc.lastActiveUnix.Store(unix)

		return sc
	}

	addresses, seen := clientAddressActivity([]*streamContext{
		stamped("203.0.113.9", 1_700_000_000),
		stamped("203.0.113.9", 1_700_000_050),
		stamped("198.51.100.7", 1_700_000_010),
		stamped("192.0.2.1", 0),
		{},
	})

	assert.Equal(t, []string{"192.0.2.1", "198.51.100.7", "203.0.113.9"}, addresses)
	assert.Equal(t, map[string]time.Time{
		"203.0.113.9":  time.Unix(1_700_000_050, 0).UTC(),
		"198.51.100.7": time.Unix(1_700_000_010, 0).UTC(),
	}, seen)

	addresses, seen = clientAddressActivity(nil)
	assert.Nil(t, addresses)
	assert.Nil(t, seen)
}

// The data path stamps the stream it was pointed at on every byte moved, and a
// wrapper built without a stamp moves bytes and stamps nothing.
func TestCountingConnStampsActivity(t *testing.T) {
	t.Parallel()

	var active atomic.Int64

	client, server := net.Pipe()
	t.Cleanup(func() { client.Close(); server.Close() }) //nolint: errcheck

	go func() { io.Copy(io.Discard, server) }() //nolint: errcheck

	stats := NewProxyStats()
	conn := newCountingConn(t.Context(), nil, essentials.WrapNetConn(client), stats, "alice").withActivity(&active)

	before := time.Now().Unix()
	_, err := conn.Write([]byte("hello"))
	require.NoError(t, err)
	assert.GreaterOrEqual(t, active.Load(), before, "a write stamps the second it happened")

	bare := newCountingConn(t.Context(), nil, essentials.WrapNetConn(client), stats, "alice")
	_, err = bare.Write([]byte("hello"))
	require.NoError(t, err, "no stamp is not an error")
}
