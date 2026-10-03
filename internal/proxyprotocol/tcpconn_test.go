package proxyprotocol

import (
	"net"
	"testing"

	"github.com/pires/go-proxyproto"
	"github.com/stretchr/testify/require"
)

// A connection accepted through the adapter says which TCP socket it wraps.
// The WEB relay's WebSocket writes each message to that socket in one vectored
// write; through the wrapper, Go would write each piece on its own.
func TestAcceptedConnsExposeTheirTCPConn(t *testing.T) {
	t.Parallel()

	base, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	listener := &ListenerAdapter{Listener: proxyproto.Listener{
		Listener: base,
		ConnPolicy: func(proxyproto.ConnPolicyOptions) (proxyproto.Policy, error) {
			return proxyproto.REQUIRE, nil
		},
	}}
	t.Cleanup(func() { listener.Close() }) //nolint: errcheck

	client, err := net.Dial("tcp", base.Addr().String())
	require.NoError(t, err)
	t.Cleanup(func() { client.Close() }) //nolint: errcheck

	header := proxyproto.HeaderProxyFromAddrs(2, &net.TCPAddr{IP: net.IPv4(203, 0, 113, 42), Port: 40000}, base.Addr())
	_, err = header.WriteTo(client)
	require.NoError(t, err)

	accepted, err := listener.Accept()
	require.NoError(t, err)
	t.Cleanup(func() { accepted.Close() }) //nolint: errcheck

	wrapped, ok := accepted.(interface{ TCPConn() (*net.TCPConn, bool) })
	require.True(t, ok, "the accepted connection must name its TCP socket")

	tcp, ok := wrapped.TCPConn()
	require.True(t, ok)
	require.NotNil(t, tcp)
}
