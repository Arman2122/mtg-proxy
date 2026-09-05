package cli

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/Arman2122/mtg-proxy/mtglib"
	"github.com/pires/go-proxyproto"
	"github.com/stretchr/testify/require"
)

// A listener that expects a PROXY header reports the address the HEADER names,
// not the address the socket was dialled from.
//
// This is the whole point of the four-hop chain a WEB deployment runs through,
// and it is what makes /stats' connected_ips and last_ip worth having there: a
// browser reaches Caddy, Caddy reaches the relay, the relay dials this socket
// on loopback. Every one of those connections has a peer address of
// 127.0.0.1, so a proxy reading the socket would file every WEB user in the
// world under the same address and report it with a straight face.
//
// TestExtraListenerProxyProtocolIsPerListener already asserts the wrapper is
// APPLIED. Nothing asserted what it produces -- which is the half that has to
// be true for the address a panel shows an operator to mean anything.
func TestProxyProtocolListenerReportsTheHeaderAddress(t *testing.T) {
	t.Parallel()

	raw, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	defer raw.Close() //nolint: errcheck

	listener := maybeProxyProtocol(raw, true)

	// The address a browser would have, arriving at a front proxy that then
	// declares it on the relay's behalf. Deliberately not a loopback address:
	// the failure this guards against is reporting 127.0.0.1, so an expectation
	// that was itself loopback could not tell the two apart.
	client := &net.TCPAddr{IP: net.IPv4(198, 51, 100, 23), Port: 54321}

	accepted := make(chan net.Conn, 1)
	failed := make(chan error, 1)

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			failed <- err

			return
		}

		// go-proxyproto parses the header lazily, on the first read or on
		// RemoteAddr. Reading first is what a real entry does, so the header
		// is consumed the same way here.
		one := make([]byte, 1)
		if _, err := conn.Read(one); err != nil {
			failed <- err

			return
		}

		accepted <- conn
	}()

	upstream, err := net.Dial("tcp", raw.Addr().String())
	require.NoError(t, err)

	defer upstream.Close() //nolint: errcheck

	header := &proxyproto.Header{
		Version:           2,
		Command:           proxyproto.PROXY,
		TransportProtocol: proxyproto.TCPv4,
		SourceAddr:        client,
		DestinationAddr:   &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 2398},
	}

	_, err = header.WriteTo(upstream)
	require.NoError(t, err)

	// One byte of payload behind the header, so the read above returns.
	_, err = upstream.Write([]byte{0xdd})
	require.NoError(t, err)

	select {
	case err := <-failed:
		require.NoError(t, err)
	case conn := <-accepted:
		defer conn.Close() //nolint: errcheck

		require.Equal(t, client.String(), conn.RemoteAddr().String(),
			"the accepted connection must report the browser's address, "+
				"not the loopback hop that declared it")

		// The exact shape the proxy's own address reader requires: it type
		// asserts to *net.TCPAddr and refuses the connection otherwise, so a
		// header that produced any other address type would be dropped rather
		// than reported.
		tcpAddr, ok := conn.RemoteAddr().(*net.TCPAddr)
		require.True(t, ok, "the proxy's address reader accepts only *net.TCPAddr")
		require.Equal(t, "198.51.100.23", tcpAddr.IP.String())
	case <-time.After(10 * time.Second):
		t.Fatal("the listener never accepted the connection")
	}
}

// Without the option, the same listener reports the socket's own peer -- so the
// wrapper is what changes the answer, and it is applied per listener.
func TestPlainListenerReportsTheSocketAddress(t *testing.T) {
	t.Parallel()

	raw, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	defer raw.Close() //nolint: errcheck

	listener := maybeProxyProtocol(raw, false)
	require.Equal(t, raw, listener, "an unwrapped listener must be the listener itself")

	accepted := make(chan net.Conn, 1)

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}

		accepted <- conn
	}()

	upstream, err := net.Dial("tcp", raw.Addr().String())
	require.NoError(t, err)

	defer upstream.Close() //nolint: errcheck

	select {
	case conn := <-accepted:
		defer conn.Close() //nolint: errcheck

		require.Equal(t, upstream.LocalAddr().String(), conn.RemoteAddr().String())
	case <-time.After(10 * time.Second):
		t.Fatal("the listener never accepted the connection")
	}
}

// The relay's backend listener and the public one disagree about PROXY headers,
// and that disagreement is the configuration a WEB deployment actually runs.
//
// A header sent to a socket not expecting one is eaten as the first bytes of an
// obfuscated handshake, and a socket expecting one that never arrives blocks --
// either way every stream dies with nothing useful in a log. Both sockets are
// built from one config, so this pins that they are decided separately.
func TestWebDeploymentShapeBuildsBothListeners(t *testing.T) {
	t.Parallel()

	ports, held := holdPorts(t, 3)
	conf := parseConfig(t, fmt.Sprintf(`
secret = "%s"
bind-to = "127.0.0.1:%d"
track-client-ips = true

# The public obfuscated2 door: real clients dial it directly and send no
# header.
[[listener]]
bind-to = "127.0.0.1:%d"
accept = ["dd"]
public = true

# The relay's backend: the relay always sends one.
[[listener]]
bind-to = "127.0.0.1:%d"
accept = ["dd"]
proxy-protocol = true
`, mtglib.GenerateSecret("cover.example.com").Hex(), held[0], held[1], held[2]))

	require.True(t, conf.TrackClientIPs.Get(false),
		"the option must survive a config that also declares listeners")

	served, err := buildListenersWith(conf, newRecordingLogger(), ports.listen)
	require.NoError(t, err)
	closeServed(t, served)
	require.Empty(t, ports.remaining())

	require.Len(t, served, 3, "bind-to plus both listeners")

	public := served[1]
	backend := served[2]

	require.Equal(t, public.raw, public.serve,
		"a socket real clients dial must not expect a PROXY header")
	require.NotEqual(t, backend.raw, backend.serve,
		"the relay's backend must expect one")
}
