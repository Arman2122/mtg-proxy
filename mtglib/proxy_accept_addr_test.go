package mtglib

import (
	"net"
	"testing"
)

/*
The accept loop used to read the client IP with

	conn.RemoteAddr().(*net.TCPAddr).IP  //nolint: forcetypeassert

and that assert is reachable from the network.

With proxy-protocol-listener on, RemoteAddr is not the socket's peer -- it is
whatever the PROXY header says. go-proxyproto's default policy is USE, and this
proxy sets neither Policy nor ConnPolicy, so any peer that can reach the port
supplies that header. A v2 header declaring a UDP transport yields a
*net.UDPAddr, a Unix transport yields a *net.UnixAddr, and an UNSPEC transport
(or a family that is neither stream nor datagram) leaves SourceAddr nil.

Each of those fails the assert. Serve runs as `go proxy.Serve(listener)` with no
recover, and an unrecovered panic in any goroutine ends the Go process -- so one
crafted header takes down the proxy and every client on it.

The connection is refused now instead. A TCP listener has no business with an
address that is not a TCP one, so this widens nothing: without the PROXY
listener, RemoteAddr on a *net.TCPConn is always a *net.TCPAddr.
*/
func TestAnAcceptedAddressThatIsNotTCPIsRefusedRatherThanFatal(t *testing.T) {
	cases := []struct {
		name   string
		addr   net.Addr
		usable bool
		why    string
	}{
		{
			name:   "an ordinary TCP peer",
			addr:   &net.TCPAddr{IP: net.IPv4(203, 0, 113, 7), Port: 4444},
			usable: true,
			why:    "the only shape a TCP listener should ever produce",
		},
		{
			name:   "an IPv6 TCP peer",
			addr:   &net.TCPAddr{IP: net.ParseIP("2001:db8::1"), Port: 4444},
			usable: true,
			why:    "same, over v6",
		},
		{
			name:   "a PROXY v2 header declaring a datagram transport",
			addr:   &net.UDPAddr{IP: net.IPv4(203, 0, 113, 7), Port: 4444},
			usable: false,
			why:    "go-proxyproto builds a *net.UDPAddr for it; the assert panicked and killed the process",
		},
		{
			name:   "a PROXY v2 header declaring a unix transport",
			addr:   &net.UnixAddr{Net: "unix", Name: "/tmp/anything"},
			usable: false,
			why:    "a v2 header can name AF_UNIX on a TCP connection",
		},
		{
			name:   "a PROXY v2 header with an UNSPEC transport",
			addr:   nil,
			usable: false,
			why:    "SourceAddr is never set for UNSPEC, so RemoteAddr returns a nil net.Addr and the assert panicked",
		},
		{
			name:   "a typed-nil TCP address",
			addr:   (*net.TCPAddr)(nil),
			usable: false,
			why:    "the assert succeeds and the field read panics one step later",
		},
		{
			name:   "a TCP address carrying no IP",
			addr:   &net.TCPAddr{Port: 4444},
			usable: false,
			why:    "an empty IP allowlists and blocklists against nothing, and logs as <nil>",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ip, ok := acceptedClientIP(c.addr)
			if c.usable {
				if !ok {
					t.Fatalf("refused a real client (%s)", c.why)
				}
				if ip == nil {
					t.Fatal("accepted with a nil IP, which the allowlist cannot evaluate")
				}
				return
			}
			if ok {
				t.Fatalf("accepted an address the allowlist cannot evaluate (%s)", c.why)
			}
			if ip != nil {
				t.Fatalf("refused but still returned an IP: %v", ip)
			}
		})
	}
}

// The old code is one line, so the test that matters is that calling it the old
// way on these inputs really did panic. Without this, "we removed an assert" is
// an assertion about a diff rather than about behaviour.
func TestTheOldAssertPanickedOnEachOfThem(t *testing.T) {
	for _, addr := range []net.Addr{
		&net.UDPAddr{IP: net.IPv4(203, 0, 113, 7), Port: 4444},
		&net.UnixAddr{Net: "unix", Name: "/tmp/anything"},
		nil,
		(*net.TCPAddr)(nil),
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("%#v did not panic under the old assert, so it is not evidence for this fix", addr)
				}
			}()
			_ = addr.(*net.TCPAddr).IP.String() //nolint: forcetypeassert
		}()
	}
}

/*
The same assert lived a second time, in streamContext.ClientIP.

That one is worse in a specific way: newStreamContext calls it while building
the logger, which is BEFORE the caller has registered `defer ctx.Close()`. So
the panic did not just kill the process — on the way out it left the client
socket open with nothing holding a reference to it.

Nil is the right answer rather than a refusal here. By the time a stream context
exists the connection has already passed the accept-loop check, so a nil means
the transport underneath is one whose peer is not a TCP address, and the honest
report is "no IP", not a crash. It reaches the logger as <nil> and the policy
layer as an IP that matches nothing.
*/
func TestAStreamContextReportsNoClientIPRatherThanPanicking(t *testing.T) {
	ctx := &streamContext{clientConn: connWithAddr{addr: &net.UnixAddr{Net: "unix", Name: "/tmp/x"}}}

	ip := ctx.ClientIP()
	if ip != nil {
		t.Fatalf("want no IP for a non-TCP peer, got %v", ip)
	}
	// The logger formats it, so it has to survive String() on the nil.
	if s := ip.String(); s != "<nil>" {
		t.Fatalf("String() on the reported IP = %q", s)
	}

	real := &streamContext{clientConn: connWithAddr{addr: &net.TCPAddr{IP: net.IPv4(203, 0, 113, 7), Port: 1}}}
	if got := real.ClientIP(); !got.Equal(net.IPv4(203, 0, 113, 7)) {
		t.Fatalf("an ordinary client lost its IP: %v", got)
	}
}

type connWithAddr struct {
	net.Conn
	addr net.Addr
}

func (c connWithAddr) RemoteAddr() net.Addr { return c.addr }
func (c connWithAddr) CloseRead() error     { return nil }
func (c connWithAddr) CloseWrite() error    { return nil }
