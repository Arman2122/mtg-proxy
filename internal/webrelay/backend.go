package webrelay

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/pires/go-proxyproto"
)

// ErrNoBackendAddress means the relay was configured without a backend to dial.
var ErrNoBackendAddress = errors.New("no WEB relay backend address")

// TCPBackend opens one loopback connection per OPEN.
//
// The connection is byte-transparent: the client applied Telegram's own MTProxy
// transform before any of this, so what arrives here is an obfuscated2 stream
// with the client's transport tag already inside it. This code must not look at
// it, reorder it or frame it -- which is why the only thing it ever prepends is
// a PROXY header, and only when the listener on the other end is expecting one.
//
// # Why the PROXY header is not its own setting
//
// The relay and the proxy read the same configuration file, and the listener the
// backend address names already declares whether it parses a header. Making this
// a second, independent knob would let the two disagree, and the failure is
// silent and total: an unexpected header is read as the first bytes of the
// obfuscated handshake, so every stream dies at the same place for a reason
// nothing logs. So the caller derives this from the [[listener]] stanza, and
// the preflight refuses a backend address that names no listener at all.
type TCPBackend struct {
	address       string
	proxyProtocol bool
	dialer        *net.Dialer
	destination   *net.TCPAddr
}

// NewTCPBackend builds a dialer for one backend address. proxyProtocol must
// mirror the listener at that address.
func NewTCPBackend(address string, proxyProtocol bool, keepAlive time.Duration) (*TCPBackend, error) {
	if address == "" {
		return nil, ErrNoBackendAddress
	}

	destination, err := net.ResolveTCPAddr("tcp", address)
	if err != nil {
		return nil, fmt.Errorf("cannot resolve the backend address %q: %w", address, err)
	}

	return &TCPBackend{
		address:       address,
		proxyProtocol: proxyProtocol,
		destination:   destination,
		dialer:        &net.Dialer{KeepAlive: keepAlive},
	}, nil
}

// Address is the backend this dials, for logs and the preflight.
func (b *TCPBackend) Address() string { return b.address }

// Dial opens the backend connection for one stream. client is the browser's
// address as the origin learned it, and it is what the proxy will see as the
// remote peer -- the whole point of running the relay in this process rather
// than accepting a loopback address for every WEB user.
func (b *TCPBackend) Dial(ctx context.Context, client net.Addr) (net.Conn, error) {
	conn, err := b.dialer.DialContext(ctx, "tcp", b.address)
	if err != nil {
		return nil, fmt.Errorf("cannot dial the backend %q: %w", b.address, err)
	}

	if !b.proxyProtocol {
		return conn, nil
	}

	header, err := b.header(client, conn)
	if err != nil {
		conn.Close() //nolint: errcheck // the dial already failed

		return nil, err
	}

	if _, err := header.WriteTo(conn); err != nil {
		conn.Close() //nolint: errcheck // the dial already failed

		return nil, fmt.Errorf("cannot write the PROXY header: %w", err)
	}

	return conn, nil
}

// header builds the v2 header. The two addresses in a PROXY header must share a
// family, and here they routinely do not: a browser can reach the front proxy
// over IPv6 while the backend listens on IPv4 loopback. Handing a mismatched
// pair to the library yields a LOCAL header, which is well-formed, parses
// cleanly, and silently discards the client address -- the one thing this whole
// path exists to carry. So the destination is restated in the client's family
// instead, keeping the port that identifies the listener.
func (b *TCPBackend) header(client net.Addr, conn net.Conn) (*proxyproto.Header, error) {
	source, ok := client.(*net.TCPAddr)
	if !ok || source == nil || source.IP == nil {
		return nil, fmt.Errorf("%w: client address %v is not a TCP address", ErrNoBackendAddress, client)
	}

	transport := proxyproto.TCPv6
	if source.IP.To4() != nil {
		transport = proxyproto.TCPv4
	}

	destination := &net.TCPAddr{IP: b.destination.IP, Port: b.destination.Port}

	if (destination.IP.To4() != nil) != (transport == proxyproto.TCPv4) {
		destination.IP = net.IPv6loopback
		if transport == proxyproto.TCPv4 {
			destination.IP = net.IPv4(127, 0, 0, 1)
		}
	}

	// The local address of the connection we just opened is the accurate
	// destination when it agrees with the family; it never does for a
	// rewritten one, so it is used only as a sanity fallback for the port.
	if destination.Port == 0 {
		if local, ok := conn.LocalAddr().(*net.TCPAddr); ok {
			destination.Port = local.Port
		}
	}

	return &proxyproto.Header{
		Version:           2,
		Command:           proxyproto.PROXY,
		TransportProtocol: transport,
		SourceAddr:        source,
		DestinationAddr:   destination,
	}, nil
}
