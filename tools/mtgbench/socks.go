package main

import (
	"bytes"
	"cmp"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Arman2122/mtg-proxy/essentials"
	"github.com/Arman2122/mtg-proxy/mtglib/obfuscation"
)

// The data centre's commands, each a byte and a big-endian 64-bit count,
// carried inside the obfuscated2 stream like any MTProto payload:
//
//	'D' n  the data centre sends n bytes
//	'U' n  the client sends n bytes; the data centre answers with n, as 8 bytes,
//	       once it has every one of them
//	'E' n  the client sends n bytes and the data centre sends them back
//	'H' 0  hold: the connection stays open and idle until it is closed
const (
	cmdDownload = 'D'
	cmdUpload   = 'U'
	cmdEcho     = 'E'
	cmdHold     = 'H'

	commandSize = 9
)

// dcChunk is the size of the data centre's own reads and writes.
const dcChunk = 64 << 10

var errBadCommand = errors.New("not a data-centre command")

// SOCKS5 replies, RFC 1928.
const (
	socksSucceeded      = 0x00
	socksNotAllowed     = 0x02
	socksNotSupported   = 0x07
	socksAddrNotSupport = 0x08
)

// DataCentre is mtgbench's Telegram. Behind SOCKS5, it answers CONNECTs to
// Telegram's data-centre addresses and then is the data centre on that same
// socket; with no SOCKS it is the direct baseline. Either way it reads the
// obfuscated2 handshake keyed on nothing -- the proxy's direct data-centre
// leg -- and then serves commands.
type DataCentre struct {
	ln    net.Listener
	socks bool
	dcs   map[string]bool

	served   atomic.Int64
	sent     atomic.Int64
	received atomic.Int64

	mu     sync.Mutex
	conns  map[net.Conn]struct{}
	closed bool
	wg     sync.WaitGroup
}

// StartSOCKS starts the data centre behind a SOCKS5 server: no authentication,
// CONNECT only, and only to Telegram's data-centre addresses.
func StartSOCKS(ctx context.Context, addr string) (*DataCentre, error) {
	return startDataCentre(ctx, addr, true)
}

// StartDirectDC starts the data centre with nothing in front of it.
func StartDirectDC(ctx context.Context, addr string) (*DataCentre, error) {
	return startDataCentre(ctx, addr, false)
}

func startDataCentre(ctx context.Context, addr string, socks bool) (*DataCentre, error) {
	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("cannot listen on %s: %w", addr, err)
	}

	dc := &DataCentre{ln: ln, socks: socks, dcs: telegramAddresses(), conns: make(map[net.Conn]struct{})}

	dc.wg.Go(dc.acceptLoop)

	return dc, nil
}

func (dc *DataCentre) Addr() string         { return dc.ln.Addr().String() }
func (dc *DataCentre) Served() int64        { return dc.served.Load() }
func (dc *DataCentre) BytesSent() int64     { return dc.sent.Load() }
func (dc *DataCentre) BytesReceived() int64 { return dc.received.Load() }

// Close stops accepting, closes every connection and waits for them.
func (dc *DataCentre) Close() error {
	err := dc.ln.Close()

	dc.mu.Lock()
	dc.closed = true

	for c := range dc.conns {
		c.Close() //nolint: errcheck
	}
	dc.mu.Unlock()

	dc.wg.Wait()

	return err //nolint: wrapcheck
}

func (dc *DataCentre) acceptLoop() {
	for {
		c, err := dc.ln.Accept()
		if err != nil {
			return
		}

		dc.mu.Lock()
		if dc.closed {
			dc.mu.Unlock()
			c.Close() //nolint: errcheck

			return
		}

		dc.conns[c] = struct{}{}
		dc.mu.Unlock()

		dc.wg.Go(func() {
			defer func() {
				dc.mu.Lock()
				delete(dc.conns, c)
				dc.mu.Unlock()
				c.Close() //nolint: errcheck
			}()

			// Both handshakes are bounded; what follows them is the run's.
			if c.SetDeadline(time.Now().Add(10*time.Second)) != nil {
				return
			}

			if dc.socks && !dc.socksConnect(c) {
				return
			}

			dc.serve(essentials.WrapNetConn(c))
		})
	}
}

// socksConnect speaks the server side of a SOCKS5 CONNECT and reports whether
// the destination is a data centre this server stands in for.
func (dc *DataCentre) socksConnect(c net.Conn) bool {
	var head [2]byte
	if _, err := io.ReadFull(c, head[:]); err != nil || head[0] != 5 {
		return false
	}

	methods := make([]byte, head[1])
	if _, err := io.ReadFull(c, methods); err != nil {
		return false
	}

	if !bytes.Contains(methods, []byte{0}) {
		c.Write([]byte{5, 0xFF}) //nolint: errcheck // no acceptable method

		return false
	}

	if _, err := c.Write([]byte{5, 0}); err != nil { // no authentication
		return false
	}

	var request [4]byte
	if _, err := io.ReadFull(c, request[:]); err != nil || request[0] != 5 {
		return false
	}

	var host net.IP

	switch request[3] {
	case 1:
		host = make(net.IP, net.IPv4len)
	case 4:
		host = make(net.IP, net.IPv6len)
	default:
		reply(c, socksAddrNotSupport)

		return false
	}

	var port [2]byte
	if _, err := io.ReadFull(c, host); err != nil {
		return false
	}

	if _, err := io.ReadFull(c, port[:]); err != nil {
		return false
	}

	if request[1] != 1 { // CONNECT
		reply(c, socksNotSupported)

		return false
	}

	destination := net.JoinHostPort(host.String(), fmt.Sprint(binary.BigEndian.Uint16(port[:])))
	if !dc.dcs[destination] {
		reply(c, socksNotAllowed)

		return false
	}

	return reply(c, socksSucceeded)
}

func reply(c net.Conn, code byte) bool {
	_, err := c.Write([]byte{5, code, 0, 1, 0, 0, 0, 0, 0, 0})

	return err == nil
}

func (dc *DataCentre) serve(raw essentials.Conn) {
	_, _, conn, err := obfuscation.Obfuscator{}.ReadHandshake(raw, obfuscation.TagSetOf(
		obfuscation.TagPaddedIntermediate, obfuscation.TagIntermediate, obfuscation.TagAbridged,
	))
	if err != nil || raw.SetDeadline(time.Time{}) != nil {
		return
	}

	dc.served.Add(1)

	buf := make([]byte, dcChunk)

	for {
		var command [commandSize]byte
		if _, err := io.ReadFull(conn, command[:]); err != nil {
			return
		}

		n := int64(binary.BigEndian.Uint64(command[1:])) //nolint: gosec // our own client's counts

		if err := dc.run(conn, command[0], n, buf); err != nil {
			return
		}
	}
}

func (dc *DataCentre) run(conn essentials.Conn, op byte, n int64, buf []byte) error {
	switch op {
	case cmdDownload:
		for left := n; left > 0; {
			chunk := min(left, int64(len(buf)))

			// Zeros every time: the writer encrypts the buffer in place.
			clear(buf[:chunk])

			if _, err := conn.Write(buf[:chunk]); err != nil {
				return err //nolint: wrapcheck
			}

			dc.sent.Add(chunk)
			left -= chunk
		}

		return nil
	case cmdUpload:
		// Wrapped so CopyBuffer uses buf: io.Discard's own ReadFrom would read
		// 8 KiB at a time.
		got, err := io.CopyBuffer(struct{ io.Writer }{io.Discard}, io.LimitReader(conn, n), buf)
		dc.received.Add(got)

		if err != nil || got != n {
			return fmt.Errorf("upload ended at %d of %d: %w", got, n, err)
		}

		var ack [8]byte
		binary.BigEndian.PutUint64(ack[:], uint64(got)) //nolint: gosec // non-negative

		_, err = conn.Write(ack[:])

		return err //nolint: wrapcheck
	case cmdEcho:
		for left := n; left > 0; {
			chunk := min(left, int64(len(buf)))
			if _, err := io.ReadFull(conn, buf[:chunk]); err != nil {
				return err //nolint: wrapcheck
			}

			dc.received.Add(chunk)

			if _, err := conn.Write(buf[:chunk]); err != nil {
				return err //nolint: wrapcheck
			}

			dc.sent.Add(chunk)
			left -= chunk
		}

		return nil
	case cmdHold:
		_, err := io.Copy(io.Discard, conn)

		return cmp.Or(err, io.EOF) //nolint: wrapcheck
	}

	return fmt.Errorf("%q: %w", op, errBadCommand)
}

func telegramAddresses() map[string]bool {
	addrs := make(map[string]bool)

	for _, list := range essentials.TelegramCoreAddresses {
		for _, a := range list {
			if host, port, err := net.SplitHostPort(a); err == nil {
				addrs[net.JoinHostPort(net.ParseIP(host).String(), port)] = true
			}
		}
	}

	return addrs
}
