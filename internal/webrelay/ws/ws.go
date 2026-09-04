// Package ws is the server half of RFC 6455, written rather than imported.
//
// The carrier needs a small and unusually strict subset: binary messages only,
// no extensions, no compression, no client role, one exact subprotocol echo, and
// a bounded message size. A general-purpose library brings a permissive parser
// and a dependency on the most exposed path this program has, to save a few
// hundred lines that are almost entirely bounds checks.
//
// # Strictness is the point
//
// Every "MAY" in RFC 6455 that could hide a distinguisher is resolved towards
// refusal:
//
//   - An unmasked client frame is a protocol error. The RFC requires the mask
//     and requires the server to fail without it; accepting one anyway is a
//     behaviour a prober can tell apart from a browser-facing endpoint.
//   - A non-minimal length is a protocol error. A 4-byte payload announced in
//     the 64-bit form is legal to decode and impossible for a browser to emit.
//   - RSV bits, reserved opcodes, fragmented control frames, oversized control
//     payloads and text messages are all refused.
//
// # What it deliberately does not do
//
// No client role, no HTTP/2 (RFC 8441) upgrade, no permessage-deflate, no
// automatic reconnection. The relay sits behind a front proxy that speaks
// HTTP/1.1 to it, and compression over a stream of already-encrypted MTProto
// payloads buys nothing while adding a well-known oracle.
package ws

import (
	"bufio"
	"crypto/sha1" //nolint:gosec // RFC 6455 names SHA-1 for the accept key; it is not a security property
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// acceptGUID is the constant RFC 6455 §1.3 defines for the accept hash.
//
// It is verified against the RFC's own published test vector in
// TestAcceptKeyMatchesTheRFCVector, and that test is not decoration. This
// constant was wrong for the life of the package -- the last group read
// "5AB0DC85B11D" instead of "C5AB0DC85B11", one character rotated off the front
// and onto the end -- and nothing caught it, because every test that exercised
// the handshake computed the expected answer with THIS constant and agreed with
// itself. A real browser does not: it recomputes the hash and closes the socket
// before onopen, which is exactly what Telegram Desktop did, on every attempt,
// with no error anywhere that named the cause.
//
// The lesson is in the shape of the bug, not the typo. A wire constant is only
// ever validated by a value that came from outside this codebase.
const acceptGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

// Opcodes. The carrier uses binary and the three control frames.
const (
	opContinuation byte = 0x0
	opText         byte = 0x1
	opBinary       byte = 0x2
	opClose        byte = 0x8
	opPing         byte = 0x9
	opPong         byte = 0xA
)

// Close codes. The specification does not say which code a protocol violation
// carries, so these are this implementation's choice, taken from RFC 6455's own
// registry rather than invented.
const (
	// CloseNormal ends a session that finished for an ordinary reason.
	CloseNormal uint16 = 1000

	// CloseProtocolError ends a session that violated the frame protocol, at
	// either the WebSocket or the shared-frame layer.
	CloseProtocolError uint16 = 1002

	// CloseUnsupportedData is a text message, which this carrier never accepts.
	CloseUnsupportedData uint16 = 1003

	// CloseTooBig is a message above the negotiated maximum.
	CloseTooBig uint16 = 1009

	// CloseInternalError is a fault on this side.
	CloseInternalError uint16 = 1011
)

// maxControlPayload is the RFC's own bound on a control frame's payload.
const maxControlPayload = 125

// Errors the caller is expected to distinguish.
var (
	// ErrNotWebSocket means the request is not a WebSocket upgrade at all. The
	// caller decides what an ordinary request gets -- for this relay, the cover
	// site.
	ErrNotWebSocket = errors.New("not a websocket upgrade request")

	// ErrHandshake means the request looked like an upgrade but was not one
	// this server can complete.
	ErrHandshake = errors.New("websocket handshake refused")

	// ErrProtocol is any violation of RFC 6455 by the peer. It always ends the
	// connection.
	ErrProtocol = errors.New("websocket protocol error")

	// ErrMessageTooBig is a message above the configured maximum.
	ErrMessageTooBig = errors.New("websocket message above the maximum size")

	// ErrClosed means the peer sent a close frame, or the connection is gone.
	ErrClosed = errors.New("websocket connection closed")
)

// Options configures one upgraded connection.
type Options struct {
	// Subprotocol is echoed back exactly. The request must offer this precise
	// value; anything else is refused. Empty means no subprotocol is
	// negotiated, which this relay never does.
	Subprotocol string

	// MaxMessage bounds a whole reassembled message. A frame that would carry a
	// message past it is refused before anything is allocated.
	MaxMessage int

	// IdleTimeout is one silence period. The connection is pinged after one
	// without traffic and closed after two, so a peer that died without a FIN
	// does not pin the session until TCP notices.
	IdleTimeout time.Duration

	// WriteTimeout bounds one write to the socket.
	WriteTimeout time.Duration
}

func (o Options) withDefaults() Options {
	if o.MaxMessage <= 0 {
		o.MaxMessage = 2 << 20
	}

	if o.IdleTimeout <= 0 {
		o.IdleTimeout = 25 * time.Second
	}

	if o.WriteTimeout <= 0 {
		o.WriteTimeout = 30 * time.Second
	}

	return o
}

// IsUpgrade reports whether a request is asking for a WebSocket upgrade. It is
// deliberately separate from [Upgrade]: the origin has to answer a request that
// is not one without ever having written a byte of WebSocket-shaped response.
func IsUpgrade(r *http.Request) bool {
	return r.Method == http.MethodGet &&
		tokenListContains(r.Header.Values("Connection"), "upgrade") &&
		strings.EqualFold(strings.TrimSpace(r.Header.Get("Upgrade")), "websocket")
}

// Upgrade completes the handshake and hands back a connection. On any error
// nothing has been written to w, so the caller is free to answer however it
// likes -- which is what lets a refused upgrade be indistinguishable from an
// ordinary 404.
func Upgrade(w http.ResponseWriter, r *http.Request, opts Options) (*Conn, error) {
	opts = opts.withDefaults()

	if !IsUpgrade(r) {
		return nil, ErrNotWebSocket
	}

	if r.Header.Get("Sec-Websocket-Version") != "13" {
		return nil, fmt.Errorf("%w: unsupported version", ErrHandshake)
	}

	key := r.Header.Get("Sec-Websocket-Key")
	if decoded, err := base64.StdEncoding.DecodeString(key); err != nil || len(decoded) != 16 {
		return nil, fmt.Errorf("%w: malformed key", ErrHandshake)
	}

	// The subprotocol carries the session bearer, so it is matched exactly
	// rather than negotiated: this server offers one value and accepts no
	// other, and a request offering several is refused rather than answered
	// with a choice.
	if opts.Subprotocol != "" {
		offered := splitTokenList(r.Header.Values("Sec-Websocket-Protocol"))
		if len(offered) != 1 || offered[0] != opts.Subprotocol {
			return nil, fmt.Errorf("%w: subprotocol mismatch", ErrHandshake)
		}
	}

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		return nil, fmt.Errorf("%w: connection cannot be hijacked", ErrHandshake)
	}

	conn, buffered, err := hijacker.Hijack()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrHandshake, err)
	}

	// Anything the client pipelined after the handshake would be read from the
	// buffered reader; a WebSocket client sends nothing before the response, so
	// data here means a smuggling attempt or a broken middlebox.
	if buffered.Reader.Buffered() > 0 {
		conn.Close() //nolint: errcheck // the handshake already failed

		return nil, fmt.Errorf("%w: unexpected buffered data", ErrHandshake)
	}

	response := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + acceptKey(key) + "\r\n"

	if opts.Subprotocol != "" {
		response += "Sec-WebSocket-Protocol: " + opts.Subprotocol + "\r\n"
	}

	response += "\r\n"

	if err := conn.SetWriteDeadline(time.Now().Add(opts.WriteTimeout)); err != nil {
		conn.Close() //nolint: errcheck // the handshake already failed

		return nil, fmt.Errorf("%w: %w", ErrHandshake, err)
	}

	if _, err := io.WriteString(conn, response); err != nil {
		conn.Close() //nolint: errcheck // the handshake already failed

		return nil, fmt.Errorf("%w: %w", ErrHandshake, err)
	}

	return newConn(conn, buffered.Reader, opts), nil
}

func acceptKey(key string) string {
	sum := sha1.Sum([]byte(key + acceptGUID)) //nolint:gosec // RFC 6455 names SHA-1 here; it is not a security property

	return base64.StdEncoding.EncodeToString(sum[:])
}

func tokenListContains(values []string, want string) bool {
	for _, token := range splitTokenList(values) {
		if strings.EqualFold(token, want) {
			return true
		}
	}

	return false
}

func splitTokenList(values []string) []string {
	tokens := make([]string, 0, len(values))

	for _, value := range values {
		for _, token := range strings.Split(value, ",") {
			if token = strings.TrimSpace(token); token != "" {
				tokens = append(tokens, token)
			}
		}
	}

	return tokens
}

// Conn is one upgraded connection. It supports a single reader and any number
// of concurrent writers, which is the shape the session layer needs: one loop
// pulling batches, many streams pushing them.
type Conn struct {
	conn   net.Conn
	reader *bufio.Reader
	opts   Options

	writeMu sync.Mutex
	closeMu sync.Mutex
	closed  bool

	// pinged is set when a ping went out for the current silence period and
	// cleared by any traffic. It is touched only by the reader.
	pinged bool
}

func newConn(conn net.Conn, reader *bufio.Reader, opts Options) *Conn {
	return &Conn{conn: conn, reader: reader, opts: opts}
}

// RemoteAddr is the peer address as the listener saw it.
func (c *Conn) RemoteAddr() net.Addr { return c.conn.RemoteAddr() }

// Read returns the next whole binary message. Control frames are answered
// inside it and never surface: a ping is ponged, a pong marks liveness, a close
// ends the connection with [ErrClosed].
//
// The returned slice is freshly allocated, so the caller may keep it.
func (c *Conn) Read() ([]byte, error) {
	var (
		message   []byte
		assembled bool
	)

	for {
		header, err := c.readHeader()
		if err != nil {
			return nil, err
		}

		if header.control() {
			if err := c.handleControl(header); err != nil {
				return nil, err
			}

			continue
		}

		switch {
		case header.opcode == opText:
			return nil, fmt.Errorf("%w: text message", ErrProtocol)
		case header.opcode == opBinary && assembled:
			return nil, fmt.Errorf("%w: new message inside a fragmented one", ErrProtocol)
		case header.opcode == opContinuation && !assembled:
			return nil, fmt.Errorf("%w: continuation without a message", ErrProtocol)
		case header.opcode != opBinary && header.opcode != opContinuation:
			return nil, fmt.Errorf("%w: reserved opcode 0x%x", ErrProtocol, header.opcode)
		}

		if int64(len(message))+header.length > int64(c.opts.MaxMessage) {
			return nil, ErrMessageTooBig
		}

		assembled = true

		chunk := make([]byte, header.length)
		if _, err := io.ReadFull(c.reader, chunk); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrClosed, err)
		}

		unmask(chunk, header.mask, len(message))
		message = append(message, chunk...)

		if header.fin {
			return message, nil
		}
	}
}

// Write sends one whole binary message.
func (c *Conn) Write(payload []byte) error {
	return c.writeFrame(opBinary, payload)
}

// Close sends a close frame carrying code and shuts the connection down. It is
// idempotent, and a failure to send the frame is not reported: the peer may
// already be gone, which is the ordinary case.
func (c *Conn) Close(code uint16, reason string) error {
	c.closeMu.Lock()

	if c.closed {
		c.closeMu.Unlock()

		return nil
	}

	c.closed = true
	c.closeMu.Unlock()

	if len(reason) > maxControlPayload-2 {
		reason = reason[:maxControlPayload-2]
	}

	payload := make([]byte, 2+len(reason))
	binary.BigEndian.PutUint16(payload, code)
	copy(payload[2:], reason)

	_ = c.writeFrame(opClose, payload)

	if err := c.conn.Close(); err != nil {
		return fmt.Errorf("cannot close the websocket: %w", err)
	}

	return nil
}

func (c *Conn) handleControl(header frameHeader) error {
	payload := make([]byte, header.length)

	if _, err := io.ReadFull(c.reader, payload); err != nil {
		return fmt.Errorf("%w: %w", ErrClosed, err)
	}

	unmask(payload, header.mask, 0)

	switch header.opcode {
	case opPing:
		return c.writeFrame(opPong, payload)
	case opPong:
		return nil
	case opClose:
		return ErrClosed
	default:
		return fmt.Errorf("%w: reserved control opcode 0x%x", ErrProtocol, header.opcode)
	}
}

func (c *Conn) writeFrame(opcode byte, payload []byte) error {
	header := make([]byte, 2, 10)
	header[0] = 0x80 | opcode

	switch {
	case len(payload) <= maxControlPayload:
		header[1] = byte(len(payload)) //nolint:gosec // bounded by the case: at most 125
	case len(payload) <= 0xFFFF:
		header[1] = 126                                                      //nolint:gosec // header was made with len 2, cap 10
		header = binary.BigEndian.AppendUint16(header, uint16(len(payload))) //nolint:gosec // bounded by the case
	default:
		header[1] = 127                                                      //nolint:gosec // ditto
		header = binary.BigEndian.AppendUint64(header, uint64(len(payload))) //nolint:gosec // a length is never negative
	}

	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	if err := c.conn.SetWriteDeadline(time.Now().Add(c.opts.WriteTimeout)); err != nil {
		return fmt.Errorf("cannot set a write deadline: %w", err)
	}

	if _, err := c.conn.Write(header); err != nil {
		return fmt.Errorf("cannot write a websocket header: %w", err)
	}

	if len(payload) > 0 {
		if _, err := c.conn.Write(payload); err != nil {
			return fmt.Errorf("cannot write a websocket payload: %w", err)
		}
	}

	return nil
}

// frameHeader is one decoded frame header.
type frameHeader struct {
	fin    bool
	opcode byte
	length int64
	mask   [4]byte
}

func (h frameHeader) control() bool { return h.opcode&0x8 != 0 }

// readHeader reads one frame header, applying the silence policy: after one
// idle period the peer is pinged, after two it is gone.
func (c *Conn) readHeader() (frameHeader, error) {
	for {
		if err := c.conn.SetReadDeadline(time.Now().Add(c.opts.IdleTimeout)); err != nil {
			return frameHeader{}, fmt.Errorf("cannot set a read deadline: %w", err)
		}

		header, err := c.decodeHeader()

		var netErr net.Error
		if err != nil && errors.As(err, &netErr) && netErr.Timeout() {
			if c.pinged {
				return frameHeader{}, fmt.Errorf("%w: silent for two idle periods", ErrClosed)
			}

			c.pinged = true

			if pingErr := c.writeFrame(opPing, nil); pingErr != nil {
				return frameHeader{}, pingErr
			}

			continue
		}

		c.pinged = false

		return header, err
	}
}

func (c *Conn) decodeHeader() (frameHeader, error) {
	var first [2]byte

	if _, err := io.ReadFull(c.reader, first[:]); err != nil {
		return frameHeader{}, fmt.Errorf("%w: %w", ErrClosed, err)
	}

	header := frameHeader{
		fin:    first[0]&0x80 != 0,
		opcode: first[0] & 0x0F,
	}

	// No extension was negotiated, so a reserved bit can only be a peer that
	// thinks one was.
	if first[0]&0x70 != 0 {
		return frameHeader{}, fmt.Errorf("%w: reserved bits set", ErrProtocol)
	}

	// RFC 6455 requires every client frame to be masked and requires the server
	// to fail the connection when one is not.
	if first[1]&0x80 == 0 {
		return frameHeader{}, fmt.Errorf("%w: unmasked client frame", ErrProtocol)
	}

	length := int64(first[1] & 0x7F)

	switch length {
	case 126:
		var extended [2]byte

		if _, err := io.ReadFull(c.reader, extended[:]); err != nil {
			return frameHeader{}, fmt.Errorf("%w: %w", ErrClosed, err)
		}

		length = int64(binary.BigEndian.Uint16(extended[:]))

		// The 16-bit form may not carry a length the 7-bit form could hold.
		if length <= maxControlPayload {
			return frameHeader{}, fmt.Errorf("%w: non-minimal length", ErrProtocol)
		}
	case 127:
		var extended [8]byte

		if _, err := io.ReadFull(c.reader, extended[:]); err != nil {
			return frameHeader{}, fmt.Errorf("%w: %w", ErrClosed, err)
		}

		unsigned := binary.BigEndian.Uint64(extended[:])

		// The high bit must be zero, and the 64-bit form may not carry a length
		// the 16-bit form could hold.
		if unsigned > 1<<62 {
			return frameHeader{}, ErrMessageTooBig
		}

		length = int64(unsigned)

		if length <= 0xFFFF {
			return frameHeader{}, fmt.Errorf("%w: non-minimal length", ErrProtocol)
		}
	}

	if header.control() {
		// A control frame is never fragmented and never long. Both rules exist
		// so a control frame can always be handled without buffering.
		if !header.fin {
			return frameHeader{}, fmt.Errorf("%w: fragmented control frame", ErrProtocol)
		}

		if length > maxControlPayload {
			return frameHeader{}, fmt.Errorf("%w: oversized control frame", ErrProtocol)
		}
	}

	if length > int64(c.opts.MaxMessage) {
		return frameHeader{}, ErrMessageTooBig
	}

	header.length = length

	if _, err := io.ReadFull(c.reader, header.mask[:]); err != nil {
		return frameHeader{}, fmt.Errorf("%w: %w", ErrClosed, err)
	}

	return header, nil
}

// unmask applies the frame mask in place. offset is the number of payload bytes
// already consumed from this frame, which is zero everywhere today but keeps the
// function correct if a caller ever streams a frame in pieces.
func unmask(payload []byte, mask [4]byte, offset int) {
	for i := range payload {
		payload[i] ^= mask[(i+offset)%4]
	}
}
