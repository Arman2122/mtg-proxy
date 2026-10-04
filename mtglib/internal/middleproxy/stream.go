package middleproxy

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/Arman2122/mtg-proxy/essentials"
)

const (
	quickAckLength uint32 = 0x80000000

	// reqHeaderLength is the size of the RPC_PROXY_REQ prefix header builds:
	// tag, flags, conn_id, two IP:port pairs, the extra block with its 16-byte
	// ad_tag, aligned to 4.
	reqHeaderLength = 84

	// maxClientPacket is the longest packet a client may declare: the one
	// whose RPC_PROXY_REQ frame is exactly frameMaxMessageLength, the most
	// the frame reader accepts. Telegram's transport documentation sets no
	// maximum; TDLib's writer stays under 1<<24 bytes plus 15 of padding, so
	// this refuses at most its last ~100 bytes, which no client fills (file
	// parts are 512 KiB).
	maxClientPacket = frameMaxMessageLength - 4 - 4 - reqHeaderLength - 4
)

var errPacketTooLarge = errors.New("client packet too large")

type proxyResponseType uint8

const (
	respAns proxyResponseType = iota
	respSimpleAck
	respCloseExt
)

// middleConn adapts a middle-proxy RPC channel to essentials.Conn so the
// existing byte-transparent relay can drive it unchanged. Bytes written to it
// are the client's (padded-)intermediate stream (client -> telegram): each
// complete inner packet is repackaged as an RPC_PROXY_REQ carrying the ad_tag.
// Bytes read from it (telegram -> client) are RPC_PROXY_ANS payloads reframed
// with a bare 4-byte length, which both transports accept. All framing is
// internal, so the relay only ever sees a plain byte stream.
type middleConn struct {
	raw        essentials.Conn
	frame      *frameConn
	connID     [8]byte
	adTag      [adTagLength]byte
	clientAddr *net.TCPAddr
	ourAddr    *net.TCPAddr

	// padded is true when the client speaks padded-intermediate (0xdddddddd).
	// It is the only transport that appends padding, so it is the only one that
	// may declare RPC_F_PAD or have its packets trimmed.
	padded bool

	// inbuf is the client's stream not yet framed: at most one partial packet
	// between writes. reqHeader is the RPC_PROXY_REQ prefix, the same for every
	// packet but its flags word; wbuf collects a write's frames.
	inbuf     []byte
	reqHeader []byte
	wbuf      []byte

	// What the client has yet to receive of the current answer: the last
	// headLeft bytes of head (the intermediate length prefix), then out, a
	// slice of the frame reader's buffer that stays valid until it reads the
	// next frame -- which Read does only once out is drained.
	head     [4]byte
	headLeft int
	out      []byte

	// readErr is an error met after Read had already copied bytes; it is
	// returned by the next Read instead of being lost.
	readErr error
}

func newMiddleConn(raw essentials.Conn, frame *frameConn, connID [8]byte, adTag [adTagLength]byte, clientAddr, ourAddr *net.TCPAddr, padded bool) *middleConn {
	return &middleConn{
		raw:        raw,
		frame:      frame,
		connID:     connID,
		adTag:      adTag,
		clientAddr: clientAddr,
		ourAddr:    ourAddr,
		padded:     padded,
	}
}

// Write frames every complete packet of the client's stream as an
// RPC_PROXY_REQ, builds them all in one buffer and sends them with one write;
// a partial packet waits for the rest. Nothing is allocated once the buffers
// have grown.
func (m *middleConn) Write(p []byte) (int, error) {
	m.inbuf = append(m.inbuf, p...)
	m.wbuf = m.wbuf[:0]

	consumed := 0

	for rest := m.inbuf; len(rest) >= 4; rest = m.inbuf[consumed:] {
		length := binary.LittleEndian.Uint32(rest[:4])

		quickAck := false
		if length >= quickAckLength {
			quickAck = true
			length -= quickAckLength
		}

		// Judged on the header, before the body is waited for: a client that
		// could declare any length could make this buffer everything it sent.
		if length > maxClientPacket {
			m.inbuf = m.inbuf[:0]

			return 0, fmt.Errorf("%w: %d bytes declared, at most %d", errPacketTooLarge, length, maxClientPacket)
		}

		if uint64(len(rest)) < uint64(length)+4 {
			break
		}

		packet := rest[4 : 4+length]
		// A plain intermediate frame carries no padding, so trimming it would
		// silently truncate real payload.
		if m.padded {
			// Clients pad padded-intermediate frames with 0-15 random bytes. Trim
			// only to 4-byte alignment, as MTProxy (packet_len & -4) does: the
			// aligned remainder is the DC's to discard, not ours.
			packet = packet[:len(packet)-len(packet)%4]
		}

		m.wbuf = m.frame.appendFrame(m.wbuf, m.header(packet, quickAck), packet)
		consumed += 4 + int(length)
	}

	// Keep only the partial packet, at the front, so the buffer does not creep;
	// and if a large packet grew it, let that size go once it has passed.
	m.inbuf = m.inbuf[:copy(m.inbuf, m.inbuf[consumed:])]
	if cap(m.inbuf) > keepBufferMax && len(m.inbuf) <= keepBufferMax {
		m.inbuf = append([]byte(nil), m.inbuf...)
	}

	if len(m.wbuf) > 0 {
		err := m.frame.writeFrames(m.wbuf)

		if cap(m.wbuf) > keepBufferMax {
			m.wbuf = nil
		}

		if err != nil {
			return 0, err
		}
	}

	return len(p), nil
}

// Read hands the client RPC_PROXY_ANS payloads reframed as intermediate
// packets (a 4-byte little-endian length, then the payload; no random padding
// -- the outer obfuscated2 and FakeTLS layers already randomise the stream)
// and RPC_SIMPLE_ACK payloads verbatim. Each byte is copied once, from the
// frame reader's buffer into dst. When dst has room and the next frame has
// already arrived in full, that frame is taken in the same call, so the client
// gets fewer, larger writes; Read never blocks for more once it has bytes.
func (m *middleConn) Read(dst []byte) (int, error) {
	if m.readErr != nil {
		return 0, m.readErr
	}

	n := 0

	for {
		if m.headLeft > 0 {
			c := copy(dst[n:], m.head[len(m.head)-m.headLeft:])
			m.headLeft -= c
			n += c
		}

		if m.headLeft == 0 && len(m.out) > 0 {
			c := copy(dst[n:], m.out)
			m.out = m.out[c:]
			n += c
		}

		if n == len(dst) || m.headLeft > 0 || len(m.out) > 0 {
			return n, nil
		}

		if n > 0 && !m.frame.nextFrameBuffered() {
			return n, nil
		}

		if err := m.nextAnswer(); err != nil {
			// With bytes in hand nextAnswer only runs on a frame that is wholly
			// buffered, so it does no socket I/O: what it can fail with is the
			// stream itself -- a bad frame, RPC_CLOSE_EXT -- never a timeout a
			// caller might retry. Keeping that for the next Read is final.
			if n > 0 {
				m.readErr = err

				return n, nil
			}

			return 0, err
		}
	}
}

// nextAnswer reads one frame and queues what it carries for the client, which
// may be nothing: Read's loop then decides whether waiting for another frame
// is allowed.
func (m *middleConn) nextAnswer() error {
	msg, err := m.frame.readPacket()
	if err != nil {
		return err
	}

	typ, payload, err := parseProxyResponse(msg)
	if err != nil {
		return err
	}

	switch typ {
	case respAns:
		// G115: payload comes from parseProxyResponse over a frame readPacket
		// already clamped to frameMaxMessageLength (16 MiB).
		binary.LittleEndian.PutUint32(m.head[:], uint32(len(payload))) //nolint:gosec
		m.headLeft = len(m.head)
		m.out = payload
	case respSimpleAck:
		// A quick-ack is forwarded to the client verbatim, without an
		// intermediate length prefix.
		m.out = payload
	case respCloseExt:
		return io.EOF
	}

	return nil
}

// baseFlags mirrors MTProxy's tag->flags mapping. RPC_F_PAD tells the middle
// proxy the client's transport carries 0-15 bytes of trailing padding, which is
// true only for 0xdddddddd.
func (m *middleConn) baseFlags() uint32 {
	flags := flagHasAdTag | flagMagic | flagExtMode2 | flagIntermediate
	if m.padded {
		flags |= flagPad
	}

	return flags
}

// buildProxyReq is one RPC_PROXY_REQ carrying packet, as Write frames it.
func (m *middleConn) buildProxyReq(packet []byte, quickAck bool) []byte {
	return append(bytes.Clone(m.header(packet, quickAck)), packet...)
}

// header returns the RPC_PROXY_REQ prefix for packet: tag, flags, connection
// id, both encoded addresses, the extra block's size and proxy-tag id, the ad
// tag, and alignment to 4. All of it but the flags word is built on first use
// and kept; the flags word is rewritten for each packet.
func (m *middleConn) header(packet []byte, quickAck bool) []byte {
	if m.reqHeader == nil {
		h := make([]byte, 0, reqHeaderLength)
		h = append(h, tagProxyRequest...)
		h = append(h, 0, 0, 0, 0) // flags, per packet
		h = append(h, m.connID[:]...)
		h = append(h, encodeIPPort(m.clientAddr)...)
		h = append(h, encodeIPPort(m.ourAddr)...)
		h = append(h, proxyRequestExtraSize...)
		h = append(h, proxyRequestProxyTag...)
		h = append(h, byte(len(m.adTag)))
		h = append(h, m.adTag[:]...)
		h = append(h, make([]byte, (4-len(h)%4)%4)...)
		m.reqHeader = h
	}

	flags := m.baseFlags()

	if quickAck {
		flags |= flagQuickAck
	}

	if len(packet) >= 8 && isAllZero(packet[:8]) {
		flags |= flagEncrypted
	}

	binary.LittleEndian.PutUint32(m.reqHeader[4:8], flags)

	return m.reqHeader
}

func (m *middleConn) Close() error                       { return m.raw.Close() }
func (m *middleConn) CloseRead() error                   { return m.raw.CloseRead() }
func (m *middleConn) CloseWrite() error                  { return m.raw.CloseWrite() }
func (m *middleConn) LocalAddr() net.Addr                { return m.raw.LocalAddr() }
func (m *middleConn) RemoteAddr() net.Addr               { return m.raw.RemoteAddr() }
func (m *middleConn) SetDeadline(t time.Time) error      { return m.raw.SetDeadline(t) }
func (m *middleConn) SetReadDeadline(t time.Time) error  { return m.raw.SetReadDeadline(t) }
func (m *middleConn) SetWriteDeadline(t time.Time) error { return m.raw.SetWriteDeadline(t) }

// parseProxyResponse classifies an RPC response and returns its client-bound
// payload. Layouts: RPC_PROXY_ANS = tag(4)|flags(4)|conn_id(8)|payload;
// RPC_SIMPLE_ACK = tag(4)|conn_id(8)|payload; RPC_CLOSE_EXT = tag(4).
func parseProxyResponse(packet []byte) (proxyResponseType, []byte, error) {
	if len(packet) < 4 {
		return 0, nil, io.ErrUnexpectedEOF
	}

	tag := packet[:4]

	switch {
	case bytes.Equal(tag, tagProxyAns):
		if len(packet) < 16 {
			return 0, nil, io.ErrUnexpectedEOF
		}

		return respAns, packet[16:], nil
	case bytes.Equal(tag, tagSimpleAck):
		if len(packet) < 12 {
			return 0, nil, io.ErrUnexpectedEOF
		}

		return respSimpleAck, packet[12:], nil
	case bytes.Equal(tag, tagCloseExt):
		return respCloseExt, nil, nil
	}

	return 0, nil, io.ErrUnexpectedEOF
}

// encodeIPPort serializes addr as 16 bytes of IPv6-mapped address followed by a
// 4-byte little-endian port, as expected inside RPC_PROXY_REQ.
func encodeIPPort(addr *net.TCPAddr) []byte {
	out := make([]byte, 20)

	if addr != nil {
		copy(out[:16], addr.IP.To16())
		// G115: kernel-supplied TCP port, 0..65535.
		binary.LittleEndian.PutUint32(out[16:], uint32(addr.Port)) //nolint:gosec
	}

	return out
}

func isAllZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}

	return true
}
