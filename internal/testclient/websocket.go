package testclient

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha1" //nolint: gosec // RFC 6455 fixes SHA-1 for the accept key
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// WebSocket opcodes, RFC 6455 section 5.2.
const (
	opBinary = 0x2
	opClose  = 0x8
	opPing   = 0x9
	opPong   = 0xA
)

var errUpgradeRefused = errors.New("the carrier upgrade was refused")

// dialWebSocket opens the carrier: a raw HTTP/1.1 upgrade on a fresh TCP
// connection, carrying the session bearer in the subprotocol the way the
// bridge script does.
func dialWebSocket(
	ctx context.Context, address, path, subprotocol, origin, forwardedFor string, timeout time.Duration,
) (net.Conn, *bufio.Reader, error) {
	conn, err := (&net.Dialer{Timeout: timeout}).DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot reach the relay: %w", err)
	}

	key := make([]byte, 16)
	if _, err := rand.Read(key); err != nil {
		conn.Close() //nolint: errcheck

		return nil, nil, fmt.Errorf("cannot make a WebSocket key: %w", err)
	}

	var request strings.Builder

	request.WriteString("GET " + path + " HTTP/1.1\r\nHost: " + address + "\r\n")
	request.WriteString("Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\n")
	request.WriteString("Sec-WebSocket-Key: " + base64.StdEncoding.EncodeToString(key) + "\r\n")
	request.WriteString("Sec-WebSocket-Protocol: " + subprotocol + "\r\n")
	request.WriteString("Origin: https://" + origin + "\r\n")

	if forwardedFor != "" {
		request.WriteString("X-Forwarded-For: " + forwardedFor + "\r\n")
	}

	request.WriteString("\r\n")

	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		conn.Close() //nolint: errcheck

		return nil, nil, fmt.Errorf("cannot set the upgrade deadline: %w", err)
	}

	reader := bufio.NewReaderSize(conn, 256<<10)

	if _, err := io.WriteString(conn, request.String()); err != nil {
		conn.Close() //nolint: errcheck

		return nil, nil, fmt.Errorf("cannot send the upgrade: %w", err)
	}

	response, err := http.ReadResponse(reader, nil)
	if err != nil {
		conn.Close() //nolint: errcheck

		return nil, nil, fmt.Errorf("cannot read the upgrade answer: %w", err)
	}

	response.Body.Close() //nolint: errcheck

	if response.StatusCode != http.StatusSwitchingProtocols ||
		response.Header.Get("Sec-WebSocket-Protocol") != subprotocol ||
		response.Header.Get("Sec-WebSocket-Accept") != acceptKey(base64.StdEncoding.EncodeToString(key)) {
		conn.Close() //nolint: errcheck

		return nil, nil, fmt.Errorf("%w: %s", errUpgradeRefused, response.Status)
	}

	if err := conn.SetDeadline(time.Time{}); err != nil {
		conn.Close() //nolint: errcheck

		return nil, nil, fmt.Errorf("cannot clear the upgrade deadline: %w", err)
	}

	return conn, reader, nil
}

// websocketGUID is RFC 6455's, section 1.3; TestTheAcceptKeyIsTheRFCs checks
// it against the RFC's own worked example.
const websocketGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

// acceptKey is the Sec-WebSocket-Accept a server must answer key with.
func acceptKey(key string) string {
	sum := sha1.Sum([]byte(key + websocketGUID)) //nolint: gosec // the protocol's own choice

	return base64.StdEncoding.EncodeToString(sum[:])
}

// appendClientFrame appends one masked, final WebSocket frame. A client must
// mask everything it sends; the relay refuses anything else. All three length
// forms are written, so one message may carry a whole batch.
func appendClientFrame(dst []byte, opcode byte, payload []byte) []byte {
	dst = append(dst, 0x80|opcode)

	switch n := len(payload); {
	case n <= 125:
		dst = append(dst, 0x80|byte(n))
	case n <= 0xFFFF:
		dst = append(dst, 0x80|126)
		dst = binary.BigEndian.AppendUint16(dst, uint16(n))
	default:
		dst = append(dst, 0x80|127)
		dst = binary.BigEndian.AppendUint64(dst, uint64(n))
	}

	var mask [4]byte

	rand.Read(mask[:]) //nolint: errcheck // crypto/rand.Read does not fail

	dst = append(dst, mask[:]...)
	start := len(dst)
	dst = append(dst, payload...)

	maskBytes(dst[start:], mask)

	return dst
}

func maskBytes(b []byte, mask [4]byte) {
	word := uint64(binary.LittleEndian.Uint32(mask[:]))
	word |= word << 32

	i := 0
	for ; i+8 <= len(b); i += 8 {
		binary.LittleEndian.PutUint64(b[i:], binary.LittleEndian.Uint64(b[i:])^word)
	}

	for ; i < len(b); i++ {
		b[i] ^= mask[i%4]
	}
}

// readServerFrame reads one WebSocket frame from the relay, which never masks
// and never fragments. The payload is read into buf when it fits.
func readServerFrame(r *bufio.Reader, buf []byte) (byte, []byte, error) {
	var head [2]byte

	if _, err := io.ReadFull(r, head[:]); err != nil {
		return 0, nil, err //nolint: wrapcheck
	}

	length := uint64(head[1] & 0x7F)

	switch length {
	case 126:
		var extended [2]byte
		if _, err := io.ReadFull(r, extended[:]); err != nil {
			return 0, nil, err //nolint: wrapcheck
		}

		length = uint64(binary.BigEndian.Uint16(extended[:]))
	case 127:
		var extended [8]byte
		if _, err := io.ReadFull(r, extended[:]); err != nil {
			return 0, nil, err //nolint: wrapcheck
		}

		length = binary.BigEndian.Uint64(extended[:])
	}

	if length > 16<<20 {
		return 0, nil, fmt.Errorf("a WebSocket frame of %d bytes is not the relay's", length)
	}

	var payload []byte
	if uint64(cap(buf)) < length {
		payload = make([]byte, length)
	} else {
		payload = buf[:length]
	}

	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, nil, err //nolint: wrapcheck
	}

	return head[0] & 0x0F, payload, nil
}
