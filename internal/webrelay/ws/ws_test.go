package ws_test

import (
	"bufio"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Arman2122/mtg-proxy/internal/webrelay/ws"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

const testSubprotocol = "tproxy-v1.QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ"

// rawClient is a deliberately dumb WebSocket client: it writes exactly the bytes
// a test asks for, including the illegal ones. A real client library would
// refuse to emit half the inputs this file needs.
type rawClient struct {
	t    *testing.T
	conn net.Conn
	r    *bufio.Reader
	key  string
}

func dial(t *testing.T, server *httptest.Server, headers map[string]string) *rawClient {
	t.Helper()

	address := strings.TrimPrefix(server.URL, "http://")

	conn, err := net.DialTimeout("tcp", address, 5*time.Second)
	require.NoError(t, err)

	t.Cleanup(func() { conn.Close() })

	raw := make([]byte, 16)
	_, err = rand.Read(raw)
	require.NoError(t, err)

	client := &rawClient{t: t, conn: conn, r: bufio.NewReader(conn), key: base64.StdEncoding.EncodeToString(raw)}

	// Defaults first, then the caller's overrides REPLACE them. Appending
	// instead would leave two fields of the same name, and Header.Get returns
	// the first -- so a test meaning to send a bad version would send a good one
	// alongside it and pass for the wrong reason.
	fields := map[string]string{
		"Upgrade":               "websocket",
		"Connection":            "Upgrade",
		"Sec-WebSocket-Version": "13",
		"Sec-WebSocket-Key":     client.key,
	}

	for name, value := range headers {
		fields[name] = value
	}

	request := "GET /api/v1/ws HTTP/1.1\r\nHost: " + address + "\r\n"

	for name, value := range fields {
		if value != "" {
			request += name + ": " + value + "\r\n"
		}
	}

	request += "\r\n"

	_, err = io.WriteString(conn, request)
	require.NoError(t, err)

	return client
}

func (c *rawClient) response() *http.Response {
	c.t.Helper()

	require.NoError(c.t, c.conn.SetReadDeadline(time.Now().Add(5*time.Second)))

	response, err := http.ReadResponse(c.r, nil)
	require.NoError(c.t, err)

	return response
}

func (c *rawClient) acceptKey() string {
	sum := sha1.Sum([]byte(c.key + "258EAFA5-E914-47DA-95CA-5AB0DC85B11D")) //nolint:gosec // the RFC names SHA-1

	return base64.StdEncoding.EncodeToString(sum[:])
}

// send writes one frame exactly as described, with no validation of its own.
func (c *rawClient) send(fin bool, opcode byte, payload []byte, opts ...func(*rawFrame)) {
	c.t.Helper()

	frame := &rawFrame{fin: fin, opcode: opcode, payload: payload, masked: true}
	for _, opt := range opts {
		opt(frame)
	}

	require.NoError(c.t, c.conn.SetWriteDeadline(time.Now().Add(5*time.Second)))
	_, err := c.conn.Write(frame.bytes())
	require.NoError(c.t, err)
}

func (c *rawClient) receive() (byte, []byte, error) {
	if err := c.conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return 0, nil, err
	}

	var head [2]byte
	if _, err := io.ReadFull(c.r, head[:]); err != nil {
		return 0, nil, err
	}

	length := int(head[1] & 0x7F)

	switch length {
	case 126:
		var extended [2]byte
		if _, err := io.ReadFull(c.r, extended[:]); err != nil {
			return 0, nil, err
		}

		length = int(binary.BigEndian.Uint16(extended[:]))
	case 127:
		var extended [8]byte
		if _, err := io.ReadFull(c.r, extended[:]); err != nil {
			return 0, nil, err
		}

		length = int(binary.BigEndian.Uint64(extended[:]))
	}

	payload := make([]byte, length)
	if _, err := io.ReadFull(c.r, payload); err != nil {
		return 0, nil, err
	}

	return head[0] & 0x0F, payload, nil
}

type rawFrame struct {
	fin     bool
	opcode  byte
	payload []byte
	masked  bool
	rsv     byte
	// lengthForm forces a specific length encoding: 0 picks the minimal one.
	lengthForm byte
}

func unmasked(f *rawFrame)     { f.masked = false }
func withRSV(f *rawFrame)      { f.rsv = 0x40 }
func longForm(f *rawFrame)     { f.lengthForm = 127 }
func extendedForm(f *rawFrame) { f.lengthForm = 126 }

func (f *rawFrame) bytes() []byte {
	out := []byte{f.opcode | f.rsv, 0}
	if f.fin {
		out[0] |= 0x80
	}

	form := f.lengthForm
	if form == 0 {
		switch {
		case len(f.payload) <= 125:
			form = byte(len(f.payload))
		case len(f.payload) <= 0xFFFF:
			form = 126
		default:
			form = 127
		}
	}

	switch form {
	case 126:
		out[1] = 126
		out = binary.BigEndian.AppendUint16(out, uint16(len(f.payload))) //nolint:gosec // test input
	case 127:
		out[1] = 127
		out = binary.BigEndian.AppendUint64(out, uint64(len(f.payload))) //nolint:gosec // test input
	default:
		out[1] = form
	}

	body := make([]byte, len(f.payload))
	copy(body, f.payload)

	if f.masked {
		out[1] |= 0x80
		mask := []byte{0x11, 0x22, 0x33, 0x44}
		out = append(out, mask...)

		for i := range body {
			body[i] ^= mask[i%4]
		}
	}

	return append(out, body...)
}

// serverResult is what the handler observed, so a test can assert on the error
// class the connection died with rather than only on the wire.
type serverResult struct {
	messages chan []byte
	errs     chan error
}

func newServer(t *testing.T, opts ws.Options) (*httptest.Server, *serverResult) {
	t.Helper()

	result := &serverResult{messages: make(chan []byte, 16), errs: make(chan error, 4)}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := ws.Upgrade(w, r, opts)
		if err != nil {
			result.errs <- err
			// The refusal is answered exactly like any other unusable request.
			w.Header().Set("Cache-Control", "no-store")
			w.WriteHeader(http.StatusNotFound)

			return
		}

		defer conn.Close(ws.CloseNormal, "")

		for {
			message, err := conn.Read()
			if err != nil {
				result.errs <- err

				return
			}

			result.messages <- message

			if err := conn.Write(message); err != nil {
				result.errs <- err

				return
			}
		}
	}))

	t.Cleanup(server.Close)

	return server, result
}

func (r *serverResult) waitErr(t *testing.T) error {
	t.Helper()

	select {
	case err := <-r.errs:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("the server never reported an error")

		return nil
	}
}

func (r *serverResult) waitMessage(t *testing.T) []byte {
	t.Helper()

	select {
	case message := <-r.messages:
		return message
	case <-time.After(5 * time.Second):
		t.Fatal("the server never read a message")

		return nil
	}
}

type HandshakeTestSuite struct {
	suite.Suite
}

func (suite *HandshakeTestSuite) TestAcceptAndExactSubprotocolEcho() {
	t := suite.T()
	server, _ := newServer(t, ws.Options{Subprotocol: testSubprotocol})

	client := dial(t, server, map[string]string{"Sec-WebSocket-Protocol": testSubprotocol})
	response := client.response()

	suite.Equal(http.StatusSwitchingProtocols, response.StatusCode)
	suite.Equal(client.acceptKey(), response.Header.Get("Sec-WebSocket-Accept"))
	suite.Equal(testSubprotocol, response.Header.Get("Sec-WebSocket-Protocol"))
}

// The subprotocol carries the session bearer, so it is matched, not negotiated.
// A request offering a list -- including one that contains the right value --
// is refused rather than answered with a choice.
func (suite *HandshakeTestSuite) TestSubprotocolIsMatchedNotNegotiated() {
	t := suite.T()

	for name, offered := range map[string]string{
		"absent":     "",
		"different":  "tproxy-v1.AAAA",
		"a list":     "chat, " + testSubprotocol,
		"truncated":  testSubprotocol[:len(testSubprotocol)-1],
		"duplicated": testSubprotocol + ", " + testSubprotocol,
	} {
		suite.Run(name, func() {
			server, result := newServer(t, ws.Options{Subprotocol: testSubprotocol})

			headers := map[string]string{}
			if offered != "" {
				headers["Sec-WebSocket-Protocol"] = offered
			}

			client := dial(t, server, headers)

			suite.Equal(http.StatusNotFound, client.response().StatusCode)
			suite.Require().ErrorIs(result.waitErr(t), ws.ErrHandshake)
		})
	}
}

// A refused upgrade must be answerable as an ordinary request: if Upgrade had
// written anything, the origin could not hide which requests it recognised.
func (suite *HandshakeTestSuite) TestRefusalLeavesTheResponseUntouched() {
	t := suite.T()
	server, result := newServer(t, ws.Options{Subprotocol: testSubprotocol})

	client := dial(t, server, map[string]string{
		"Sec-WebSocket-Protocol": testSubprotocol,
		"Sec-WebSocket-Version":  "8",
	})

	response := client.response()
	suite.Equal(http.StatusNotFound, response.StatusCode)
	suite.Equal("no-store", response.Header.Get("Cache-Control"))
	suite.Empty(response.Header.Get("Sec-WebSocket-Accept"))
	suite.Require().ErrorIs(result.waitErr(t), ws.ErrHandshake)
}

func (suite *HandshakeTestSuite) TestNonUpgradeRequest() {
	t := suite.T()
	server, result := newServer(t, ws.Options{Subprotocol: testSubprotocol})

	response, err := server.Client().Get(server.URL + "/api/v1/ws") //nolint:noctx // a test request
	suite.Require().NoError(err)

	defer response.Body.Close()

	suite.Equal(http.StatusNotFound, response.StatusCode)
	suite.Require().ErrorIs(result.waitErr(t), ws.ErrNotWebSocket)
}

type FramingTestSuite struct {
	suite.Suite
}

func (suite *FramingTestSuite) connect() (*rawClient, *serverResult) {
	t := suite.T()
	server, result := newServer(t, ws.Options{Subprotocol: testSubprotocol, MaxMessage: 4096})
	client := dial(t, server, map[string]string{"Sec-WebSocket-Protocol": testSubprotocol})

	suite.Require().Equal(http.StatusSwitchingProtocols, client.response().StatusCode)

	return client, result
}

func (suite *FramingTestSuite) TestBinaryRoundTrip() {
	client, result := suite.connect()

	client.send(true, 0x2, []byte("hello"))
	suite.Equal([]byte("hello"), result.waitMessage(suite.T()))

	opcode, payload, err := client.receive()
	suite.Require().NoError(err)
	suite.Equal(byte(0x2), opcode)
	suite.Equal([]byte("hello"), payload)
}

func (suite *FramingTestSuite) TestFragmentsAreReassembled() {
	client, result := suite.connect()

	client.send(false, 0x2, []byte("frag"))
	client.send(false, 0x0, []byte("ment"))
	client.send(true, 0x0, []byte("ed"))

	suite.Equal([]byte("fragmented"), result.waitMessage(suite.T()))
}

func (suite *FramingTestSuite) TestPingIsPonged() {
	client, _ := suite.connect()

	client.send(true, 0x9, []byte("token"))

	opcode, payload, err := client.receive()
	suite.Require().NoError(err)
	suite.Equal(byte(0xA), opcode)
	suite.Equal([]byte("token"), payload)
}

func (suite *FramingTestSuite) TestCloseFromThePeer() {
	client, result := suite.connect()

	client.send(true, 0x8, []byte{0x03, 0xE8})
	suite.Require().ErrorIs(result.waitErr(suite.T()), ws.ErrClosed)
}

// Every one of these is legal to decode and impossible for a browser to emit.
// Accepting any of them is a behaviour that tells a prober this endpoint is not
// what it claims to be.
func (suite *FramingTestSuite) TestProtocolViolations() {
	t := suite.T()

	testData := map[string]func(*rawClient){
		"text message": func(c *rawClient) {
			c.send(true, 0x1, []byte("text"))
		},
		"unmasked frame": func(c *rawClient) {
			c.send(true, 0x2, []byte("plain"), unmasked)
		},
		"reserved bit": func(c *rawClient) {
			c.send(true, 0x2, []byte("rsv"), withRSV)
		},
		"reserved opcode": func(c *rawClient) {
			c.send(true, 0x3, []byte("reserved"))
		},
		"fragmented control frame": func(c *rawClient) {
			c.send(false, 0x9, []byte("ping"))
		},
		"oversized control frame": func(c *rawClient) {
			c.send(true, 0x9, make([]byte, 126))
		},
		"non-minimal 16-bit length": func(c *rawClient) {
			c.send(true, 0x2, []byte("short"), extendedForm)
		},
		"non-minimal 64-bit length": func(c *rawClient) {
			c.send(true, 0x2, []byte("short"), longForm)
		},
		"continuation without a message": func(c *rawClient) {
			c.send(true, 0x0, []byte("orphan"))
		},
		"new message inside a fragmented one": func(c *rawClient) {
			c.send(false, 0x2, []byte("first"))
			c.send(true, 0x2, []byte("second"))
		},
	}

	for name, send := range testData {
		suite.Run(name, func() {
			client, result := suite.connect()
			send(client)

			suite.Require().ErrorIs(result.waitErr(t), ws.ErrProtocol)
		})
	}
}

func (suite *FramingTestSuite) TestMessageAboveTheMaximum() {
	t := suite.T()
	server, result := newServer(t, ws.Options{Subprotocol: testSubprotocol, MaxMessage: 128})
	client := dial(t, server, map[string]string{"Sec-WebSocket-Protocol": testSubprotocol})

	suite.Require().Equal(http.StatusSwitchingProtocols, client.response().StatusCode)

	client.send(true, 0x2, make([]byte, 200))
	suite.Require().ErrorIs(result.waitErr(t), ws.ErrMessageTooBig)
}

// The bound is on the whole reassembled message, not on one frame: three legal
// fragments that add up past the maximum are still one oversized message.
func (suite *FramingTestSuite) TestFragmentsCannotSmuggleAnOversizedMessage() {
	t := suite.T()
	server, result := newServer(t, ws.Options{Subprotocol: testSubprotocol, MaxMessage: 128})
	client := dial(t, server, map[string]string{"Sec-WebSocket-Protocol": testSubprotocol})

	suite.Require().Equal(http.StatusSwitchingProtocols, client.response().StatusCode)

	client.send(false, 0x2, make([]byte, 100))
	client.send(true, 0x0, make([]byte, 100))

	suite.Require().ErrorIs(result.waitErr(t), ws.ErrMessageTooBig)
}

type LivenessTestSuite struct {
	suite.Suite
}

// A peer that died without a FIN must not pin the session until TCP notices.
// One silence period produces a ping; two produce a close.
func (suite *LivenessTestSuite) TestSilenceIsPingedThenClosed() {
	t := suite.T()
	server, result := newServer(t, ws.Options{
		Subprotocol: testSubprotocol,
		IdleTimeout: 150 * time.Millisecond,
	})
	client := dial(t, server, map[string]string{"Sec-WebSocket-Protocol": testSubprotocol})

	suite.Require().Equal(http.StatusSwitchingProtocols, client.response().StatusCode)

	opcode, _, err := client.receive()
	suite.Require().NoError(err)
	suite.Equal(byte(0x9), opcode, "the first idle period must produce a ping")

	suite.Require().ErrorIs(result.waitErr(t), ws.ErrClosed)
}

// Traffic clears the ping state, so a busy connection is never pinged and never
// reaches the two-period close.
func (suite *LivenessTestSuite) TestTrafficPostponesTheProbe() {
	t := suite.T()
	server, result := newServer(t, ws.Options{
		Subprotocol: testSubprotocol,
		IdleTimeout: 200 * time.Millisecond,
	})
	client := dial(t, server, map[string]string{"Sec-WebSocket-Protocol": testSubprotocol})

	suite.Require().Equal(http.StatusSwitchingProtocols, client.response().StatusCode)

	for range 4 {
		time.Sleep(80 * time.Millisecond)
		client.send(true, 0x2, []byte("tick"))
		result.waitMessage(t)

		opcode, _, err := client.receive()
		suite.Require().NoError(err)
		suite.Equal(byte(0x2), opcode, "a busy connection is never pinged")
	}
}

func TestHandshake(t *testing.T) {
	t.Parallel()
	suite.Run(t, &HandshakeTestSuite{})
}

func TestFraming(t *testing.T) {
	t.Parallel()
	suite.Run(t, &FramingTestSuite{})
}

func TestLiveness(t *testing.T) {
	t.Parallel()
	suite.Run(t, &LivenessTestSuite{})
}

// The accept key is the one value a peer verifies before it will speak at all,
// so it is pinned against a fixed vector rather than recomputed by the test with
// the same code under test.
//
// The expected value was produced by an independent implementation of the same
// construction (Node's crypto, in a scratch script) rather than copied from a
// document, because a mistyped constant here would pass review and fail every
// real browser. TestBridgeInABrowser is the end of that argument: a genuine
// Chromium handshake refuses a wrong accept key outright.
func TestAcceptKeyIsCorrectForAFixedVector(t *testing.T) {
	t.Parallel()

	server, _ := newServer(t, ws.Options{})

	address := strings.TrimPrefix(server.URL, "http://")
	conn, err := net.DialTimeout("tcp", address, 5*time.Second)
	require.NoError(t, err)

	defer conn.Close()

	request := fmt.Sprintf("GET /api/v1/ws HTTP/1.1\r\nHost: %s\r\n"+
		"Upgrade: websocket\r\nConnection: Upgrade\r\n"+
		"Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n", address)

	_, err = io.WriteString(conn, request)
	require.NoError(t, err)
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))

	response, err := http.ReadResponse(bufio.NewReader(conn), nil)
	require.NoError(t, err)

	defer response.Body.Close()

	require.Equal(t, http.StatusSwitchingProtocols, response.StatusCode)
	require.Equal(t, "7NQHw21/u2y5o3iigl/YosUutlE=", response.Header.Get("Sec-WebSocket-Accept"))
}
