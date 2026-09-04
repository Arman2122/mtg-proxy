package webrelay

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Arman2122/mtg-proxy/internal/webrelay/frame"
	"github.com/Arman2122/mtg-proxy/mtglib"
	"github.com/stretchr/testify/require"
)

// wsClient is the smallest WebSocket client that can drive a real carrier: it
// masks what it sends, because the server refuses anything else, and reassembles
// nothing, because the relay never fragments.
type wsClient struct {
	// testing.TB rather than *testing.T so the benchmark can drive the same
	// carrier the integration test does. A throughput number measured through a
	// second, simpler client would be measuring that client.
	t    testing.TB
	conn net.Conn
	r    *bufio.Reader
}

func dialCarrier(t testing.TB, server *httptest.Server, token string) *wsClient {
	t.Helper()

	address := strings.TrimPrefix(server.URL, "http://")

	conn, err := net.DialTimeout("tcp", address, 5*time.Second)
	require.NoError(t, err)

	t.Cleanup(func() { conn.Close() })

	key := make([]byte, 16)
	_, err = rand.Read(key)
	require.NoError(t, err)

	request := "GET " + carrierPath + " HTTP/1.1\r\nHost: " + address + "\r\n" +
		"Upgrade: websocket\r\nConnection: Upgrade\r\n" +
		"Sec-WebSocket-Version: 13\r\n" +
		"Sec-WebSocket-Key: " + base64.StdEncoding.EncodeToString(key) + "\r\n" +
		"Sec-WebSocket-Protocol: " + subprotocolPrefix + token + "\r\n" +
		"Origin: https://" + originHost + "\r\n\r\n"

	_, err = io.WriteString(conn, request)
	require.NoError(t, err)
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))

	reader := bufio.NewReader(conn)

	response, err := http.ReadResponse(reader, nil)
	require.NoError(t, err)
	require.Equal(t, http.StatusSwitchingProtocols, response.StatusCode)
	require.Equal(t, subprotocolPrefix+token, response.Header.Get("Sec-WebSocket-Protocol"),
		"the subprotocol carries the bearer and must be echoed exactly")

	return &wsClient{t: t, conn: conn, r: reader}
}

func (c *wsClient) send(frames ...frame.Frame) {
	c.t.Helper()

	payload, err := frame.Limits{}.EncodeBatch(nil, frames, frame.ClientToRelay)
	require.NoError(c.t, err)

	header := []byte{0x82, 0}

	switch {
	case len(payload) <= 125:
		header[1] = byte(len(payload)) | 0x80
	default:
		header[1] = 126 | 0x80
		header = binary.BigEndian.AppendUint16(header, uint16(len(payload))) //nolint:gosec // test input
	}

	mask := []byte{0xA1, 0xB2, 0xC3, 0xD4}
	header = append(header, mask...)

	masked := make([]byte, len(payload))
	for i := range payload {
		masked[i] = payload[i] ^ mask[i%4]
	}

	require.NoError(c.t, c.conn.SetWriteDeadline(time.Now().Add(5*time.Second)))
	_, err = c.conn.Write(append(header, masked...))
	require.NoError(c.t, err)
}

// receive returns the next batch of relay frames, skipping control frames.
func (c *wsClient) receive() []frame.Frame {
	c.t.Helper()

	for {
		require.NoError(c.t, c.conn.SetReadDeadline(time.Now().Add(5*time.Second)))

		var head [2]byte
		_, err := io.ReadFull(c.r, head[:])
		require.NoError(c.t, err)

		length := int(head[1] & 0x7F)

		switch length {
		case 126:
			var extended [2]byte
			_, err = io.ReadFull(c.r, extended[:])
			require.NoError(c.t, err)

			length = int(binary.BigEndian.Uint16(extended[:]))
		case 127:
			var extended [8]byte
			_, err = io.ReadFull(c.r, extended[:])
			require.NoError(c.t, err)

			length = int(binary.BigEndian.Uint64(extended[:]))
		}

		payload := make([]byte, length)
		_, err = io.ReadFull(c.r, payload)
		require.NoError(c.t, err)

		if head[0]&0x0F != 0x02 {
			continue // a ping or a close; the carrier's own frames are binary
		}

		decoded, err := frame.Limits{}.DecodeBatch(payload, frame.RelayToClient)
		require.NoError(c.t, err)

		return decoded
	}
}

// TestARealClientCanReachTheBackend walks the whole path a Telegram client
// walks: derive a capability, fetch the bridge, spend its bootstrap, open the
// carrier, and push bytes through a stream to a backend and back.
//
// Every piece below has its own unit tests. This is the only one that proves
// they fit together -- that the bootstrap the page embeds is the one the session
// endpoint accepts, that the token it returns is the one the subprotocol
// carries, and that a byte written by a client comes out of a socket the proxy
// would have accepted.
func TestARealClientCanReachTheBackend(t *testing.T) {
	t.Parallel()

	// A stand-in for the proxy's own loopback [[listener]].
	backendListener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	t.Cleanup(func() { backendListener.Close() })

	accepted := make(chan net.Conn, 1)

	go func() {
		conn, err := backendListener.Accept()
		if err == nil {
			accepted <- conn
		}
	}()

	signer, err := NewSigner(bytes.Repeat([]byte{5}, TokenKeySize))
	require.NoError(t, err)

	secret := mtglib.Secret{Mode: mtglib.SecretModeFakeTLS, Host: "www.cloudflare.com"}
	secret.Key[0] = 42

	backend, err := NewTCPBackend(backendListener.Addr().String(), false, 0)
	require.NoError(t, err)

	origin, err := NewOrigin(OriginOptions{
		Host:    originHost,
		Secrets: []mtglib.Secret{secret},
		Signer:  signer,
		Cover:   http.NotFoundHandler(),
		Backend: backend,
		ClientIP: func(*http.Request) net.Addr {
			return &net.TCPAddr{IP: net.IPv4(203, 0, 113, 42), Port: 40000}
		},
	})
	require.NoError(t, err)

	server := httptest.NewServer(origin)
	t.Cleanup(server.Close)

	capability, err := Derive(WebSecret(secret), originHost)
	require.NoError(t, err)

	// 1. The bridge page, and the bootstrap it embeds.
	pageResponse, err := server.Client().Get(server.URL + "/?bridge=" + capability.String()) //nolint:noctx // a test request
	require.NoError(t, err)

	defer pageResponse.Body.Close()

	document, err := io.ReadAll(pageResponse.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, pageResponse.StatusCode)

	const marker = `"token":"`

	start := strings.Index(string(document), marker)
	require.Positive(t, start)

	rest := string(document)[start+len(marker):]
	bootstrapToken := rest[:strings.IndexByte(rest, '"')]

	// 2. Spend it on a session, exactly as the bridge does.
	hello, err := frame.Limits{}.EncodeBatch(nil, []frame.Frame{frame.NewHello()}, frame.ClientToRelay)
	require.NoError(t, err)

	request, err := http.NewRequestWithContext(t.Context(), http.MethodPost,
		server.URL+sessionPath, bytes.NewReader(hello))
	require.NoError(t, err)

	request.Header.Set("Authorization", "Bearer "+bootstrapToken)

	sessionResponse, err := server.Client().Do(request)
	require.NoError(t, err)

	defer sessionResponse.Body.Close()

	require.Equal(t, http.StatusOK, sessionResponse.StatusCode)

	welcome, err := io.ReadAll(sessionResponse.Body)
	require.NoError(t, err)

	decoded, err := frame.Limits{}.DecodeBatch(welcome, frame.RelayToClient)
	require.NoError(t, err)
	require.Len(t, decoded, 1)
	require.Equal(t, frame.TypeWelcome, decoded[0].Type)

	sessionToken := sessionResponse.Header.Get("X-Session-Token")
	require.Len(t, sessionToken, TokenLength)

	// 3. The carrier, and a stream through it.
	client := dialCarrier(t, server, sessionToken)
	client.send(frame.NewOpen(17), frame.NewData(17, []byte("client to backend")))

	var backendConn net.Conn

	select {
	case backendConn = <-accepted:
	case <-time.After(5 * time.Second):
		t.Fatal("the relay never dialled the backend")
	}

	defer backendConn.Close()

	buf := make([]byte, len("client to backend"))
	require.NoError(t, backendConn.SetReadDeadline(time.Now().Add(5*time.Second)))
	_, err = io.ReadFull(backendConn, buf)
	require.NoError(t, err)
	require.Equal(t, "client to backend", string(buf), "the stream must reach the backend byte for byte")

	// 4. Credit comes back, and only after the backend has the bytes.
	frames := client.receive()
	require.NotEmpty(t, frames)
	require.Equal(t, frame.TypeWindow, frames[0].Type)

	delta, ok := frames[0].WindowDelta()
	require.True(t, ok)
	require.Equal(t, uint32(len("client to backend")), delta)

	// 5. And the other direction.
	_, err = backendConn.Write([]byte("backend to client"))
	require.NoError(t, err)

	for {
		frames = client.receive()
		if frames[0].Type == frame.TypeData {
			break
		}
	}

	require.Equal(t, uint32(17), frames[0].StreamID)
	require.Equal(t, "backend to client", string(frames[0].Payload))
}
