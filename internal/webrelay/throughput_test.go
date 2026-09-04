package webrelay

import (
	"bytes"
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

// Downlink throughput through the whole relay: WebSocket framing, the outbox
// and its batching, per-stream flow control, and the backend read pump.
//
// It measures THIS PROCESS, on loopback, with no TLS and no front proxy. That
// is deliberate: a number that included the network would be a number about the
// network. What an operator needs from here is the ceiling the relay itself
// imposes and the memory it costs to reach it; the wire between a browser and a
// datacentre is theirs to measure.
//
// Run it with:
//
//	go test ./internal/webrelay/ -run xxx -bench Downlink -benchtime 20x
func BenchmarkCarrierDownlink(b *testing.B) {
	const chunk = 64 << 10 // what the relay itself emits per DATA frame

	payload := bytes.Repeat([]byte{0x5a}, chunk)

	backendListener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(b, err)

	defer backendListener.Close()

	// The backend writes for as long as the relay will take it.
	go func() {
		for {
			conn, err := backendListener.Accept()
			if err != nil {
				return
			}

			go func(c net.Conn) {
				defer c.Close()

				for {
					if _, err := c.Write(payload); err != nil {
						return
					}
				}
			}(conn)
		}
	}()

	signer, err := NewSigner(bytes.Repeat([]byte{5}, TokenKeySize))
	require.NoError(b, err)

	secret := mtglib.Secret{Mode: mtglib.SecretModeFakeTLS, Host: "www.cloudflare.com"}
	secret.Key[0] = 42

	backend, err := NewTCPBackend(backendListener.Addr().String(), false, 0)
	require.NoError(b, err)

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
	require.NoError(b, err)

	server := httptest.NewServer(origin)
	defer server.Close()

	capability, err := Derive(WebSecret(secret), originHost)
	require.NoError(b, err)

	token := benchSession(b, server, capability.String())
	client := dialCarrier(b, server, token)

	client.send(frame.NewOpen(1))

	var (
		received int64
		credited uint32
		start    = time.Now()
	)

	b.ResetTimer()

	for range b.N {
		for _, f := range client.receive() {
			if f.Type != frame.TypeData {
				continue
			}

			size := uint32(len(f.Payload)) //nolint:gosec // bounded by the frame limits
			received += int64(size)
			credited += size

			// Credit is returned in lumps, the way a client drains: returning it
			// per frame would measure the test's own chattiness.
			if credited >= 1<<20 {
				client.send(frame.NewWindow(1, credited))
				credited = 0
			}
		}
	}

	b.StopTimer()

	elapsed := time.Since(start).Seconds()
	if elapsed > 0 {
		b.ReportMetric(float64(received)/elapsed/(1<<20), "MiB/s")
	}

	b.ReportMetric(float64(received)/float64(b.N), "bytes/op")
}

// benchSession walks the bootstrap the bridge page walks: fetch the page, read
// the token out of it, spend it on a session.
func benchSession(b *testing.B, server *httptest.Server, capability string) string {
	b.Helper()

	response, err := server.Client().Get(server.URL + "/?bridge=" + capability) //nolint:noctx // a benchmark request
	require.NoError(b, err)

	defer response.Body.Close()

	document, err := io.ReadAll(response.Body)
	require.NoError(b, err)

	const marker = `"token":"`

	rest := string(document)[strings.Index(string(document), marker)+len(marker):]
	bootstrap := rest[:strings.IndexByte(rest, '"')]

	hello, err := frame.Limits{}.EncodeBatch(nil, []frame.Frame{frame.NewHello()}, frame.ClientToRelay)
	require.NoError(b, err)

	request, err := http.NewRequestWithContext(b.Context(), http.MethodPost,
		server.URL+sessionPath, bytes.NewReader(hello))
	require.NoError(b, err)

	request.Header.Set("Authorization", "Bearer "+bootstrap)

	sessionResponse, err := server.Client().Do(request)
	require.NoError(b, err)

	defer sessionResponse.Body.Close()

	require.Equal(b, http.StatusOK, sessionResponse.StatusCode)

	return sessionResponse.Header.Get("X-Session-Token")
}
