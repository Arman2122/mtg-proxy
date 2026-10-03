package webrelay

import (
	"bytes"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/Arman2122/mtg-proxy/internal/testclient"
	"github.com/Arman2122/mtg-proxy/mtglib"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The ring forgets the oldest id once it is full, whether it grew there or
// started there: the rule a close race is judged by.
func TestTombstonesForgetTheOldestPastTheirSize(t *testing.T) {
	t.Parallel()

	tombs := newTombstones(3)
	for id := uint32(1); id <= 5; id++ {
		tombs.add(id)
	}

	for id, want := range map[uint32]bool{1: false, 2: false, 3: true, 4: true, 5: true} {
		assert.Equal(t, want, tombs.has(id), "id %d", id)
	}
}

// echoOnceBackend is a stand-in for the proxy's loopback listener: each
// connection gets its first byte back, then is held open and idle.
func echoOnceBackend(t *testing.T) string {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	var (
		mu   sync.Mutex
		held []net.Conn
	)

	t.Cleanup(func() {
		listener.Close() //nolint: errcheck

		mu.Lock()
		defer mu.Unlock()

		for _, c := range held {
			c.Close() //nolint: errcheck
		}
	})

	go func() {
		for {
			c, err := listener.Accept()
			if err != nil {
				return
			}

			mu.Lock()
			held = append(held, c)
			mu.Unlock()

			go func() {
				one := make([]byte, 1)
				if _, err := io.ReadFull(c, one); err == nil {
					c.Write(one) //nolint: errcheck
				}
			}()
		}
	}()

	return listener.Addr().String()
}

// An idle WEB session -- a carrier and one stream waiting on its backend --
// costs the relay little: under 32 KiB, measured here together with the test
// client's own side, which TestAnIdleSessionHoldsLittleMemory holds under 16.
func TestAnIdleRelaySessionHoldsLittle(t *testing.T) { //nolint: paralleltest // reads the heap
	const sessions = 64

	backend, err := NewTCPBackend(echoOnceBackend(t), false, 0)
	require.NoError(t, err)

	signer, err := NewSigner(bytes.Repeat([]byte{5}, TokenKeySize))
	require.NoError(t, err)

	secret := mtglib.Secret{Mode: mtglib.SecretModeFakeTLS, Host: "www.cloudflare.com"}
	secret.Key[0] = 42

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

	open := func() *testclient.WebSession {
		session, err := testclient.OpenWebSession(t.Context(), server.URL, capability.String(),
			testclient.WebOptions{Origin: originHost, ReadBufferSize: 4 << 10})
		require.NoError(t, err)

		stream, err := session.OpenStream(1)
		require.NoError(t, err)
		require.NoError(t, stream.SetDeadline(time.Now().Add(10*time.Second)))

		_, err = stream.Write([]byte{9})
		require.NoError(t, err)

		_, err = io.ReadFull(stream, make([]byte, 1))
		require.NoError(t, err, "the stream reached its backend and back")

		return session
	}

	// One first, so the server, the pools and the client's transport are warm.
	warm := open()

	var before, after runtime.MemStats

	runtime.GC()
	runtime.ReadMemStats(&before)

	held := make([]*testclient.WebSession, 0, sessions)
	for range sessions {
		held = append(held, open())
	}

	runtime.GC()
	runtime.ReadMemStats(&after)

	perSession := (int64(after.HeapAlloc) - int64(before.HeapAlloc)) / sessions //nolint: gosec // heap sizes
	t.Logf("an idle session holds %d bytes, relay and test client together", perSession)
	assert.Less(t, perSession, int64(48<<10), "an idle session holds %d bytes, relay and test client together", perSession)

	for _, s := range append(held, warm) {
		s.Close() //nolint: errcheck
	}
}
