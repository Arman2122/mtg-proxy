package mtglib

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	stdtls "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/Arman2122/mtg-proxy/essentials"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// scoutingNetwork is fakeNetwork with an HTTP client that dials where the scout
// asks and accepts the local cover site's self-signed certificate. fakeNetwork's
// own client ignores the scout's dialer, so nothing could be measured through it.
type scoutingNetwork struct {
	*fakeNetwork
}

func (scoutingNetwork) MakeHTTPClient(
	dial func(ctx context.Context, network, address string) (essentials.Conn, error),
) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &stdtls.Config{InsecureSkipVerify: true}, //nolint: gosec // a local test site
			DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
				return dial(ctx, network, address)
			},
		},
	}
}

// selfSignedCert is a certificate for host carrying sans extra names, so two
// of them make certificate chains of different sizes.
func selfSignedCert(t *testing.T, host string, sans int) stdtls.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	names := []string{host}
	for i := 1; i <= sans; i++ {
		names = append(names, fmt.Sprintf("name-%03d.%s", i, host))
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     names,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	return stdtls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// The spec's acceptance test for per-host sizing: a proxy with no doppelganger
// URLs, two ee secrets naming two cover sites whose certificates differ in
// size, and each client's fake handshake sized like the site its SNI names.
// Both sites sit behind one fronting address, told apart by SNI, as an SNI
// router would serve them.
func TestHandshakeIsSizedLikeTheNamedCoverSite(t *testing.T) {
	t.Parallel()

	const small, large = "small.cover.test", "large.cover.test"

	// Both above the fake handshake's 1,000-byte floor, as real chains are.
	certs := map[string]stdtls.Certificate{
		small: selfSignedCert(t, small, 50),
		large: selfSignedCert(t, large, 300),
	}

	site := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("cover")) //nolint: errcheck
	}))
	site.TLS = &stdtls.Config{ //nolint: gosec // a local test site
		GetCertificate: func(hello *stdtls.ClientHelloInfo) (*stdtls.Certificate, error) {
			cert, ok := certs[hello.ServerName]
			if !ok {
				return nil, fmt.Errorf("no certificate for %q", hello.ServerName)
			}

			return &cert, nil
		},
	}
	site.StartTLS()
	t.Cleanup(site.Close)

	_, port, err := net.SplitHostPort(site.Listener.Addr().String())
	require.NoError(t, err)

	frontingPort, err := strconv.Atoi(port)
	require.NoError(t, err)

	secrets := map[string]Secret{"alice": GenerateSecret(small), "bob": GenerateSecret(large)}

	opts, _ := servingOpts(t)
	opts.Network = scoutingNetwork{opts.Network.(*fakeNetwork)} //nolint: forcetypeassert
	opts.Secrets = secrets
	opts.DomainFrontingHost = "127.0.0.1"
	opts.DomainFrontingPort = uint(frontingPort)
	opts.DoppelGangerScoutCovers = true

	proxy, err := NewProxy(opts)
	require.NoError(t, err)
	t.Cleanup(proxy.Shutdown)

	for _, host := range []string{small, large} {
		require.Eventually(t, func() bool { return proxy.doppelGanger.NoiseParamsFor(host).Mean > 0 },
			10*time.Second, 20*time.Millisecond, "%s was never measured", host)
	}

	smallNoise, largeNoise := proxy.doppelGanger.NoiseParamsFor(small), proxy.doppelGanger.NoiseParamsFor(large)
	require.Greater(t, largeNoise.Mean-smallNoise.Mean, smallNoise.Jitter+largeNoise.Jitter,
		"precondition: the two sites' sizes must not overlap, or this test proves nothing")

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	served := serveInBackground(proxy, listener)
	t.Cleanup(func() {
		listener.Close() //nolint: errcheck
		<-served
	})

	for i, c := range []struct{ name, host string }{{"alice", small}, {"bob", large}} {
		client, err := net.Dial("tcp", listener.Addr().String())
		require.NoError(t, err)

		hello := fakeTLSClientHello(t, secrets[c.name].Key, c.host, bytes.Repeat([]byte{byte(0x50 + i)}, 32))

		_, err = client.Write(hello)
		require.NoError(t, err)
		require.NoError(t, client.SetReadDeadline(time.Now().Add(5*time.Second)))

		records, _ := goldenReadFlight(t, client)
		client.Close() //nolint: errcheck

		noise := proxy.doppelGanger.NoiseParamsFor(c.host)

		assert.InDelta(t, noise.Mean, len(records[2].payload), float64(noise.Jitter),
			"%s's handshake must be sized like %s's certificate flight", c.name, c.host)
	}
}
