package doppel

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// coverServer is a local HTTPS site whose certificate carries sans extra
// names, so two of them present certificate chains of different sizes. It
// counts the requests it serves.
type coverServer struct {
	*httptest.Server

	requests atomic.Int64
}

func newCoverServer(t *testing.T, sans int) *coverServer {
	t.Helper()

	cs := &coverServer{}
	cs.Server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		cs.requests.Add(1)
		w.Write([]byte("cover")) //nolint: errcheck
	}))

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	names := make([]string, sans+1)
	names[0] = "cover.test"

	for i := 1; i <= sans; i++ {
		names[i] = fmt.Sprintf("name-%03d.cover.test", i)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "cover.test"},
		DNSNames:     names,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	cs.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}} //nolint: gosec
	cs.StartTLS()
	t.Cleanup(cs.Close)

	return cs
}

func (cs *coverServer) host(name string) CoverHost {
	return CoverHost{Host: name, Addr: cs.Listener.Addr().String()}
}

func quietLogger() *LoggerMock {
	log := &LoggerMock{}
	log.On("Info", mock.AnythingOfType("string")).Maybe()
	log.On("WarningError", mock.AnythingOfType("string"), mock.Anything).Maybe()

	return log
}

// measured is what one scout visit to h reports as its certificate size.
func measured(t *testing.T, h CoverHost) int {
	t.Helper()

	result, err := NewScout(SimpleNetwork{}, nil).LearnCover(t.Context(), h)
	require.NoError(t, err)
	require.Positive(t, result.CertSize)

	return result.CertSize
}

func calibrated(g *Ganger, host string) func() bool {
	return func() bool { return g.NoiseParamsFor(host).Mean > 0 }
}

// With no URLs configured, each cover site named by the secrets is measured,
// and a handshake for one is sized like that site's, not like another's.
func TestCoverHostsAreMeasuredSeparately(t *testing.T) {
	t.Parallel()

	small, large := newCoverServer(t, 0), newCoverServer(t, 300)
	a, b := small.host("a.test"), large.host("b.test")

	g := NewGanger(t.Context(), SimpleNetwork{}, quietLogger(), time.Hour, 3, nil, false, ShapingRecord, true)
	g.SetCoverHosts([]CoverHost{a, b})
	g.Run()
	t.Cleanup(g.Shutdown)

	require.Eventually(t, calibrated(g, "a.test"), 5*time.Second, 20*time.Millisecond)
	require.Eventually(t, calibrated(g, "b.test"), 5*time.Second, 20*time.Millisecond)

	noiseA, noiseB := g.NoiseParamsFor("a.test"), g.NoiseParamsFor("b.test")

	assert.InDelta(t, measured(t, a), noiseA.Mean, float64(noiseA.Jitter), "a.test is sized like a.test")
	assert.InDelta(t, measured(t, b), noiseB.Mean, float64(noiseB.Jitter), "b.test is sized like b.test")
	assert.Greater(t, noiseB.Mean-noiseA.Mean, noiseA.Jitter+noiseB.Jitter,
		"two cover sites with different certificates must not share one size")
}

// A cover site that appears later -- a secret change -- is measured at once,
// not at the next raid hours away; until then its handshakes use the fallback.
func TestNewCoverHostIsMeasuredPromptly(t *testing.T) {
	t.Parallel()

	small, large := newCoverServer(t, 0), newCoverServer(t, 300)
	a, b := small.host("a.test"), large.host("b.test")

	g := NewGanger(t.Context(), SimpleNetwork{}, quietLogger(), time.Hour, 3, nil, false, ShapingRecord, true)
	g.SetCoverHosts([]CoverHost{a})
	g.Run()
	t.Cleanup(g.Shutdown)

	require.Eventually(t, calibrated(g, "a.test"), 5*time.Second, 20*time.Millisecond)
	assert.Equal(t, g.NoiseParams(), g.NoiseParamsFor("b.test"), "an unmeasured host falls back")

	g.SetCoverHosts([]CoverHost{a, b})

	require.Eventually(t, calibrated(g, "b.test"), 5*time.Second, 20*time.Millisecond,
		"a new cover host must be measured promptly, with raids an hour apart")
}

// Configured URLs keep today's behaviour: the URLs are scouted, the cover
// hosts are not, and every host gets the one global size.
func TestConfiguredURLsKeepTodaysBehaviour(t *testing.T) {
	t.Parallel()

	configured, cover := newCoverServer(t, 0), newCoverServer(t, 300)

	g := NewGanger(t.Context(), SimpleNetwork{}, quietLogger(), time.Hour, 3,
		[]string{configured.URL}, false, ShapingRecord, true)
	g.SetCoverHosts([]CoverHost{cover.host("b.test")})
	g.Run()
	t.Cleanup(g.Shutdown)

	require.Eventually(t, func() bool { return g.NoiseParams().Mean > 0 }, 5*time.Second, 20*time.Millisecond)

	assert.Equal(t, g.NoiseParams(), g.NoiseParamsFor("b.test"))
	assert.Zero(t, cover.requests.Load(), "with URLs configured the cover hosts are not scouted")
}

// Without the scouting switch -- a library user who did not ask -- cover hosts
// are recorded but nothing is fetched.
func TestCoverHostsAreNotScoutedUnlessAsked(t *testing.T) {
	t.Parallel()

	cover := newCoverServer(t, 0)

	g := NewGanger(t.Context(), SimpleNetwork{}, quietLogger(), time.Hour, 3, nil, false, ShapingRecord, false)
	g.SetCoverHosts([]CoverHost{cover.host("a.test")})
	g.Run()
	t.Cleanup(g.Shutdown)

	time.Sleep(300 * time.Millisecond)

	assert.Equal(t, []CoverHost{cover.host("a.test")}, g.CoverHosts())
	assert.Zero(t, cover.requests.Load())
}
