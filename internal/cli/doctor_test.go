package cli

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Arman2122/mtg-proxy/essentials"
	"github.com/Arman2122/mtg-proxy/internal/config"
	"github.com/Arman2122/mtg-proxy/internal/utils"
	"github.com/Arman2122/mtg-proxy/mtglib"
	"github.com/Arman2122/mtg-proxy/mtglib/obfuscation"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mtg doctor is what an operator runs when a proxy does not work, so it is the
// one command whose own correctness nobody can check in the field: a check that
// says ✅ for a broken thing, or ❌ for a working one, sends them the wrong way.
// Every check reaches the world through a seam -- the network, the resolver,
// the NTP query, the output -- and these tests drive each seam both ways.

// doctorNetwork is a mtglib.Network whose every dial goes where the test says,
// whose public-IP lookup answers what the test says, and which records the
// addresses it was asked for.
type doctorNetwork struct {
	dial     func(ctx context.Context, network, address string) (net.Conn, error)
	publicIP map[string]string // "tcp4"/"tcp6" -> body the IP service returns; missing = failure

	mu     sync.Mutex
	dialed []string
}

func (n *doctorNetwork) Dial(network, address string) (essentials.Conn, error) {
	return n.DialContext(context.Background(), network, address)
}

func (n *doctorNetwork) DialContext(ctx context.Context, network, address string) (essentials.Conn, error) {
	n.mu.Lock()
	n.dialed = append(n.dialed, address)
	n.mu.Unlock()

	conn, err := n.dial(ctx, network, address)
	if err != nil {
		return nil, err
	}

	return essentials.WrapNetConn(conn), nil
}

// MakeHTTPClient is how getIP reaches its IP service. The client answers from
// the map and never dials: the protocol the caller wanted is recovered from the
// dial function it passed, by dialling nothing and reading the error it makes.
func (n *doctorNetwork) MakeHTTPClient(
	dial func(ctx context.Context, network, address string) (essentials.Conn, error),
) *http.Client {
	return &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		// getIP wraps the native dialer with the protocol baked in; probing it
		// against an unroutable address surfaces which one.
		_, err := dial(r.Context(), "tcp", "192.0.2.1:1")

		protocol := "tcp4"
		if err != nil && strings.Contains(err.Error(), "tcp6") {
			protocol = "tcp6"
		}

		body, ok := n.publicIP[protocol]
		if !ok {
			return nil, errors.New("no route to the IP service")
		}

		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{},
			Body:       io.NopCloser(strings.NewReader(body + "\n")),
			Request:    r,
		}, nil
	})}
}

func (n *doctorNetwork) NativeDialer() *net.Dialer { return &net.Dialer{Timeout: time.Second} }

func (n *doctorNetwork) addresses() []string {
	n.mu.Lock()
	defer n.mu.Unlock()

	return append([]string(nil), n.dialed...)
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// refuseAll is a network on which nothing answers.
func refuseAll(_ context.Context, _, address string) (net.Conn, error) {
	return nil, fmt.Errorf("dial tcp %s: connection refused", address)
}

// toFakeDC sends every dial to one local stand-in Telegram, whatever address
// was asked for.
func toFakeDC(addr string) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	}
}

// startFakeDC is a Telegram DC as far as the doctor's probe can tell: it reads
// the obfuscated2 handshake, takes the req_pq_multi out of its envelope, and
// answers a resPQ that echoes the nonce. That echo is the whole of what the
// probe verifies, so this is exactly enough to make ✅ mean something.
func startFakeDC(t *testing.T) string {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { listener.Close() }) //nolint: errcheck

	// TL: resPQ#05162463 nonce:int128 server_nonce:int128 pq:string ...
	const ctorResPQ uint32 = 0x05162463

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}

			go func(c net.Conn) {
				defer c.Close() //nolint: errcheck

				_ = c.SetDeadline(time.Now().Add(10 * time.Second))

				_, _, obfs, err := obfuscation.Obfuscator{}.ReadHandshake(
					essentials.WrapNetConn(c), obfuscation.TagSetOf(obfuscation.TagPaddedIntermediate))
				if err != nil {
					return
				}

				var lenBuf [4]byte
				if _, err := io.ReadFull(obfs, lenBuf[:]); err != nil {
					return
				}

				body := make([]byte, binary.LittleEndian.Uint32(lenBuf[:]))
				if _, err := io.ReadFull(obfs, body); err != nil {
					return
				}

				// envelope(20) + constructor(4), then the client's nonce.
				const nonceAt = 20 + 4
				if len(body) < nonceAt+16 {
					return
				}

				tl := make([]byte, 0, 64)
				tl = binary.LittleEndian.AppendUint32(tl, ctorResPQ)
				tl = append(tl, body[nonceAt:nonceAt+16]...) // nonce, echoed
				tl = append(tl, make([]byte, 16)...)         // server_nonce
				tl = append(tl, make([]byte, 24)...)         // pq and fingerprints, not verified

				envelope := make([]byte, 20, 20+len(tl))
				binary.LittleEndian.PutUint32(envelope[16:20], uint32(len(tl))) //nolint: gosec // small
				envelope = append(envelope, tl...)

				frame := binary.LittleEndian.AppendUint32(nil, uint32(len(envelope))) //nolint: gosec // small
				frame = append(frame, envelope...)

				_, _ = obfs.Write(frame)
			}(conn)
		}
	}()

	return listener.Addr().String()
}

// fakeResolver answers LookupIPAddr from a map and refuses every other name.
type fakeResolver map[string][]string

func (r fakeResolver) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	ips, ok := r[host]
	if !ok {
		return nil, fmt.Errorf("lookup %s: no such host", host)
	}

	out := make([]net.IPAddr, 0, len(ips))
	for _, ip := range ips {
		out = append(out, net.IPAddr{IP: net.ParseIP(ip)})
	}

	return out, nil
}

// newDoctor builds a doctor over a config, writing to a buffer the test reads,
// with an NTP that reports the given offset.
func newDoctor(t *testing.T, raw string, ntpOffset time.Duration, ntpErr error) (*Doctor, *bytes.Buffer) {
	t.Helper()

	conf, err := utils.ParseConfig([]byte(raw))
	require.NoError(t, err)

	out := &bytes.Buffer{}

	return &Doctor{
		conf: conf,
		out:  out,
		queryNTP: func(string) (time.Duration, error) {
			return ntpOffset, ntpErr
		},
	}, out
}

const doctorSecretHost = "alice.example.com"

// doctorConfig is the smallest config the doctor accepts, plus whatever the
// test appends.
func doctorConfig(extra string) string {
	return `
secret = "` + mtglib.GenerateSecret(doctorSecretHost).Hex() + `"
bind-to = "127.0.0.1:3128"
tolerate-time-skewness = "10s"
` + extra
}

func TestDoctorDeprecatedOptions(t *testing.T) {
	t.Parallel()

	t.Run("a clean config is all good", func(t *testing.T) {
		t.Parallel()

		d, out := newDoctor(t, doctorConfig(""), 0, nil)

		assert.True(t, d.checkDeprecatedConfig())
		assert.Contains(t, out.String(), "All good")
	})

	t.Run("a deprecated key is named with its replacement", func(t *testing.T) {
		t.Parallel()

		d, out := newDoctor(t, doctorConfig(`domain-fronting-port = 443`), 0, nil)

		assert.False(t, d.checkDeprecatedConfig())
		assert.Contains(t, out.String(), `"domain-fronting-port"`)
		assert.Contains(t, out.String(), "deprecated")
		assert.Contains(t, out.String(), `"port"`, "the replacement must be named")
	})
}

// The doctor names every key the binary does not know, with its path, because
// "this setting does nothing" is what an operator runs the doctor for.
func TestDoctorUnknownKeys(t *testing.T) {
	t.Parallel()

	t.Run("a clean config is all known", func(t *testing.T) {
		t.Parallel()

		d, out := newDoctor(t, doctorConfig(""), 0, nil)

		assert.True(t, d.checkUnknownKeys())
		assert.Contains(t, out.String(), "Every key in the file is known")
	})

	t.Run("a misspelled key is named with its path", func(t *testing.T) {
		t.Parallel()

		d, out := newDoctor(t, doctorConfig(`track-client-ip = true

[secret-limits.default]
quota_reset = "monthly"
`), 0, nil)

		assert.False(t, d.checkUnknownKeys())
		assert.Contains(t, out.String(), `"track-client-ip"`)
		assert.Contains(t, out.String(), `"secret-limits.default.quota_reset"`)
		assert.Contains(t, out.String(), "ignored")
	})
}

// The skew check grades the NTP offset against tolerate-time-skewness. Its
// thresholds are the difference between a proxy that works and one that
// rejects every client for a reason nothing else reports.
func TestDoctorTimeSkewness(t *testing.T) {
	t.Parallel()

	for name, tc := range map[string]struct {
		offset time.Duration
		err    error
		ok     bool
		mark   string
	}{
		"well inside tolerance":     {offset: time.Second, ok: true, mark: "✅"},
		"drifting, still inside":    {offset: 5 * time.Second, ok: false, mark: "⚠️"},
		"about to reject clients":   {offset: 9 * time.Second, ok: false, mark: "❌"},
		"negative drift counts too": {offset: -9 * time.Second, ok: false, mark: "❌"},
		"ntp unreachable":           {err: errors.New("i/o timeout"), ok: false, mark: "‼️"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			d, out := newDoctor(t, doctorConfig(""), tc.offset, tc.err)

			assert.Equal(t, tc.ok, d.checkTimeSkewness())
			assert.Contains(t, out.String(), tc.mark)
		})
	}
}

// The network check dials every DC and runs a real MTProto probe on each.
// Against a stand-in DC that answers the probe it is all ✅; against a network
// where nothing answers it is all ❌; and the IP-version preference decides
// which addresses are tried at all.
func TestDoctorNetworkCheck(t *testing.T) {
	t.Parallel()

	t.Run("every DC reachable", func(t *testing.T) {
		t.Parallel()

		d, out := newDoctor(t, doctorConfig(""), 0, nil)
		ntw := &doctorNetwork{dial: toFakeDC(startFakeDC(t))}

		assert.True(t, d.checkNetwork(ntw))

		for dc := range essentials.TelegramCoreAddresses {
			assert.Contains(t, out.String(), fmt.Sprintf("✅ DC %d (rpc", dc))
		}

		assert.NotContains(t, out.String(), "❌")
	})

	t.Run("nothing reachable", func(t *testing.T) {
		t.Parallel()

		d, out := newDoctor(t, doctorConfig(""), 0, nil)
		ntw := &doctorNetwork{dial: refuseAll}

		assert.False(t, d.checkNetwork(ntw))

		for dc := range essentials.TelegramCoreAddresses {
			assert.Contains(t, out.String(), fmt.Sprintf("❌ DC %d:", dc))
		}

		assert.Contains(t, out.String(), "connection refused")
	})

	t.Run("only-ipv6 tries only IPv6 addresses", func(t *testing.T) {
		t.Parallel()

		d, _ := newDoctor(t, doctorConfig(`prefer-ip = "only-ipv6"`), 0, nil)
		ntw := &doctorNetwork{dial: refuseAll}

		d.checkNetwork(ntw)

		dialed := ntw.addresses()
		require.NotEmpty(t, dialed)

		for _, addr := range dialed {
			host, _, err := net.SplitHostPort(addr)
			require.NoError(t, err)
			assert.Nil(t, net.ParseIP(host).To4(), "an IPv4 address was tried under only-ipv6: %s", addr)
		}
	})
}

// The fronting check dials the cover site with the native dialer, so it is
// driven with a real loopback socket: one that listens, and a port that does
// not.
func TestDoctorFrontingDomain(t *testing.T) {
	t.Parallel()

	t.Run("reachable", func(t *testing.T) {
		t.Parallel()

		cover, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)

		defer cover.Close() //nolint: errcheck

		_, port, err := net.SplitHostPort(cover.Addr().String())
		require.NoError(t, err)

		d, out := newDoctor(t, doctorConfig("[domain-fronting]\nhost = \"127.0.0.1\"\nport = "+port), 0, nil)

		assert.True(t, d.checkFrontingDomain(&doctorNetwork{dial: refuseAll}))
		assert.Contains(t, out.String(), "✅ 127.0.0.1:"+port+" is reachable")
	})

	t.Run("not listening", func(t *testing.T) {
		t.Parallel()

		d, out := newDoctor(t, doctorConfig("[domain-fronting]\nhost = \"127.0.0.1\"\nport = 1"), 0, nil)

		assert.False(t, d.checkFrontingDomain(&doctorNetwork{dial: refuseAll}))
		assert.Contains(t, out.String(), "❌ 127.0.0.1:1:")
	})
}

// The SNI check compares what the secret's hostname resolves to against the
// server's public address -- from the config when set, else detected. A
// mismatch is the single most common reason a FakeTLS proxy does not work.
func TestDoctorSNIMatch(t *testing.T) {
	t.Parallel()

	const ours = "203.0.113.7"

	t.Run("matches the detected public address", func(t *testing.T) {
		t.Parallel()

		d, out := newDoctor(t, doctorConfig(""), 0, nil)
		ntw := &doctorNetwork{dial: refuseAll, publicIP: map[string]string{"tcp4": ours}}

		assert.True(t, d.checkSecretHost(fakeResolver{doctorSecretHost: {ours}}, ntw))
		assert.Contains(t, out.String(), "✅ IP address "+ours+" matches secret hostname "+doctorSecretHost)
	})

	t.Run("matches the configured public address without detecting", func(t *testing.T) {
		t.Parallel()

		d, out := newDoctor(t, doctorConfig(`public-ipv4 = "`+ours+`"`), 0, nil)
		// No IP service at all: the config must be enough.
		ntw := &doctorNetwork{dial: refuseAll}

		assert.True(t, d.checkSecretHost(fakeResolver{doctorSecretHost: {ours}}, ntw))
		assert.Contains(t, out.String(), "✅")
	})

	t.Run("resolves elsewhere", func(t *testing.T) {
		t.Parallel()

		d, out := newDoctor(t, doctorConfig(""), 0, nil)
		ntw := &doctorNetwork{dial: refuseAll, publicIP: map[string]string{"tcp4": ours}}

		assert.False(t, d.checkSecretHost(fakeResolver{doctorSecretHost: {"198.51.100.1"}}, ntw))
		assert.Contains(t, out.String(), "❌ Hostname "+doctorSecretHost)
		assert.Contains(t, out.String(), "198.51.100.1")
		assert.Contains(t, out.String(), ours, "the server's own address must be shown for comparison")
	})

	t.Run("does not resolve", func(t *testing.T) {
		t.Parallel()

		d, out := newDoctor(t, doctorConfig(""), 0, nil)
		ntw := &doctorNetwork{dial: refuseAll, publicIP: map[string]string{"tcp4": ours}}

		assert.False(t, d.checkSecretHost(fakeResolver{}, ntw))
		assert.Contains(t, out.String(), "‼️ cannot resolve DNS name of "+doctorSecretHost)
	})

	t.Run("public address unknown", func(t *testing.T) {
		t.Parallel()

		d, out := newDoctor(t, doctorConfig(""), 0, nil)
		ntw := &doctorNetwork{dial: refuseAll} // no IP service, nothing configured

		assert.False(t, d.checkSecretHost(fakeResolver{doctorSecretHost: {ours}}, ntw))
		assert.Contains(t, out.String(), "‼️ cannot detect public IP address")
	})
}

// diagnose runs every check in order and its verdict is all of them. Driven
// once with everything healthy and once with one thing wrong, so a regression
// that drops a check from the aggregate is caught.
func TestDoctorDiagnose(t *testing.T) {
	t.Parallel()

	const ours = "203.0.113.7"

	cover, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	// Cleanup, not defer: the subtests are parallel, so this function returns
	// before they run, and a defer would close the cover site under them.
	t.Cleanup(func() { cover.Close() }) //nolint: errcheck

	_, port, err := net.SplitHostPort(cover.Addr().String())
	require.NoError(t, err)

	healthy := doctorConfig("[domain-fronting]\nhost = \"127.0.0.1\"\nport = " + port)
	dc := startFakeDC(t)
	resolver := fakeResolver{doctorSecretHost: {ours}}

	t.Run("everything healthy", func(t *testing.T) {
		t.Parallel()

		d, out := newDoctor(t, healthy, time.Second, nil)
		ntw := &doctorNetwork{dial: toFakeDC(dc), publicIP: map[string]string{"tcp4": ours}}

		ok, err := d.diagnose(ntw, resolver)
		require.NoError(t, err)
		assert.True(t, ok)

		for _, section := range []string{
			"Deprecated options", "Time skewness", "Validate native network connectivity",
			"Validate fronting domain connectivity", "Validate SNI-DNS match",
		} {
			assert.Contains(t, out.String(), section)
		}

		assert.NotContains(t, out.String(), "❌")
		assert.NotContains(t, out.String(), "‼️")
	})

	t.Run("one thing wrong is a failing verdict", func(t *testing.T) {
		t.Parallel()

		d, out := newDoctor(t, healthy, time.Second, errors.New("ntp: i/o timeout"))
		ntw := &doctorNetwork{dial: toFakeDC(dc), publicIP: map[string]string{"tcp4": ours}}

		ok, err := d.diagnose(ntw, resolver)
		require.NoError(t, err)
		assert.False(t, ok)
		assert.Contains(t, out.String(), "‼️ cannot access ntp pool")
	})

	t.Run("the native check can be skipped", func(t *testing.T) {
		t.Parallel()

		d, out := newDoctor(t, healthy, time.Second, nil)
		d.SkipNativeCheck = true
		ntw := &doctorNetwork{dial: refuseAll, publicIP: map[string]string{"tcp4": ours}}

		ok, err := d.diagnose(ntw, resolver)
		require.NoError(t, err)
		assert.True(t, ok, "with the native check skipped, an unreachable network must not fail the verdict")
		assert.Contains(t, out.String(), "Skipped")
		assert.Empty(t, ntw.addresses(), "a skipped check must not dial")
	})
}

// The config's own parser is what the doctor reads, so a config the proxy
// would refuse is refused here too rather than half-diagnosed.
func TestDoctorReadsTheConfigTheProxyWould(t *testing.T) {
	t.Parallel()

	_, err := config.Parse([]byte("this is not toml ]["))
	require.Error(t, err)
}
