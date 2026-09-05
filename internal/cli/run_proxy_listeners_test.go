package cli

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Arman2122/mtg-proxy/internal/config"
	"github.com/Arman2122/mtg-proxy/internal/proxyprotocol"
	"github.com/Arman2122/mtg-proxy/internal/utils"
	"github.com/Arman2122/mtg-proxy/logger"
	"github.com/Arman2122/mtg-proxy/mtglib"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// recordingLogger keeps the WarningError messages so a test can assert that a
// non-fatal listener failure was actually reported and not swallowed.
type recordingLogger struct {
	mtglib.Logger

	mutex    sync.Mutex
	warnings []string
}

func newRecordingLogger() *recordingLogger {
	return &recordingLogger{Logger: logger.NewNoopLogger()}
}

func (r *recordingLogger) Named(_ string) mtglib.Logger          { return r }
func (r *recordingLogger) BindInt(_ string, _ int) mtglib.Logger { return r }
func (r *recordingLogger) BindStr(_, _ string) mtglib.Logger     { return r }
func (r *recordingLogger) BindJSON(_, _ string) mtglib.Logger    { return r }

func (r *recordingLogger) WarningError(msg string, err error) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	r.warnings = append(r.warnings, fmt.Sprintf("%s: %v", msg, err))
}

func (r *recordingLogger) Warning(msg string) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	r.warnings = append(r.warnings, msg)
}

func (r *recordingLogger) recorded() []string {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	return append([]string(nil), r.warnings...)
}

// heldPorts is a set of loopback sockets bound in advance and handed to
// buildListenersWith by address. bind-to rejects port 0, so a config has to
// name concrete ports; picking a free one and closing it left a gap between
// the pick and the bind in which any parallel test in this package could take
// it, and a [[listener]] that loses its port is skipped by design, so the
// symptom was one listener served where two were expected -- once, under
// -race, and never on rerun. Here the socket picked IS the socket served, and
// there is no gap.
//
// An address it does not hold goes to the real binder, so a test that wants a
// bind to fail for real -- takenPort -- still gets a real failure.
type heldPorts struct {
	mu   sync.Mutex
	held map[string]net.Listener
}

func holdPorts(t *testing.T, n int) (*heldPorts, []uint) {
	t.Helper()

	h := &heldPorts{held: make(map[string]net.Listener, n)}
	ports := make([]uint, 0, n)

	for range n {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)

		h.held[l.Addr().String()] = l
		ports = append(ports, uint(l.Addr().(*net.TCPAddr).Port)) //nolint: forcetypeassert
	}

	// Whatever was never asked for is closed here; whatever was handed out
	// belongs to the served set and closeServed closes it.
	t.Cleanup(func() {
		h.mu.Lock()
		defer h.mu.Unlock()

		for _, l := range h.held {
			l.Close() //nolint: errcheck
		}
	})

	return h, ports
}

func (h *heldPorts) listen(addr string) (net.Listener, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if l, ok := h.held[addr]; ok {
		delete(h.held, addr)

		return l, nil
	}

	return utils.NewListener(addr, 0)
}

// remaining lists the held addresses nobody asked for. A test asserts it is
// empty, so a config that rendered an address in a form the binder was not
// asked for by -- and so fell through to a real, racy bind -- fails loudly
// instead of flaking quietly.
func (h *heldPorts) remaining() []string {
	h.mu.Lock()
	defer h.mu.Unlock()

	addrs := make([]string, 0, len(h.held))
	for addr := range h.held {
		addrs = append(addrs, addr)
	}

	return addrs
}

// takenPort occupies a port for the whole test and returns it.
func takenPort(t *testing.T) uint {
	t.Helper()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	t.Cleanup(func() { l.Close() }) //nolint: errcheck

	return uint(l.Addr().(*net.TCPAddr).Port) //nolint: forcetypeassert
}

func parseConfig(t *testing.T, raw string) *config.Config {
	t.Helper()

	conf, err := config.Parse([]byte(raw))
	require.NoError(t, err)

	return conf
}

func closeServed(t *testing.T, served []servedListener) {
	t.Helper()

	t.Cleanup(func() {
		for _, sl := range served {
			sl.raw.Close() //nolint: errcheck
		}
	})
}

// assertServing proves a socket is really listening.
func assertServing(t *testing.T, listener net.Listener) {
	t.Helper()

	conn, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	require.NoError(t, err)

	conn.Close() //nolint: errcheck
}

// TestExtraListenerBindFailureIsNotFatal pins the rule that keeps a taken
// loopback port from taking the public port down with it: the [[listener]] is
// logged and skipped, bind-to still binds and still serves.
func TestExtraListenerBindFailureIsNotFatal(t *testing.T) {
	t.Parallel()

	ports, held := holdPorts(t, 1)
	busy := takenPort(t)
	conf := parseConfig(t, fmt.Sprintf(`
secret = "%s"
bind-to = "127.0.0.1:%d"

[[listener]]
bind-to = "127.0.0.1:%d"
accept = ["dd", "plain"]
`, mtglib.GenerateSecret("cover.example.com").Hex(), held[0], busy))

	log := newRecordingLogger()

	// The taken port is not held, so it reaches the real binder and fails for
	// real -- which is the behaviour under test.
	served, err := buildListenersWith(conf, log, ports.listen)
	require.NoError(t, err)
	closeServed(t, served)
	require.Empty(t, ports.remaining())

	require.Len(t, served, 1, "the extra listener must be skipped, not served")
	assert.Equal(t, mtglib.DefaultListenerPolicy, served[0].policy)
	assertServing(t, served[0].raw)

	warnings := strings.Join(log.recorded(), "\n")
	assert.Contains(t, warnings, fmt.Sprintf("cannot start extra listener on 127.0.0.1:%d", busy))
}

// TestGlobalProxyProtocolDoesNotWrapExtraListener pins the split of the global
// proxy-protocol-listener flag: it applies to bind-to only, because a
// [[listener]] carries its own key and its carrier (tproxy-server) sends no
// PROXY header.
func TestGlobalProxyProtocolDoesNotWrapExtraListener(t *testing.T) {
	t.Parallel()

	ports, held := holdPorts(t, 2)
	conf := parseConfig(t, fmt.Sprintf(`
secret = "%s"
bind-to = "127.0.0.1:%d"
proxy-protocol-listener = true

[[listener]]
bind-to = "127.0.0.1:%d"
accept = ["dd"]
`, mtglib.GenerateSecret("cover.example.com").Hex(), held[0], held[1]))

	served, err := buildListenersWith(conf, newRecordingLogger(), ports.listen)
	require.NoError(t, err)
	closeServed(t, served)
	require.Empty(t, ports.remaining())

	require.Len(t, served, 2)

	assert.IsType(t, &proxyprotocol.ListenerAdapter{}, served[0].serve)
	assert.Equal(t, served[1].raw, served[1].serve,
		"the global proxy-protocol-listener must not wrap a [[listener]]")
	assert.False(t, served[1].policy.ProxyProtocol)
	assert.Equal(t, []string{"dd"}, served[1].policy.Modes.Strings())
}

// TestExtraListenerProxyProtocolIsPerListener is the other half of the split: a
// [[listener]] that asks for a PROXY header gets one even though the global flag
// is off.
func TestExtraListenerProxyProtocolIsPerListener(t *testing.T) {
	t.Parallel()

	ports, held := holdPorts(t, 2)
	conf := parseConfig(t, fmt.Sprintf(`
secret = "%s"
bind-to = "127.0.0.1:%d"

[[listener]]
bind-to = "127.0.0.1:%d"
accept = ["plain"]
proxy-protocol = true
`, mtglib.GenerateSecret("cover.example.com").Hex(), held[0], held[1]))

	served, err := buildListenersWith(conf, newRecordingLogger(), ports.listen)
	require.NoError(t, err)
	closeServed(t, served)
	require.Empty(t, ports.remaining())

	require.Len(t, served, 2)

	assert.Equal(t, served[0].raw, served[0].serve, "bind-to must be unwrapped without the global flag")
	assert.IsType(t, &proxyprotocol.ListenerAdapter{}, served[1].serve)
	assertServing(t, served[1].raw)
}

// TestListenerReportAbsentWithoutExtraListeners keeps the /stats capability
// report shaped exactly as today for every deployment that has no [[listener]].
func TestListenerReportAbsentWithoutExtraListeners(t *testing.T) {
	t.Parallel()

	conf := parseConfig(t, fmt.Sprintf(`
secret = "%s"
bind-to = "0.0.0.0:443"
`, mtglib.GenerateSecret("cover.example.com").Hex()))

	assert.Nil(t, listenerReport(conf))
	assert.True(t, conf.GetListenerModes().Empty())
}

// TestListenerReportNamesEveryListener is what /stats and the unserved-secret
// warning read: bind-to is reported as the public FakeTLS door, each
// [[listener]] as what it actually accepts.
func TestListenerReportNamesEveryListener(t *testing.T) {
	t.Parallel()

	conf := parseConfig(t, fmt.Sprintf(`
secret = "%s"
bind-to = "0.0.0.0:443"

[[listener]]
bind-to = "127.0.0.1:2398"
accept = ["dd", "plain"]
`, mtglib.GenerateSecret("cover.example.com").Hex()))

	assert.Equal(t, []mtglib.ListenerJSON{
		{Bind: "0.0.0.0:443", Accept: []string{"ee"}, Public: true},
		{Bind: "127.0.0.1:2398", Accept: []string{"dd", "plain"}, Public: false},
	}, listenerReport(conf))

	assert.Equal(t, []string{"dd", "plain"}, conf.GetListenerModes().Strings())
}
