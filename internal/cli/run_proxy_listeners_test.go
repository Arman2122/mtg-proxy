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

// freePort returns a port that was free a moment ago. bind-to rejects port 0,
// so a config needs a concrete number.
func freePort(t *testing.T) uint {
	t.Helper()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	port := uint(l.Addr().(*net.TCPAddr).Port) //nolint: forcetypeassert

	require.NoError(t, l.Close())

	return port
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

	busy := takenPort(t)
	conf := parseConfig(t, fmt.Sprintf(`
secret = "%s"
bind-to = "127.0.0.1:%d"

[[listener]]
bind-to = "127.0.0.1:%d"
accept = ["dd", "plain"]
`, mtglib.GenerateSecret("cover.example.com").Hex(), freePort(t), busy))

	log := newRecordingLogger()

	served, err := buildListeners(conf, log)
	require.NoError(t, err)
	closeServed(t, served)

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

	conf := parseConfig(t, fmt.Sprintf(`
secret = "%s"
bind-to = "127.0.0.1:%d"
proxy-protocol-listener = true

[[listener]]
bind-to = "127.0.0.1:%d"
accept = ["dd"]
`, mtglib.GenerateSecret("cover.example.com").Hex(), freePort(t), freePort(t)))

	served, err := buildListeners(conf, newRecordingLogger())
	require.NoError(t, err)
	closeServed(t, served)

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

	conf := parseConfig(t, fmt.Sprintf(`
secret = "%s"
bind-to = "127.0.0.1:%d"

[[listener]]
bind-to = "127.0.0.1:%d"
accept = ["plain"]
proxy-protocol = true
`, mtglib.GenerateSecret("cover.example.com").Hex(), freePort(t), freePort(t)))

	served, err := buildListeners(conf, newRecordingLogger())
	require.NoError(t, err)
	closeServed(t, served)

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
