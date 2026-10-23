package cli

import (
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/Arman2122/mtg-proxy/internal/config"
	"github.com/Arman2122/mtg-proxy/logger"
	"github.com/Arman2122/mtg-proxy/mtglib"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// perAddressConfig is a config with three secrets whose [secret-limits] tables
// are the given text. top goes before the first table, listeners after the last.
func perAddressConfig(t *testing.T, top, limits, listeners string) *config.Config {
	t.Helper()

	hex := mtglib.GenerateSecret("cover.example.com").Hex()

	return parseConfig(t, top+"\n\n"+
		"[secrets]\n"+
		fmt.Sprintf("alice = %q\nbob = %q\ncarol = %q\n\n", hex, hex, hex)+
		limits+"\n\n"+
		listeners+"\n")
}

// TestPerAddressControlsIn pins which [secret-limits] keys count as per-address:
// client-conns, client-speed and client-fair, and only when they are in force.
// ip-limit is the older control the spec leaves out, and a zero or false value
// is the key written but off.
func TestPerAddressControlsIn(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		limits string
		want   []string
	}{
		"no limits at all": {limits: "", want: nil},
		"limits that are not per-address": {
			limits: "[secret-limits.alice]\nquota = \"1GB\"\nspeed = \"8mbit\"\nip-limit = 2\n",
			want:   nil,
		},
		"client-conns alone": {
			limits: "[secret-limits.alice]\nclient-conns = 6\n",
			want:   []string{"client-conns"},
		},
		"client-speed alone": {
			limits: "[secret-limits.alice]\nclient-speed = \"1mbit\"\n",
			want:   []string{"client-speed"},
		},
		"client-fair alone": {
			limits: "[secret-limits.alice]\nclient-fair = true\nspeed-down = \"8mbit\"\n",
			want:   []string{"client-fair"},
		},
		"all three on one secret": {
			limits: "[secret-limits.alice]\n" +
				"client-speed = \"1mbit\"\nclient-fair = true\nclient-conns = 4\nspeed = \"8mbit\"\n",
			want: []string{"client-conns", "client-fair", "client-speed"},
		},
		"client-conns zero is off": {
			limits: "[secret-limits.alice]\nclient-conns = 0\nquota = \"1GB\"\n",
			want:   nil,
		},
		"client-fair false is off": {
			limits: "[secret-limits.alice]\nclient-fair = false\nspeed = \"8mbit\"\n",
			want:   nil,
		},
		"client-speed empty is off": {
			limits: "[secret-limits.alice]\nclient-speed = \"\"\nquota = \"1GB\"\n",
			want:   nil,
		},
		"an off key beside an on key": {
			limits: "[secret-limits.alice]\nclient-conns = 0\nclient-speed = \"1mbit\"\n",
			want:   []string{"client-speed"},
		},
		"different keys on different secrets are a union, sorted": {
			limits: "[secret-limits.alice]\nclient-speed = \"1mbit\"\n\n" +
				"[secret-limits.bob]\nclient-conns = 2\n\n" +
				"[secret-limits.carol]\nclient-fair = true\nspeed = \"8mbit\"\n",
			want: []string{"client-conns", "client-fair", "client-speed"},
		},
		"the same key on several secrets is named once": {
			limits: "[secret-limits.alice]\nclient-conns = 2\n\n" +
				"[secret-limits.bob]\nclient-conns = 5\n\n" +
				"[secret-limits.carol]\nclient-conns = 1\nclient-speed = \"1mbit\"\n",
			want: []string{"client-conns", "client-speed"},
		},
		"a per-address secret among plain ones": {
			limits: "[secret-limits.alice]\nquota = \"1GB\"\n\n" +
				"[secret-limits.bob]\nip-limit = 3\n\n" +
				"[secret-limits.carol]\nclient-conns = 2\n",
			want: []string{"client-conns"},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			conf := perAddressConfig(t, `bind-to = "127.0.0.1:443"`, tc.limits, "")

			assert.Equal(t, tc.want, perAddressControlsIn(conf))
		})
	}
}

// proxyProtocolConfig is a config with the given bind-to port and, optionally,
// the global PROXY-protocol flag and one extra listener on its own port.
type proxyProtocolConfig struct {
	global      bool
	extra       bool
	extraProxy  bool
	extraBroken bool // the extra listener's port is taken, so it is never served
}

// TestProxyProtocolListeners is the listener half of the decision: of the
// sockets that are really served, which expect a PROXY header. The global flag
// reaches bind-to only; an extra listener has its own key; and an extra
// listener that failed to bind is not served and so is not named.
func TestProxyProtocolListeners(t *testing.T) {
	t.Parallel()

	tests := map[string]proxyProtocolConfig{
		"neither":                                       {},
		"bind-to with the global flag":                  {global: true},
		"an extra listener with its key":                {extra: true, extraProxy: true},
		"an extra listener without its key":             {extra: true},
		"the global flag beside a plain extra listener": {global: true, extra: true},
		"both":                                {global: true, extra: true, extraProxy: true},
		"an extra listener that did not bind": {extra: true, extraProxy: true, extraBroken: true},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			ports, held := holdPorts(t, 2)
			mainAddr := fmt.Sprintf("127.0.0.1:%d", held[0])
			extraAddr := fmt.Sprintf("127.0.0.1:%d", held[1])

			if tc.extraBroken {
				// A port that is not held reaches the real binder, which
				// fails because takenPort keeps it busy.
				busy := takenPort(t)
				extraAddr = fmt.Sprintf("127.0.0.1:%d", busy)
			}

			top := fmt.Sprintf("bind-to = %q\n", mainAddr)
			if tc.global {
				top += "proxy-protocol-listener = true\n"
			}

			listeners := ""
			if tc.extra {
				listeners = fmt.Sprintf("[[listener]]\nbind-to = %q\naccept = [\"dd\"]\n", extraAddr)
				if tc.extraProxy {
					listeners += "proxy-protocol = true\n"
				}
			}

			served, err := buildListenersWith(perAddressConfig(t, top, "", listeners), newRecordingLogger(), ports.listen)
			require.NoError(t, err)
			closeServed(t, served)

			var want []string

			if tc.global {
				want = append(want, mainAddr)
			}

			if tc.extra && tc.extraProxy && !tc.extraBroken {
				want = append(want, extraAddr)
			}

			assert.Equal(t, want, proxyProtocolListeners(served))
		})
	}
}

// fieldLog is one warning with the fields bound to the logger that wrote it.
type fieldLog struct {
	msg    string
	fields map[string]string
}

// fieldSink collects what a tree of fieldLoggers writes.
type fieldSink struct {
	mu       sync.Mutex
	warnings []fieldLog
}

func (s *fieldSink) recorded() []fieldLog {
	s.mu.Lock()
	defer s.mu.Unlock()

	return append([]fieldLog(nil), s.warnings...)
}

// text is everything a log line carries, for asserting what it does not.
func (l fieldLog) text() string {
	var out strings.Builder

	out.WriteString(l.msg)

	for key, value := range l.fields {
		out.WriteString(" " + key + "=" + value)
	}

	return out.String()
}

// fieldLogger records Warning calls together with their Bind* fields, which the
// shared recordingLogger drops: the listener and the keys are fields, not text.
type fieldLogger struct {
	mtglib.Logger

	sink   *fieldSink
	fields map[string]string
}

func newFieldLogger() (*fieldLogger, *fieldSink) {
	sink := &fieldSink{}

	return &fieldLogger{Logger: logger.NewNoopLogger(), sink: sink, fields: map[string]string{}}, sink
}

func (f *fieldLogger) with(name, value string) *fieldLogger {
	fields := make(map[string]string, len(f.fields)+1)
	for k, v := range f.fields {
		fields[k] = v
	}

	fields[name] = value

	return &fieldLogger{Logger: f.Logger, sink: f.sink, fields: fields}
}

func (f *fieldLogger) Named(_ string) mtglib.Logger          { return f }
func (f *fieldLogger) BindInt(n string, v int) mtglib.Logger { return f.with(n, fmt.Sprint(v)) }
func (f *fieldLogger) BindStr(n, v string) mtglib.Logger     { return f.with(n, v) }
func (f *fieldLogger) BindJSON(n, v string) mtglib.Logger    { return f.with(n, v) }

func (f *fieldLogger) Warning(msg string) {
	f.sink.mu.Lock()
	defer f.sink.mu.Unlock()

	f.sink.warnings = append(f.sink.warnings, fieldLog{msg: msg, fields: f.fields})
}

// TestWarnPerAddressControls is the emit: one line per PROXY-protocol listener
// that is served, only when a per-address control is in use, naming the keys
// and the listener, and never a secret's name or a limit's value.
func TestWarnPerAddressControls(t *testing.T) {
	t.Parallel()

	const (
		secretName = "vip-customers"
		keys       = "client-conns, client-fair, client-speed"
	)

	limits := fmt.Sprintf("[secret-limits.%s]\nclient-conns = 7\nclient-speed = \"3141kbit\"\n"+
		"client-fair = true\nspeed = \"8mbit\"\nip-limit = 3\n", secretName)
	plain := fmt.Sprintf("[secret-limits.%s]\nquota = \"1GB\"\nip-limit = 3\n", secretName)

	tests := map[string]struct {
		limits       string
		global       bool
		extraProxy   bool
		wantListener []string
	}{
		"controls on a PROXY-protocol bind-to": {limits: limits, global: true, wantListener: []string{"main"}},
		"controls on a PROXY-protocol extra listener": {
			limits: limits, extraProxy: true, wantListener: []string{"extra"},
		},
		"controls with two PROXY-protocol listeners": {
			limits: limits, global: true, extraProxy: true, wantListener: []string{"main", "extra"},
		},
		"controls and no PROXY-protocol listener":   {limits: limits},
		"a PROXY-protocol listener and no controls": {global: true, extraProxy: true},
		"limits that are not per-address on PROXY":  {limits: plain, global: true, extraProxy: true},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			ports, held := holdPorts(t, 2)
			addrs := map[string]string{
				"main":  fmt.Sprintf("127.0.0.1:%d", held[0]),
				"extra": fmt.Sprintf("127.0.0.1:%d", held[1]),
			}

			top := fmt.Sprintf("bind-to = %q\n", addrs["main"])
			if tc.global {
				top += "proxy-protocol-listener = true\n"
			}

			listeners := fmt.Sprintf("[[listener]]\nbind-to = %q\naccept = [\"dd\"]\n", addrs["extra"])
			if tc.extraProxy {
				listeners += "proxy-protocol = true\n"
			}

			hex := mtglib.GenerateSecret("cover.example.com").Hex()
			conf := parseConfig(t, top+"\n[secrets]\n"+fmt.Sprintf("%s = %q\n\n", secretName, hex)+
				tc.limits+"\n\n"+listeners)

			served, err := buildListenersWith(conf, newRecordingLogger(), ports.listen)
			require.NoError(t, err)
			closeServed(t, served)
			require.Len(t, served, 2)

			log, sink := newFieldLogger()
			warnPerAddressControls(log, conf, served)

			got := sink.recorded()
			require.Len(t, got, len(tc.wantListener), "one line per PROXY-protocol listener")

			for i, which := range tc.wantListener {
				line := got[i]

				assert.Equal(t, addrs[which], line.fields["listener"])
				assert.Equal(t, keys, line.fields["keys"])
				assert.Contains(t, line.msg, "the one the PROXY header claims")
				assert.Contains(t, line.msg, "anyone who can reach this listener can forge it")

				// The keys are named; neither whose secret they are on nor
				// what they are set to is, and the line carries no field
				// beyond the listener and the keys.
				assert.Len(t, line.fields, 2)

				text := line.text()
				assert.NotContains(t, text, secretName)
				assert.NotContains(t, text, "3141kbit")
				assert.NotContains(t, text, "ip-limit")
			}
		})
	}
}
