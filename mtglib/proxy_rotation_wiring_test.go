package mtglib

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The rotation clock's wiring: the proxy resolves one clock before it builds its
// first set, every build of a set reads it, and the registration re-check judges
// a retiring key by it. And what the engine says when it drops an entry.

const (
	retiringIgnoredMessage = "a retiring key was ignored"
	clockBehindMessage     = "the wall clock is behind the latest time seen; rotation overlaps are judged by the latest time"
)

// rotationLogLine is one line a rotationLogger was told to write.
type rotationLogLine struct {
	level  string
	msg    string
	err    string
	fields map[string]string
}

// rotationLog keeps every line, at every level, with the fields bound to it.
type rotationLog struct {
	mu    sync.Mutex
	lines []rotationLogLine
}

func (r *rotationLog) add(level, msg string, err error, fields map[string]string) {
	line := rotationLogLine{level: level, msg: msg, fields: fields}
	if err != nil {
		line.err = err.Error()
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	r.lines = append(r.lines, line)
}

// named is the lines whose message is msg, in the order they were written.
func (r *rotationLog) named(msg string) []rotationLogLine {
	r.mu.Lock()
	defer r.mu.Unlock()

	var out []rotationLogLine

	for _, line := range r.lines {
		if line.msg == msg {
			out = append(out, line)
		}
	}

	return out
}

// text is everything the log holds, as one string: levels, messages, errors,
// and every field's name and value.
func (r *rotationLog) text() string {
	r.mu.Lock()
	defer r.mu.Unlock()

	var out strings.Builder

	for _, line := range r.lines {
		fmt.Fprintf(&out, "%s %s %s\n", line.level, line.msg, line.err)

		for name, value := range line.fields {
			fmt.Fprintf(&out, " %s=%s\n", name, value)
		}
	}

	return out.String()
}

// rotationLogger is a Logger that records into a rotationLog. Unlike
// denyProbeLogger it keeps the level, and it keeps Debug and Printf too: a leak
// is a leak at any level.
type rotationLogger struct {
	log    *rotationLog
	fields map[string]string
}

func (l rotationLogger) bind(name, value string) Logger {
	fields := make(map[string]string, len(l.fields)+1)
	maps.Copy(fields, l.fields)
	fields[name] = value

	return rotationLogger{log: l.log, fields: fields}
}

func (l rotationLogger) say(level, msg string, err error) { l.log.add(level, msg, err, l.fields) }

func (l rotationLogger) Named(string) Logger            { return l }
func (l rotationLogger) BindInt(n string, v int) Logger { return l.bind(n, strconv.Itoa(v)) }
func (l rotationLogger) BindStr(n, v string) Logger     { return l.bind(n, v) }
func (l rotationLogger) BindJSON(n, v string) Logger    { return l.bind(n, v) }
func (l rotationLogger) Printf(format string, args ...any) {
	l.say("printf", fmt.Sprintf(format, args...), nil)
}
func (l rotationLogger) Info(msg string)                  { l.say("info", msg, nil) }
func (l rotationLogger) InfoError(msg string, err error)  { l.say("info", msg, err) }
func (l rotationLogger) Warning(msg string)               { l.say("warning", msg, nil) }
func (l rotationLogger) WarningError(msg string, e error) { l.say("warning", msg, e) }
func (l rotationLogger) Debug(msg string)                 { l.say("debug", msg, nil) }
func (l rotationLogger) DebugError(msg string, e error)   { l.say("debug", msg, e) }

// ignoredLines is the engine's drop lines as "level|secret_name|reason", in
// order, and fails the test when a line carries a field other than those two.
func ignoredLines(t *testing.T, r *rotationLog) []string {
	t.Helper()

	var out []string

	for _, line := range r.named(retiringIgnoredMessage) {
		assert.Equal(t, []string{"reason", "secret_name"}, slices.Sorted(maps.Keys(line.fields)),
			"the drop line names the secret and the reason, and nothing else")

		out = append(out, line.level+"|"+line.fields["secret_name"]+"|"+line.fields["reason"])
	}

	return out
}

// leaks names the spellings of the given secrets that text carries: the value
// in hex, in base64url and in base64, and the 16-byte key in hex, in base64 and
// in base64url. It names them by their label and the secret's position, and
// never prints one. The base64 forms are unpadded, which any padded form
// contains. A hex spelling is looked for in either case.
func leaks(text string, secrets []Secret) []string {
	lower := strings.ToLower(text)

	var found []string

	for i, s := range secrets {
		raw, key := s.makeBytes(), s.Key[:]

		for _, spelling := range []struct {
			label, text string
			hex         bool
		}{
			{"value in hex", s.Hex(), true},
			{"value in base64url", s.Base64(), false},
			{"value in base64", base64.RawStdEncoding.EncodeToString(raw), false},
			{"key in hex", hex.EncodeToString(key), true},
			{"key in base64", base64.RawStdEncoding.EncodeToString(key), false},
			{"key in base64url", base64.RawURLEncoding.EncodeToString(key), false},
		} {
			haystack, needle := text, spelling.text
			if spelling.hex {
				haystack, needle = lower, strings.ToLower(needle)
			}

			if strings.Contains(haystack, needle) {
				found = append(found, fmt.Sprintf("secret %d: %s", i, spelling.label))
			}
		}
	}

	return found
}

// newRotationProxy builds a proxy through NewProxy on a recording logger and the
// given clock, with alice as its one primary, and stops it with the test.
func newRotationProxy(t *testing.T, mutate func(*ProxyOpts)) (*Proxy, *rotationLog) {
	t.Helper()

	opts, _ := servingOpts(t)
	record := &rotationLog{}
	opts.Logger = rotationLogger{log: record}

	mutate(&opts)

	proxy, err := NewProxy(opts)
	require.NoError(t, err)
	t.Cleanup(proxy.Shutdown)

	return proxy, record
}

// TestNewProxyJudgesTheInitialSetByItsClock: the first set is built at the
// clock the options carry, not at the wall clock. The three cases are chosen so
// that a build at time.Now() fails each of them: an until in the real future
// with a clock past it, and an until in the real past with a clock before it.
func TestNewProxyJudgesTheInitialSetByItsClock(t *testing.T) {
	t.Parallel()

	old := GenerateSecret("old.example.com")

	build := func(t *testing.T, at, until time.Time) (*Proxy, *rotationLog) {
		t.Helper()

		return newRotationProxy(t, func(opts *ProxyOpts) {
			opts.RotationClock = NewRotationClock(newSteppedClock(at).now, nil)
			opts.RetiringSecrets = []RetiringSecret{retire("alice", old, until)}
		})
	}

	t.Run("a clock past the until drops the entry as expired", func(t *testing.T) {
		t.Parallel()

		// In the real future, so that the wall clock alone would keep it.
		until := time.Now().Add(time.Hour).Round(0)

		proxy, record := build(t, until.Add(time.Hour), until)

		assert.Empty(t, proxy.secrets.Load().retiring, "the clock's now is after until: the entry is not in the set")
		assert.Equal(t, []string{"info|alice|expired"}, ignoredLines(t, record), "and an Info expired drop is logged for it")
	})

	t.Run("a clock before the until keeps the entry", func(t *testing.T) {
		t.Parallel()

		until := time.Now().Add(time.Hour).Round(0)

		proxy, record := build(t, until.Add(-30*time.Minute), until)

		set := proxy.secrets.Load()
		require.Len(t, set.retiring, 1)
		assert.Equal(t, "alice", set.names[set.retiring[0].nameIdx])
		assert.Equal(t, old.Key, set.retiring[0].secret.Key)
		assert.True(t, set.retiring[0].until.Equal(until))
		assert.Empty(t, ignoredLines(t, record), "nothing was dropped")
	})

	t.Run("a clock before a until the wall clock has passed keeps the entry", func(t *testing.T) {
		t.Parallel()

		// In the real past, so that the wall clock alone would drop it.
		until := time.Now().Add(-time.Hour).Round(0)

		proxy, record := build(t, until.Add(-time.Hour), until)

		assert.Len(t, proxy.secrets.Load().retiring, 1, "the proxy's clock is the one that counts")
		assert.Empty(t, ignoredLines(t, record))
	})
}

// TestNewProxyBuildsAClockWhenNoneIsGiven: with no RotationClock in the options
// the proxy builds one on the wall clock that logs a behind episode through the
// proxy's own logger. A clock that is given is the one it keeps.
func TestNewProxyBuildsAClockWhenNoneIsGiven(t *testing.T) {
	t.Parallel()

	t.Run("none given", func(t *testing.T) {
		t.Parallel()

		until := time.Now().Add(time.Hour).Round(0)

		proxy, record := newRotationProxy(t, func(opts *ProxyOpts) {
			opts.RetiringSecrets = []RetiringSecret{retire("alice", GenerateSecret("old.example.com"), until)}
		})

		require.NotNil(t, proxy.rotation, "NewProxy builds the clock")
		assert.Len(t, proxy.secrets.Load().retiring, 1, "and the initial set is judged by it, on the wall clock")

		// Push the mark an hour ahead: the wall clock is now an hour behind it.
		ahead := time.Now().Add(time.Hour)
		proxy.rotation.mark.Store(ahead.UnixNano())

		got := proxy.rotation.Now()
		assert.True(t, got.Equal(ahead), "the built clock holds its mark")

		lines := record.named(clockBehindMessage)
		require.Len(t, lines, 1, "and reports the episode once, through the proxy's logger")
		assert.Equal(t, "warning", lines[0].level)
		assert.Equal(t, []string{"behind_by"}, slices.Sorted(maps.Keys(lines[0].fields)))

		gap, err := time.ParseDuration(lines[0].fields["behind_by"])
		require.NoError(t, err)
		assert.InDelta(t, float64(time.Hour), float64(gap), float64(5*time.Minute), "with the gap")

		proxy.rotation.Now()
		assert.Len(t, record.named(clockBehindMessage), 1, "a second read of the same episode is silent")

		proxy.rotation.onBehind(3 * time.Second)

		lines = record.named(clockBehindMessage)
		require.Len(t, lines, 2)
		assert.Equal(t, "3s", lines[1].fields["behind_by"], "the gap is written as a duration")
	})

	t.Run("one given", func(t *testing.T) {
		t.Parallel()

		clock := NewRotationClock(time.Now, nil)

		proxy, _ := newRotationProxy(t, func(opts *ProxyOpts) { opts.RotationClock = clock })

		assert.Same(t, clock, proxy.rotation, "the very instance, so the reloader and the proxy share it")
	})
}

// rotationSwapConfig is alice with one retiring key until the given time.
func rotationSwapConfig(alice, old Secret, until time.Time) SecretConfig {
	return SecretConfig{
		Secrets:  map[string]Secret{"alice": alice},
		Retiring: []RetiringSecret{retire("alice", old, until)},
	}
}

// TestASwapReadsTheClockOnce: a swap reads the clock once, whichever way it
// comes in, so that the build, and everything after it that judges expiry, sees
// one instant.
func TestASwapReadsTheClockOnce(t *testing.T) {
	t.Parallel()

	alice := GenerateSecret("alice.example.com")
	old := GenerateSecret("old.example.com")

	// Far ahead of the wall clock, so that an entry the clock keeps is kept by
	// the wall clock too: this test counts reads and says nothing about which
	// instant they judge by, and a hand-built proxy has no logger to write a
	// drop to.
	clockAt := time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC)
	cfg := rotationSwapConfig(alice, old, clockAt.Add(time.Hour))

	for _, route := range []struct {
		name string
		swap func(*Proxy) error
	}{
		{"ReplaceSecrets", func(p *Proxy) error { return p.ReplaceSecrets(cfg) }},
		{"ReloadSecrets", func(p *Proxy) error {
			p.reloader = func() (SecretConfig, error) { return cfg, nil }

			return p.ReloadSecrets()
		}},
		{"an API mutator", func(p *Proxy) error { return p.SetGlobalAdTag(&[AdTagLength]byte{1}) }},
	} {
		t.Run(route.name, func(t *testing.T) {
			t.Parallel()

			var reads atomic.Int64

			p := newReloadTestProxy(map[string]Secret{"alice": alice})
			// The setup swap adds an entry, and a swap logs each entry new to
			// its set: a proxy that swaps one in needs a logger to say so.
			p.logger = testLogger()
			p.rotation = NewRotationClock(func() time.Time {
				reads.Add(1)

				return clockAt
			}, nil)

			// The mutator starts from the set in force, so it needs one with an
			// entry in it to carry.
			require.NoError(t, p.ReplaceSecrets(cfg))
			require.Len(t, p.secrets.Load().retiring, 1)

			before := reads.Load()

			require.NoError(t, route.swap(p))

			assert.Equal(t, before+1, reads.Load(), "one read for the whole swap")
			assert.Len(t, p.secrets.Load().retiring, 1, "and the entry is still judged unexpired by it")
		})
	}
}

// TestASwapJudgesRetiringEntriesByTheProxysClock: the swap builds at the clock
// the proxy holds. The two directions are chosen so that a build at time.Now()
// gets each wrong.
func TestASwapJudgesRetiringEntriesByTheProxysClock(t *testing.T) {
	t.Parallel()

	alice := GenerateSecret("alice.example.com")
	old := GenerateSecret("old.example.com")

	for _, route := range []struct {
		name string
		swap func(*Proxy, SecretConfig) error
	}{
		{"ReplaceSecrets", func(p *Proxy, cfg SecretConfig) error { return p.ReplaceSecrets(cfg) }},
		{"ReloadSecrets", func(p *Proxy, cfg SecretConfig) error {
			p.reloader = func() (SecretConfig, error) { return cfg, nil }

			return p.ReloadSecrets()
		}},
	} {
		t.Run(route.name, func(t *testing.T) {
			t.Parallel()

			t.Run("a clock the wall clock has passed keeps an entry", func(t *testing.T) {
				t.Parallel()

				record := &rotationLog{}

				p := newReloadTestProxy(map[string]Secret{"alice": alice})
				p.logger = rotationLogger{log: record}
				p.rotation = NewRotationClock(newSteppedClock(time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)).now, nil)

				require.NoError(t, route.swap(p, rotationSwapConfig(alice, old, time.Date(2000, 1, 1, 1, 0, 0, 0, time.UTC))))

				assert.Len(t, p.secrets.Load().retiring, 1, "unexpired by the proxy's clock, though the wall clock is far past it")
				assert.Empty(t, ignoredLines(t, record))
			})

			t.Run("a clock ahead of the wall clock drops an entry", func(t *testing.T) {
				t.Parallel()

				until := time.Now().Add(time.Hour).Round(0)
				record := &rotationLog{}

				p := newReloadTestProxy(map[string]Secret{"alice": alice})
				p.logger = rotationLogger{log: record}
				p.rotation = NewRotationClock(newSteppedClock(until.Add(time.Hour)).now, nil)

				require.NoError(t, route.swap(p, rotationSwapConfig(alice, old, until)))

				assert.Empty(t, p.secrets.Load().retiring, "expired by the proxy's clock, though the wall clock is before it")
				assert.Equal(t, []string{"info|alice|expired"}, ignoredLines(t, record))
			})
		})
	}
}

// TestTheRegistrationRecheckJudgesARetiringKeyByTheProxysClock: a stream
// attributed before a swap registers under the set in force, and a key that set
// holds only as a retiring one is accepted until the proxy's clock says
// otherwise. Nothing but the clock moves between the swap and the registration
// in the second case: no sweep has run.
func TestTheRegistrationRecheckJudgesARetiringKeyByTheProxysClock(t *testing.T) {
	t.Parallel()

	register := func(t *testing.T, until, swapAt, registerAt time.Time) DenyReason {
		t.Helper()

		probe := newClientTableProbe(t, false)
		p := probe.proxy

		source := newSteppedClock(swapAt)
		p.rotation = NewRotationClock(source.now, nil)

		set := p.secrets.Load()
		alice := slices.Index(set.names, "alice")
		oldSecret := set.secrets[alice]

		sc := probe.stream(t, tcpFrom("203.0.113.9", 50002), 0)
		require.Equal(t, DenyNone, p.attribute(sc, set, alice))

		cfg := set.toConfig()
		cfg.Secrets["alice"] = GenerateSecret("alice.example.com")
		cfg.Retiring = []RetiringSecret{retire("alice", oldSecret, until)}

		require.NoError(t, p.ReplaceSecrets(cfg))
		require.Len(t, p.secrets.Load().retiring, 1, "the swap kept the stream's key as a retiring one")

		source.set(registerAt)

		return p.tryRegisterConn(sc)
	}

	t.Run("an overlap the clock has not ended admits the stream", func(t *testing.T) {
		t.Parallel()

		// A clock in the year 2000, and an until an hour on: the wall clock has
		// long passed it.
		start := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)

		assert.Equal(t, DenyNone, register(t, start.Add(time.Hour), start, start))
	})

	t.Run("an overlap the clock ended since the swap refuses it", func(t *testing.T) {
		t.Parallel()

		// An until in the real future, so the wall clock alone has not ended it.
		until := time.Now().Add(time.Hour).Round(0)

		assert.Equal(t, DenyKeyRevoked, register(t, until, until.Add(-30*time.Minute), until.Add(30*time.Minute)))
	})
}

// TestEngineDropsAreLoggedByReasonWithoutKeys: each of the seven reasons an
// entry is not kept for is one line, in the order the entries were handed in,
// at the level the log table gives it, naming the secret and the reason and
// nothing else. No line carries a key in any spelling. The start-up build and
// a swap write the same lines, and the check covers every line the proxy wrote
// at every level, not only these.
func TestEngineDropsAreLoggedByReasonWithoutKeys(t *testing.T) {
	t.Parallel()

	k := keyFilledFrom
	ee := func(first byte) Secret { return eeSecretOf(k(first), candidatesCover) }
	dd := func(first byte) Secret { return ddSecretOf(k(first)) }
	hours := func(n int) time.Time { return rotationAt(time.Duration(n) * time.Hour) }

	alice, bob := eeSecretOf(k(10), "alice.example.com"), dd(40)
	primaries := map[string]Secret{"alice": alice, "bob": bob}

	// One drop of each reason. The valid entries after alice's first are
	// five: past the four a name keeps, the earliest goes.
	handed := []RetiringSecret{
		retire("alice", eeSecretOf(k(100), ""), hours(1)),
		retire("alice", ee(101), hours(-1)),
		retire("ghost", ee(102), hours(1)),
		retire("alice", dd(40), hours(1)),
		retire("alice", dd(10), hours(1)),
		retire("bob", dd(103), hours(1)),
		retire("bob", dd(103), hours(2)),
		retire("alice", ee(104), hours(2)),
		retire("alice", ee(105), hours(3)),
		retire("alice", ee(106), hours(4)),
		retire("alice", ee(107), hours(5)),
		retire("alice", ee(108), hours(6)),
	}

	want := []string{
		"warning|alice|invalid",
		"info|alice|expired",
		"warning|ghost|dangling",
		"warning|alice|key_of_other_secret",
		"info|alice|same_as_primary",
		"info|bob|duplicate",
		"warning|alice|over_cap",
	}

	proxy, record := newRotationProxy(t, func(opts *ProxyOpts) {
		opts.Secrets = primaries
		opts.RetiringSecrets = handed
		opts.RotationClock = NewRotationClock(newSteppedClock(rotationNow).now, nil)
	})

	assert.Equal(t, want, ignoredLines(t, record), "the start-up build, in input order")
	assert.Len(t, proxy.secrets.Load().retiring, 5, "the entries that survive")

	startup := len(record.named(retiringIgnoredMessage))

	proxy.reloadMu.Lock()
	err := proxy.swapSecretConfigLocked(SecretConfig{Secrets: primaries, Retiring: handed})
	proxy.reloadMu.Unlock()
	require.NoError(t, err)

	swapped := ignoredLines(t, record)
	require.Len(t, swapped, startup+len(want))
	assert.Equal(t, want, swapped[startup:], "a swap writes the same lines")

	all := []Secret{alice, bob}
	for _, entry := range handed {
		all = append(all, entry.Secret)
	}

	assert.Empty(t, leaks(record.text(), all), "no line, at any level, carries a key in any spelling")
}
