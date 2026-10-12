package cli

import (
	"fmt"
	"maps"
	"os"
	"slices"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/Arman2122/mtg-proxy/antireplay"
	"github.com/Arman2122/mtg-proxy/events"
	"github.com/Arman2122/mtg-proxy/internal/utils"
	"github.com/Arman2122/mtg-proxy/ipblocklist"
	"github.com/Arman2122/mtg-proxy/logger"
	"github.com/Arman2122/mtg-proxy/mtglib"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// reloadingProxy writes initial to path and builds a proxy on it the way run
// does: its first set from the file judged on the proxy's clock, and its
// reload through run's own reloader on that same clock. It reaches no network
// and listens on nothing; a test drives it through ReloadSecrets and reads it
// back through SnapshotSecrets.
func reloadingProxy(t *testing.T, path, initial string) *mtglib.Proxy {
	t.Helper()

	require.NoError(t, os.WriteFile(path, []byte(initial), 0o600))

	conf, err := utils.ReadConfig(path)
	require.NoError(t, err)

	log := logger.NewNoopLogger()
	clock := mtglib.NewRotationClock(time.Now, nil)

	proxy, err := mtglib.NewProxy(mtglib.ProxyOpts{
		Network:         &doctorNetwork{dial: refuseAll},
		AntiReplayCache: antireplay.NewNoop(),
		IPBlocklist:     ipblocklist.NewNoop(),
		IPAllowlist:     ipblocklist.NewNoop(),
		EventStream:     events.NewNoopStream(),
		Logger:          log,
		Secrets:         conf.GetSecrets(),
		RetiringSecrets: conf.GetRetiringSecrets(clock.Now()).Usable,
		RotationClock:   clock,
		SecretsReloader: makeSecretsReloader(path, log, clock),
	})
	require.NoError(t, err)
	t.Cleanup(proxy.Shutdown)

	return proxy
}

// snapshotOf is the proxy's view of one secret, as GET /secrets shows it.
func snapshotOf(t *testing.T, proxy *mtglib.Proxy, name string) mtglib.SecretInfo {
	t.Helper()

	for _, info := range proxy.SnapshotSecrets() {
		if info.Name == name {
			return info
		}
	}

	t.Fatalf("the proxy has no secret %q", name)

	return mtglib.SecretInfo{}
}

// D4, §10. A hand edit re-keys [secrets] and, in the same save, writes a block
// with a typo in until. Refusing the reload would keep the leaked key as the
// primary and the new one dead -- the opposite of what the operator asked for.
// So the block is dropped with a Warning, and the rest of the file applies: the
// new primaries, and the other, well-formed block.
func TestAReloadWithABadBlockAppliesTheRest(t *testing.T) {
	t.Parallel()

	aliceOld := mtglib.GenerateSecret("cover.example.com")
	aliceNew := mtglib.GenerateSecret("cover.example.com")
	bobOld := mtglib.GenerateSecret("cover.example.com")
	bobNew := mtglib.GenerateSecret("cover.example.com")

	until := time.Now().Add(24 * time.Hour).Truncate(time.Second)
	bindTo := "127.0.0.1:3128"

	before := retiringFile(bindTo, map[string]mtglib.Secret{"alice": aliceOld, "bob": bobOld})
	after := retiringFile(bindTo, map[string]mtglib.Secret{"alice": aliceNew, "bob": bobNew},
		retiringBlock("alice", aliceOld, "2026-10-09 09:30"),
		retiringBlock("bob", bobOld, rfc3339(until)))

	const badBlock = `retiring-secret #1 (name "alice"): until is not an RFC 3339 date-time with an offset, ` +
		`such as 2026-10-09T09:30:00Z; the entry is ignored and its key is not accepted`

	t.Run("the reloader", func(t *testing.T) {
		t.Parallel()

		path := writeConfig(t, before)
		log, sink := newFieldLogger()
		reload := makeSecretsReloader(path, log, mtglib.NewRotationClock(time.Now, nil))

		require.NoError(t, os.WriteFile(path, []byte(after), 0o600))

		cfg, err := reload()
		require.Empty(t, retiringLeaks(errText(err), aliceOld, aliceNew, bobOld, bobNew), "the error carries a key")
		require.NoError(t, err, "a problem in a block never refuses the reload")

		assert.True(t, cfg.Secrets["alice"] == aliceNew, "alice's new primary is applied")
		assert.True(t, cfg.Secrets["bob"] == bobNew, "bob's new primary is applied")

		require.Equal(t, 1, len(cfg.Retiring), "bob's block, and nothing for alice's")
		assert.Equal(t, "bob", cfg.Retiring[0].Name)
		assert.True(t, cfg.Retiring[0].Secret == bobOld, "bob's entry holds bob's old key")
		assert.True(t, cfg.Retiring[0].Until.Equal(until))

		warnings := sink.recorded()

		for _, warning := range warnings {
			require.Empty(t, retiringLeaks(warning.text(), aliceOld, aliceNew, bobOld, bobNew), "a Warning carries a key")
		}

		require.Len(t, warnings, 1)
		assert.Equal(t, badBlock, warnings[0].msg)
		assert.Empty(t, warnings[0].fields)
	})

	t.Run("the proxy", func(t *testing.T) {
		t.Parallel()

		path := writeConfig(t, before)
		proxy := reloadingProxy(t, path, before)

		require.NoError(t, os.WriteFile(path, []byte(after), 0o600))
		require.NoError(t, proxy.ReloadSecrets(), "a problem in a block never refuses the reload")

		alice := snapshotOf(t, proxy, "alice")
		assert.True(t, alice.Secret == aliceNew.Base64(), "alice's new primary is in force")
		assert.Zero(t, alice.RetiringKeys, "alice's old key is not accepted")

		bob := snapshotOf(t, proxy, "bob")
		assert.True(t, bob.Secret == bobNew.Base64(), "bob's new primary is in force")
		assert.Equal(t, 1, bob.RetiringKeys, "bob's old key is accepted until its until")
	})
}

// errText is err's text, or nothing for no error: what a leak check reads
// before any assertion that could print it.
func errText(err error) string {
	if err == nil {
		return ""
	}

	return err.Error()
}

// levelLine is one line a levelLogger recorded.
type levelLine struct {
	level  string
	msg    string
	fields map[string]string
}

func (l levelLine) text() string {
	return fieldLog{msg: l.msg, fields: l.fields}.text()
}

// levelSink collects what a tree of levelLoggers writes at Info and Warning.
type levelSink struct {
	mu    sync.Mutex
	lines []levelLine
}

func (s *levelSink) at(level string) []levelLine {
	s.mu.Lock()
	defer s.mu.Unlock()

	var out []levelLine

	for _, line := range s.lines {
		if line.level == level {
			out = append(out, line)
		}
	}

	return out
}

func (s *levelSink) all() []levelLine {
	s.mu.Lock()
	defer s.mu.Unlock()

	return append([]levelLine(nil), s.lines...)
}

// levelLogger records Info and Warning lines with their level and fields;
// Debug is dropped.
type levelLogger struct {
	mtglib.Logger

	sink   *levelSink
	fields map[string]string
}

func newLevelLogger() (*levelLogger, *levelSink) {
	sink := &levelSink{}

	return &levelLogger{Logger: logger.NewNoopLogger(), sink: sink, fields: map[string]string{}}, sink
}

func (l *levelLogger) with(name, value string) *levelLogger {
	fields := make(map[string]string, len(l.fields)+1)
	for k, v := range l.fields {
		fields[k] = v
	}

	fields[name] = value

	return &levelLogger{Logger: l.Logger, sink: l.sink, fields: fields}
}

func (l *levelLogger) record(level, msg string) {
	l.sink.mu.Lock()
	defer l.sink.mu.Unlock()

	l.sink.lines = append(l.sink.lines, levelLine{level: level, msg: msg, fields: l.fields})
}

func (l *levelLogger) Named(_ string) mtglib.Logger          { return l }
func (l *levelLogger) BindInt(n string, v int) mtglib.Logger { return l.with(n, strconv.Itoa(v)) }
func (l *levelLogger) BindStr(n, v string) mtglib.Logger     { return l.with(n, v) }
func (l *levelLogger) BindJSON(n, v string) mtglib.Logger    { return l.with(n, v) }
func (l *levelLogger) Info(msg string)                       { l.record("info", msg) }
func (l *levelLogger) InfoError(msg string, _ error)         { l.record("info", msg) }
func (l *levelLogger) Warning(msg string)                    { l.record("warn", msg) }
func (l *levelLogger) WarningError(msg string, _ error)      { l.record("warn", msg) }

// misplacedUserLine is the line for a [secrets] user named retiring-secret.
const misplacedUserLine = `a [secrets] user named "retiring-secret" is ignored: ` +
	`[[retiring-secret]] blocks go in their own table, above or between the other tables, one per old key`

// What run logs of the table, at start and on every reload, through one
// function: each problem or warning at Warning, then the count of expired
// entries at Info, then each note at Info -- and nothing at all for a file
// without the table.
func TestTheRetiringReportIsLoggedAtItsLevels(t *testing.T) {
	t.Parallel()

	alice := mtglib.GenerateSecret("cover.example.com")
	bob := mtglib.GenerateSecret("cover.example.com")
	aliceOld := mtglib.GenerateSecret("old.example.com")
	bobOld := mtglib.GenerateSecret("old.example.com")
	misplaced := mtglib.GenerateSecret("old.example.com")
	everyValue := []mtglib.Secret{alice, bob, aliceOld, bobOld, misplaced}

	primaries := map[string]mtglib.Secret{"alice": alice, "bob": bob}
	now := time.Now()

	t.Run("a table with something of each kind", func(t *testing.T) {
		t.Parallel()

		raw := retiringFile("127.0.0.1:3128", primaries,
			retiringBlock("alice", alice, rfc3339(now.Add(24*time.Hour))),
			retiringBlock("bob", bobOld, rfc3339(now.Add(24*time.Hour))),
			retiringBlock("bob", bobOld, rfc3339(now.Add(48*time.Hour))),
			retiringBlock("alice", aliceOld, rfc3339(now.Add(-24*time.Hour))),
			retiringBlock("alice", aliceOld, "next tuesday"),
		) + fmt.Sprintf("retiring-secret = %q\n", misplaced.Hex())

		log, sink := newLevelLogger()

		cfg, err := makeSecretsReloader(writeConfig(t, raw), log, mtglib.NewRotationClock(time.Now, nil))()
		require.Empty(t, retiringLeaks(errText(err), everyValue...), "the error carries a key")
		require.NoError(t, err)

		for _, line := range sink.all() {
			require.Empty(t, retiringLeaks(line.text(), everyValue...), "a line carries a key")
		}

		assert.Equal(t, 1, len(cfg.Retiring), "bob's later entry")
		assert.Equal(t, []string{"alice", "bob"}, slices.Sorted(maps.Keys(cfg.Secrets)), "the user is not served")

		warnings := sink.at("warn")
		require.Len(t, warnings, 2)
		assert.Equal(t, misplacedUserLine, warnings[0].msg)
		assert.Equal(t, `retiring-secret #5 (name "alice"): until is not an RFC 3339 date-time with an offset, `+
			`such as 2026-10-09T09:30:00Z; the entry is ignored and its key is not accepted`, warnings[1].msg)

		for _, line := range warnings {
			assert.Empty(t, line.fields)
		}

		infos := sink.at("info")
		require.Len(t, infos, 3)
		assert.Equal(t, retiringExpiredSummary, infos[0].msg)
		assert.Equal(t, map[string]string{"expired": "1"}, infos[0].fields)
		assert.Equal(t, `retiring-secret #1 (name "alice"): the key is the secret's own primary; the entry changes nothing`,
			infos[1].msg)
		assert.Equal(t, `retiring-secret #2 (name "bob"): the same key as another entry of this name; the later until is kept`,
			infos[2].msg)
		assert.Empty(t, infos[1].fields)
		assert.Empty(t, infos[2].fields)
	})

	t.Run("a table with nothing to say", func(t *testing.T) {
		t.Parallel()

		raw := retiringFile("127.0.0.1:3128", primaries, retiringBlock("alice", aliceOld, rfc3339(now.Add(24*time.Hour))))
		log, sink := newLevelLogger()

		cfg, err := makeSecretsReloader(writeConfig(t, raw), log, mtglib.NewRotationClock(time.Now, nil))()
		require.NoError(t, err)
		assert.Equal(t, 1, len(cfg.Retiring))
		assert.Zero(t, len(sink.all()), "a usable entry and nothing else is not logged")
	})

	t.Run("no table", func(t *testing.T) {
		t.Parallel()

		log, sink := newLevelLogger()

		_, err := makeSecretsReloader(writeConfig(t, retiringFile("127.0.0.1:3128", primaries)), log,
			mtglib.NewRotationClock(time.Now, nil))()
		require.NoError(t, err)
		assert.Zero(t, len(sink.all()), "a file without the table is not logged")
	})
}

// Revision 4 of §1.1 (Task 8b's review, I1). An operator retires a leaked link
// by appending retiring-secret = "<old value>" where users are appended, below
// [secrets]. That parses -- as a user named retiring-secret whose key is the
// leaked one -- and served, it would keep the leaked key as a primary forever.
// It is never served: run --check refuses the file, doctor fails it, and a
// reload applies the rest of the edit, the re-key included, with a Warning.
func TestASecretsUserNamedRetiringSecretIsNeverServed(t *testing.T) {
	t.Parallel()

	leaked := mtglib.GenerateSecret("cover.example.com")
	renewed := mtglib.GenerateSecret("cover.example.com")
	bob := mtglib.GenerateSecret("cover.example.com")
	everyValue := []mtglib.Secret{leaked, renewed, bob}

	before := retiringFile("127.0.0.1:3128", map[string]mtglib.Secret{"alice": leaked, "bob": bob})
	misEdit := retiringFile("127.0.0.1:3128", map[string]mtglib.Secret{"alice": renewed, "bob": bob}) +
		fmt.Sprintf("retiring-secret = %q\n", leaked.Hex())

	t.Run("run --check refuses it", func(t *testing.T) {
		t.Parallel()

		err := (&Run{ConfigPath: writeConfig(t, misEdit), Check: true}).Run(nil, "test")
		require.Empty(t, retiringLeaks(errText(err), everyValue...), "the refusal carries a key")
		require.ErrorIs(t, err, errRetiringProblems)

		// The heading speaks of settings, which a [secrets] key is as much as a
		// block is; the line follows it.
		assert.Equal(t, "retiring-secret settings that run ignores or warns about:\n  "+misplacedUserLine, err.Error())
	})

	t.Run("the reloader drops it, with a Warning, and applies the rest", func(t *testing.T) {
		t.Parallel()

		log, sink := newFieldLogger()

		cfg, err := makeSecretsReloader(writeConfig(t, misEdit), log, mtglib.NewRotationClock(time.Now, nil))()
		require.Empty(t, retiringLeaks(errText(err), everyValue...), "the error carries a key")
		require.NoError(t, err, "the user never refuses the reload")

		assert.Equal(t, []string{"alice", "bob"}, slices.Sorted(maps.Keys(cfg.Secrets)), "the user is served")
		assert.True(t, cfg.Secrets["alice"] == renewed, "the re-key is applied")

		for _, secret := range cfg.Secrets {
			assert.False(t, secret.Key == leaked.Key, "the leaked key is served")
		}

		warnings := sink.recorded()

		for _, warning := range warnings {
			require.Empty(t, retiringLeaks(warning.text(), everyValue...), "a Warning carries a key")
		}

		require.Len(t, warnings, 1)
		assert.Equal(t, misplacedUserLine, warnings[0].msg)
	})

	t.Run("a reload serves the rest and not the user", func(t *testing.T) {
		t.Parallel()

		path := writeConfig(t, before)
		proxy := reloadingProxy(t, path, before)

		require.NoError(t, os.WriteFile(path, []byte(misEdit), 0o600))

		err := proxy.ReloadSecrets()
		require.Empty(t, retiringLeaks(errText(err), everyValue...), "the error carries a key")
		require.NoError(t, err)

		served := proxy.SnapshotSecrets()
		require.Equal(t, 2, len(served), "alice and bob, and no third secret")

		alice := snapshotOf(t, proxy, "alice")
		assert.True(t, alice.Secret == renewed.Base64(), "the re-key is in force")
		assert.Zero(t, alice.RetiringKeys, "nothing retires alice's old key")

		for _, info := range served {
			assert.NotEqual(t, "retiring-secret", info.Name)
			assert.False(t, info.Secret == leaked.Base64(), "the leaked key is served")
		}
	})

	t.Run("doctor fails it", func(t *testing.T) {
		t.Parallel()

		d, out := newDoctor(t, misEdit, time.Second, nil)

		assert.False(t, d.checkRetiringSecrets())
		require.Empty(t, retiringLeaks(out.String(), everyValue...), "the doctor printed a key")
		assert.Contains(t, out.String(), "⚠️  "+misplacedUserLine)
	})

	t.Run("the secrets every reader is given leave it out", func(t *testing.T) {
		t.Parallel()

		conf, err := utils.ParseConfig([]byte(misEdit))
		require.NoError(t, err)

		_, found := conf.GetSecrets()["retiring-secret"]
		assert.False(t, found, "GetSecrets, which run, access, doctor and the relay read, serves the user")
	})
}
