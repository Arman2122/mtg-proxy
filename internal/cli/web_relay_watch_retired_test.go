package cli

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Arman2122/mtg-proxy/internal/utils"
	"github.com/Arman2122/mtg-proxy/internal/webrelay"
	"github.com/Arman2122/mtg-proxy/logger"
	"github.com/Arman2122/mtg-proxy/mtglib"
	"github.com/stretchr/testify/require"
)

// Task 11 on the running relay: a retired key's WEB capability is recognised
// from the file, so its holder gets the local 404 and never the cover site, and
// a change of the retired list alone reaches the registry without counting a
// profile reload.
//
// No assertion here prints a capability or a value: a Secret's String() is its
// value. Outcomes are told apart by the relay's own counters, because the
// fixture's cover site is an empty directory that answers 404 too.

// The values of the fixture's clients, as reloadConfigTOML spells them. alice
// is oneSecret; rekeyed is bob's value, the key alice is rotated to.
const (
	aliceValue   = "7oe1GqLy6TBc38CV3jx7q09nb29nbGUuY29t"
	rekeyedValue = "7ni1GqLy6TBc38CV3jx7q09nb29nbGUuY29t"

	relayHost = "proxy.example.com"

	farAway = "2999-01-01T00:00:00Z"
	longAgo = "2000-01-01T00:00:00Z"
)

// Two retired keys, as ee values (hex), none of them a fixture client's.
const (
	retiredKeyOne = "1111111111111111aaaaaaaaaaaaaaaa"
	retiredKeyTwo = "2222222222222222bbbbbbbbbbbbbbbb"
)

// retiredEE is key's ee value fronting www.google.com, in hex.
func retiredEE(key string) string { return "ee" + key + hex.EncodeToString([]byte("www.google.com")) }

// relayBlock is one [[retiring-secret]] block. It opens with its own header
// and so can be spliced after the [[listener]] lines (writeReloadConfig's
// listener argument is raw text), which is between two tables.
func relayBlock(name, value, until string) string {
	return fmt.Sprintf("\n[[retiring-secret]]\nname = %q\nsecret = %q\nuntil = %q\n", name, value, until)
}

// capabilityOfValue is the WEB capability a holder of value presents.
func capabilityOfValue(t *testing.T, value string) string {
	t.Helper()

	secret, err := mtglib.ParseSecret(value)
	require.NoError(t, err)

	capability, err := webrelay.Derive(webrelay.WebSecret(secret), relayHost)
	require.NoError(t, err)

	return capability.String()
}

// spellingsOf is the four spellings a leak test looks for, of a value given in
// hex or base64url: the value in hex and in base64url, its 16-byte key in hex
// and in base64 (standard and url, unpadded).
func spellingsOf(t *testing.T, value string) []string {
	t.Helper()

	secret, err := mtglib.ParseSecret(value)
	require.NoError(t, err)

	raw, err := hex.DecodeString(secret.Hex())
	require.NoError(t, err)

	return []string{
		strings.ToLower(secret.Hex()),
		base64.RawURLEncoding.EncodeToString(raw),
		hex.EncodeToString(secret.Key[:]),
		base64.RawStdEncoding.EncodeToString(secret.Key[:]),
		base64.RawURLEncoding.EncodeToString(secret.Key[:]),
	}
}

// capturingLogger records every line at every level with the fields bound to it.
type capturingLogger struct {
	mtglib.Logger

	sink   *logSink
	fields string
}

type logSink struct {
	mutex sync.Mutex
	lines []string
}

func newCapturingLogger() *capturingLogger {
	return &capturingLogger{Logger: logger.NewNoopLogger(), sink: &logSink{}}
}

func (c *capturingLogger) bound(field string) *capturingLogger {
	return &capturingLogger{Logger: c.Logger, sink: c.sink, fields: c.fields + " " + field}
}

func (c *capturingLogger) Named(_ string) mtglib.Logger { return c }
func (c *capturingLogger) BindInt(name string, value int) mtglib.Logger {
	return c.bound(fmt.Sprintf("%s=%d", name, value))
}

func (c *capturingLogger) BindStr(name, value string) mtglib.Logger {
	return c.bound(name + "=" + value)
}

func (c *capturingLogger) BindJSON(name, value string) mtglib.Logger {
	return c.bound(name + "=" + value)
}

func (c *capturingLogger) record(level, message string) {
	c.sink.mutex.Lock()
	defer c.sink.mutex.Unlock()

	c.sink.lines = append(c.sink.lines, level+":"+c.fields+" "+message)
}

func (c *capturingLogger) Debug(message string)   { c.record("debug", message) }
func (c *capturingLogger) Info(message string)    { c.record("info", message) }
func (c *capturingLogger) Warning(message string) { c.record("warning", message) }
func (c *capturingLogger) WarningError(message string, err error) {
	c.record("warning", fmt.Sprintf("%s: %v", message, err))
}

// at is the lines of one level.
func (c *capturingLogger) at(level string) []string {
	c.sink.mutex.Lock()
	defer c.sink.mutex.Unlock()

	var out []string

	for _, line := range c.sink.lines {
		if strings.HasPrefix(line, level+":") {
			out = append(out, line)
		}
	}

	return out
}

func (c *capturingLogger) everything() string {
	c.sink.mutex.Lock()
	defer c.sink.mutex.Unlock()

	return strings.Join(c.sink.lines, "\n")
}

// retiredRelay is a relay built from a file, its reloader driven by hand.
type retiredRelay struct {
	dir      string
	path     string
	origin   *webrelay.Origin
	counters *webrelay.Counters
	reloader *profileReloader
	log      *capturingLogger
}

// newRetiredRelay starts a relay on a file with the given [secrets] and blocks.
func newRetiredRelay(t *testing.T, secrets string, blocks ...string) *retiredRelay {
	t.Helper()

	dir := t.TempDir()
	path := writeReloadConfig(t, dir, nil, strings.Join(blocks, ""), secrets)

	conf, err := utils.ReadConfig(path)
	require.NoError(t, err)
	require.NoError(t, conf.ValidateWeb())

	log := newCapturingLogger()
	counters := webrelay.NewCounters(time.Now())

	origin, _, err := buildOrigin(conf, counters, log)
	require.NoError(t, err)

	structure, err := webStructure(conf)
	require.NoError(t, err)

	return &retiredRelay{
		dir:      dir,
		path:     path,
		origin:   origin,
		counters: counters,
		reloader: newProfileReloader(conf, path, origin, counters, structure, log),
		log:      log,
	}
}

// write replaces the file.
func (r *retiredRelay) write(t *testing.T, secrets string, blocks ...string) {
	t.Helper()

	writeReloadConfig(t, r.dir, nil, strings.Join(blocks, ""), secrets)
}

func (r *retiredRelay) ticks(n int) {
	for range n {
		r.reloader.tick()
	}
}

func (r *retiredRelay) stats() webrelay.RelayStats {
	return r.counters.Snapshot(time.Now(), 0, 0)
}

// The three answers a bridge request can get.
const (
	answerBridge = "the bridge"
	answerLocal  = "a local 404"
	answerCover  = "the cover site"
)

// answer asks for a capability's bridge and says which tier answered, by what
// moved: the bridge by its page, the local 404 by the not-found counter, the
// cover site by its own.
func (r *retiredRelay) answer(t *testing.T, capability string) string {
	t.Helper()

	before := r.stats().Refused

	recorder := httptest.NewRecorder()
	r.origin.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/?bridge="+capability, nil))

	after := r.stats().Refused

	switch {
	case strings.Contains(recorder.Body.String(), "TPROXY_BOOT"):
		return answerBridge
	case after.NotFound == before.NotFound+1 && after.CoverServed == before.CoverServed:
		return answerLocal
	case after.CoverServed == before.CoverServed+1 && after.NotFound == before.NotFound:
		return answerCover
	default:
		return "an answer no tier gives"
	}
}

// W3: a change of the retired list alone is recognised by the running relay,
// and leaves the profiles and the reload count alone. It is the shape of a
// --prune, and of the first look at a file whose only news is a retiring block.
func TestARetiredOnlyChangeIsRecognisedWithoutReloadingTheProfiles(t *testing.T) {
	t.Parallel()

	relay := newRetiredRelay(t, oneSecret)

	one := capabilityOfValue(t, retiredEE(retiredKeyOne))
	two := capabilityOfValue(t, retiredEE(retiredKeyTwo))

	require.Equal(t, answerCover, relay.answer(t, one), "precondition: an unknown capability is the website")

	// A block appears: nothing about the profiles changes.
	relay.write(t, oneSecret, relayBlock("alice", retiredEE(retiredKeyOne), farAway))
	relay.ticks(2)

	require.Equal(t, 1, relay.origin.Profiles())
	require.Zero(t, relay.stats().Reloads, "a retired-only change was counted as a profile reload")
	require.Zero(t, relay.stats().ReloadFails)
	require.Equal(t, answerLocal, relay.answer(t, one), "the new retired capability is not recognised")
	require.Equal(t, answerCover, relay.answer(t, two), "a capability no block names is still the website")
	require.True(t, servesBridge(t, relay.origin, relay.path, "alice"), "the live client stopped being served")
	require.Empty(t, relay.log.at("warning"), "a clean retired-only change must report nothing")

	// A second block, an expired one, then the table emptied (a --prune).
	relay.write(t, oneSecret,
		relayBlock("alice", retiredEE(retiredKeyOne), farAway),
		relayBlock("alice", retiredEE(retiredKeyTwo), longAgo))
	relay.ticks(2)

	require.Equal(t, answerLocal, relay.answer(t, one))
	require.Equal(t, answerLocal, relay.answer(t, two), "an expired block's capability must be recognised too")
	require.Zero(t, relay.stats().Reloads)

	relay.write(t, oneSecret)
	relay.ticks(2)

	require.Equal(t, answerCover, relay.answer(t, one), "a pruned block's capability is an unknown one again")
	require.Equal(t, answerCover, relay.answer(t, two))
	require.Zero(t, relay.stats().Reloads)
	require.Zero(t, relay.stats().ReloadFails)
	require.True(t, servesBridge(t, relay.origin, relay.path, "alice"))
}

// The change is logged at Debug, with counts: a retired capability is derived
// from a credential, and nothing the relay prints may carry one.
func TestARetiredOnlyChangeIsLoggedAtDebugWithCountsOnly(t *testing.T) {
	t.Parallel()

	relay := newRetiredRelay(t, oneSecret)

	relay.write(t, oneSecret,
		relayBlock("alice", retiredEE(retiredKeyOne), farAway),
		relayBlock("alice", retiredEE(retiredKeyTwo), farAway))
	relay.ticks(2)

	var changed []string

	for _, line := range relay.log.at("debug") {
		if strings.Contains(line, "retired") {
			changed = append(changed, line)
		}
	}

	require.Len(t, changed, 1, "one Debug line says the retired list changed")
	require.Contains(t, changed[0], "retired=2", "the line carries the count")
	require.Empty(t, relay.log.at("info"), "a retired-only change is not an Info event")
	require.Empty(t, relay.log.at("warning"))

	all := relay.log.everything()

	for _, key := range []string{retiredKeyOne, retiredKeyTwo} {
		for _, spelling := range spellingsOf(t, retiredEE(key)) {
			require.NotContains(t, strings.ToLower(all), strings.ToLower(spelling), "a retired value reached a log line")
		}
	}

	for _, capability := range []string{
		capabilityOfValue(t, retiredEE(retiredKeyOne)), capabilityOfValue(t, retiredEE(retiredKeyTwo)),
	} {
		require.NotContains(t, all, capability, "a retired capability reached a log line")
	}
}

// A retired key already in the file when the relay starts is recognised from
// the first request, expired or not, whatever its name: the startup path, not
// the reload.
func TestRetiredCapabilitiesAreRecognisedFromStartup(t *testing.T) {
	t.Parallel()

	relay := newRetiredRelay(t, oneSecret,
		relayBlock("alice", retiredEE(retiredKeyOne), longAgo),
		relayBlock("nobody", retiredEE(retiredKeyTwo), farAway))

	for _, value := range []string{retiredEE(retiredKeyOne), retiredEE(retiredKeyTwo)} {
		require.Equal(t, answerLocal, relay.answer(t, capabilityOfValue(t, value)),
			"a retired capability is not answered locally")
	}

	require.Equal(t, answerBridge, relay.answer(t, capabilityOfValue(t, aliceValue)))
	require.Equal(t, 1, relay.origin.Profiles(), "a retired key is not a profile")
	require.Zero(t, relay.stats().Refused.CoverServed, "a retired capability reached the cover site")
}

// An edit that leaves the retired values alone -- a comment, or a block's until
// moved -- is not a retired change either: it is compared by value.
func TestAnUnchangedRetiredListIsNotReapplied(t *testing.T) {
	t.Parallel()

	relay := newRetiredRelay(t, oneSecret, relayBlock("alice", retiredEE(retiredKeyOne), farAway))

	relay.write(t, oneSecret+"  # edited by hand", relayBlock("alice", retiredEE(retiredKeyOne), farAway))
	relay.ticks(2)

	relay.write(t, oneSecret, relayBlock("alice", retiredEE(retiredKeyOne), "2998-01-01T00:00:00Z"))
	relay.ticks(2)

	for _, line := range relay.log.at("debug") {
		require.NotContains(t, line, "retired capabilities", "an edit that left the retired values alone was applied as a change")
	}

	require.Equal(t, 2, len(relay.log.at("debug")), "each edit that changed nothing is said so, at Debug")
	require.Zero(t, relay.stats().Reloads)
	require.Equal(t, answerLocal, relay.answer(t, capabilityOfValue(t, retiredEE(retiredKeyOne))))
}

// A change of the profiles keeps the retired list. A reload that swapped in
// the new profiles and forgot the retired ones would send every old link to the
// cover site the moment any client was added.
func TestAProfileChangeCarriesTheRetiredList(t *testing.T) {
	t.Parallel()

	relay := newRetiredRelay(t, oneSecret, relayBlock("alice", retiredEE(retiredKeyOne), farAway))
	old := capabilityOfValue(t, retiredEE(retiredKeyOne))

	relay.write(t, twoSecrets, relayBlock("alice", retiredEE(retiredKeyOne), farAway))
	relay.ticks(2)

	require.Equal(t, 2, relay.origin.Profiles())
	require.Equal(t, int64(1), relay.stats().Reloads)
	require.True(t, servesBridge(t, relay.origin, relay.path, "bob"))
	require.Equal(t, answerLocal, relay.answer(t, old), "a profile change dropped the retired list")

	// And the change of both at once, which is what a signal sends.
	relay.write(t, twoSecrets, relayBlock("alice", retiredEE(retiredKeyTwo), farAway))
	relay.reloader.reload(reloadTriggerSignal)

	require.Equal(t, int64(2), relay.stats().Reloads, "a signal is counted")
	require.Equal(t, answerCover, relay.answer(t, old))
	require.Equal(t, answerLocal, relay.answer(t, capabilityOfValue(t, retiredEE(retiredKeyTwo))))
}

// A rotation is one write: alice's value is replaced and the old one comes back
// as a block. The relay must change over in one step -- the new link serves, and
// the old one is the local 404 at once, never the website in between.
func TestARotationMovesTheOldCapabilityToTierTwoInOneSwap(t *testing.T) {
	t.Parallel()

	relay := newRetiredRelay(t, oneSecret)

	old := capabilityOfValue(t, aliceValue)
	fresh := capabilityOfValue(t, rekeyedValue)

	require.Equal(t, answerBridge, relay.answer(t, old), "precondition: the old link serves")
	require.Equal(t, answerCover, relay.answer(t, fresh))

	relay.write(t, `alice = "`+rekeyedValue+`"`, relayBlock("alice", aliceValue, farAway))
	relay.ticks(2)

	require.Equal(t, int64(1), relay.stats().Reloads)
	require.Equal(t, answerBridge, relay.answer(t, fresh), "the new link does not serve")
	require.Equal(t, answerLocal, relay.answer(t, old), "the old link must be the local 404, never the website")
	require.EqualValues(t, 1, relay.stats().Refused.CoverServed, "only the precondition's probe reached the cover site")
}

// A signal that lands a retired-only change is a reload the operator asked
// about, so it is counted, and the retired capability is recognised.
func TestARetiredOnlyChangeBySignalIsCountedAndRecognised(t *testing.T) {
	t.Parallel()

	relay := newRetiredRelay(t, oneSecret)

	relay.write(t, oneSecret, relayBlock("alice", retiredEE(retiredKeyOne), farAway))
	relay.reloader.reload(reloadTriggerSignal)

	require.Equal(t, int64(1), relay.stats().Reloads, "a signal that landed was not reported")
	require.Equal(t, answerLocal, relay.answer(t, capabilityOfValue(t, retiredEE(retiredKeyOne))))

	relay.ticks(4)

	require.Equal(t, int64(1), relay.stats().Reloads, "the watcher applied the signal's change a second time")
}

// A file the relay refuses keeps the retired list it had: a broken save must
// not send the old links to the cover site.
func TestARefusedFileKeepsTheRetiredList(t *testing.T) {
	t.Parallel()

	relay := newRetiredRelay(t, oneSecret, relayBlock("alice", retiredEE(retiredKeyOne), farAway))
	old := capabilityOfValue(t, retiredEE(retiredKeyOne))

	require.NoError(t, os.WriteFile(relay.path, []byte("this is not toml at all ]["), 0o600))
	relay.ticks(2)

	require.Equal(t, int64(1), relay.stats().ReloadFails)
	require.Equal(t, answerLocal, relay.answer(t, old), "a broken file dropped the retired list")

	// A structural change is refused whole, retired list included.
	dir := relay.dir
	writeReloadConfig(t, dir, map[string]string{"host": `"other.example.com"`},
		relayBlock("alice", retiredEE(retiredKeyTwo), farAway), twoSecrets)
	relay.ticks(2)

	require.Equal(t, int64(2), relay.stats().ReloadFails)
	require.Equal(t, answerLocal, relay.answer(t, old))
	require.Equal(t, answerCover, relay.answer(t, capabilityOfValue(t, retiredEE(retiredKeyTwo))),
		"a refused file took in its retired list")
}
