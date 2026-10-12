package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Arman2122/mtg-proxy/internal/utils"
	"github.com/Arman2122/mtg-proxy/mtglib"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// runLog is what a run wrote to stdout while the test held it: every line, in
// order, read off a pipe that is drained for as long as the run writes, so the
// run never blocks on a full pipe whatever the test is doing.
type runLog struct {
	mu    sync.Mutex
	lines []string
	ended chan struct{}
}

// captureRunLog points os.Stdout at a pipe for the run the test is about to
// start (makeLogger binds the logger to whatever os.Stdout is at the time). end
// gives stdout back, closes the pipe once the run has returned, and waits until
// every line written has been read.
func captureRunLog(t *testing.T) (*runLog, func()) {
	t.Helper()

	reader, writer, err := os.Pipe()
	require.NoError(t, err)

	log := &runLog{ended: make(chan struct{})}

	go func() {
		defer close(log.ended)

		scanner := bufio.NewScanner(reader)
		scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)

		for scanner.Scan() {
			log.mu.Lock()
			log.lines = append(log.lines, scanner.Text())
			log.mu.Unlock()
		}

		// A line past the buffer stops the scanner; the pipe must still be
		// drained, or the run would block writing to it.
		io.Copy(io.Discard, reader) //nolint: errcheck
	}()

	stdout := os.Stdout
	os.Stdout = writer

	var once sync.Once

	end := func() {
		once.Do(func() {
			os.Stdout = stdout

			writer.Close() //nolint: errcheck
			<-log.ended
			reader.Close() //nolint: errcheck
		})
	}

	t.Cleanup(end)

	return log, end
}

// entries is every JSON line of the log, in order.
func (l *runLog) entries(t *testing.T) []map[string]any {
	t.Helper()

	l.mu.Lock()
	defer l.mu.Unlock()

	out := make([]map[string]any, 0, len(l.lines))

	for _, line := range l.lines {
		var entry map[string]any
		if json.Unmarshal([]byte(line), &entry) == nil {
			out = append(out, entry)
		}
	}

	return out
}

func (l *runLog) text() string {
	l.mu.Lock()
	defer l.mu.Unlock()

	return strings.Join(l.lines, "\n")
}

// The lines the proxy writes once its management API is bound, and when it
// cannot bind it -- which does not stop the proxy.
const (
	apiStarted   = "Management API server started"
	apiNotBound  = "cannot start management API listener"
	apiBindError = "cannot bind "
)

// servesAPIOn reports whether the log says the proxy bound its API on addr.
func (l *runLog) servesAPIOn(t *testing.T, addr string) bool {
	t.Helper()

	for _, entry := range l.entries(t) {
		if entry["message"] == apiStarted && entry["bind"] == addr {
			return true
		}
	}

	return false
}

// couldNotBindAPI reports whether the log says the proxy found addr taken.
func (l *runLog) couldNotBindAPI(t *testing.T, addr string) bool {
	t.Helper()

	for _, entry := range l.entries(t) {
		if reason, ok := entry["error"].(string); ok && entry["message"] == apiNotBound &&
			strings.Contains(reason, apiBindError+addr) {
			return true
		}
	}

	return false
}

// freeLoopbackPort is a port nothing listens on, for a socket the proxy binds
// itself (the management API does not bind through the listen seam). Picking
// and releasing it leaves a gap in which another process can take the port, so
// startRotationRun, its one user, retries a run that loses it.
func freeLoopbackPort(t *testing.T) uint {
	t.Helper()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	port := uint(l.Addr().(*net.TCPAddr).Port) //nolint: forcetypeassert

	require.NoError(t, l.Close())

	return port
}

// apiCall makes one request to the run's management API.
func apiCall(t *testing.T, method, url string) (int, string, error) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	require.NoError(t, err)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, "", err
	}

	defer resp.Body.Close() //nolint: errcheck

	body, err := io.ReadAll(resp.Body)

	return resp.StatusCode, string(body), err
}

// rotationRun is one runProxyWith the E6 harness started and saw serve its API.
type rotationRun struct {
	api    string // host:port of the management API
	log    *runLog
	endLog func()

	stop  func()
	ended chan struct{}
	err   error // what runProxyWith returned; read only once ended is closed
}

// end stops the run and waits for it to return, and returns what it returned.
func (r *rotationRun) end(t *testing.T) error {
	t.Helper()

	r.stop()

	select {
	case <-r.ended:
		return r.err
	case <-time.After(15 * time.Second):
		t.Fatal("the run loop did not return")

		return nil
	}
}

// startRotationRun starts runProxyWith on the config file raw makes of two held
// loopback ports and an API address, with its log captured, and returns once
// the log shows the proxy bound that API address: its own socket, so every
// request after that reaches this run. The API binds outside the listen seam on
// a port picked and released, so a pick another process took first -- which the
// proxy logs and serves on without -- ends that run and is retried on a new
// port; any early end of the run fails the test.
//
// Whatever happens to the test, the run is stopped and waited for before its
// log is closed and before anything registered earlier is undone.
func startRotationRun(
	t *testing.T, raw func(public, extra uint, api string) string, now func() time.Time,
) *rotationRun {
	t.Helper()

	for range 5 {
		if run := tryRotationRun(t, raw, now); run != nil {
			return run
		}
	}

	t.Fatal("every API port picked was taken before the run could bind it")

	return nil
}

// tryRotationRun is one attempt of startRotationRun: the run serving its API,
// or nil when another process took the API port first.
func tryRotationRun(
	t *testing.T, raw func(public, extra uint, api string) string, now func() time.Time,
) *rotationRun {
	t.Helper()

	ports, held := holdPorts(t, 2)
	api := fmt.Sprintf("127.0.0.1:%d", freeLoopbackPort(t))
	text := raw(held[0], held[1], api)

	conf, err := utils.ParseConfig([]byte(text))
	require.NoError(t, err)

	path := writeConfig(t, text)
	log, endLog := captureRunLog(t)

	stop := make(chan struct{})

	var stopOnce sync.Once

	run := &rotationRun{
		api:    api,
		log:    log,
		endLog: endLog,
		stop:   func() { stopOnce.Do(func() { close(stop) }) },
		ended:  make(chan struct{}),
	}

	go func() {
		run.err = runProxyWith(stop, conf, "test", path, ports.listen, now)
		close(run.ended)
	}()

	// Registered after captureRunLog, so it runs first: a failed assertion
	// never leaves the run writing to a closed pipe, or serving.
	t.Cleanup(func() {
		run.stop()

		select {
		case <-run.ended:
		case <-time.After(15 * time.Second):
			t.Error("the run loop did not return")
		}
	})

	deadline := time.Now().Add(10 * time.Second)

	for !log.servesAPIOn(t, api) {
		// A taken API port does not stop the proxy, which serves on without
		// its API: this run is ended, and the next attempt picks another port.
		if log.couldNotBindAPI(t, api) {
			require.NoError(t, run.end(t))
			endLog()

			return nil
		}

		select {
		case <-run.ended:
			t.Fatalf("the run ended before its API was up: %v", run.err)
		case <-time.After(10 * time.Millisecond):
		}

		require.True(t, time.Now().Before(deadline), "the run's API never came up")
	}

	return run
}

// E6 (M2, m4′; Task 2's m3). One rotation clock serves the reloader and the
// proxy, and it is the run's own: built in runProxyWith on the time it is given,
// reporting through the run's logger.
//
// The run starts an hour after the overlap's until, so the clock's mark is past
// it. The time then steps two hours back -- an NTP step, say -- and a reload
// arrives, an hour before until by the wall clock. On the one clock the reloader
// judges by the mark: the entry is expired, the Info summary counts it, and the
// engine is never handed it, so it logs no drop. A reloader on a clock of its own
// would judge by the wall clock, hand the entry over, and the engine, on the run's
// clock, would drop it as expired. The step is reported once, by the run's
// reporter.
//
// The file also holds a block with a malformed until, which neither the start
// nor the reload refuses; a block still in its overlap, which both hand to the
// proxy; and (Task 8b's review, I1) a [secrets] user named retiring-secret, which
// neither serves and both warn about.
//
// It is not parallel: the run writes its log to os.Stdout, which the test points
// at a pipe, and debug = true sets zerolog's global level, which it puts back.
func TestOneRotationClockServesTheReloaderAndTheProxy(t *testing.T) {
	level := zerolog.GlobalLevel()
	t.Cleanup(func() { zerolog.SetGlobalLevel(level) })

	// Far from the wall clock, so that whatever read the wall clock instead of
	// the run's would judge differently: every entry is unexpired by it.
	until := time.Date(2099, 10, 9, 9, 30, 0, 0, time.UTC)

	primary, err := mtglib.GenerateSecretMode(mtglib.SecretModeDD, "")
	require.NoError(t, err)

	old, err := mtglib.GenerateSecretMode(mtglib.SecretModeDD, "")
	require.NoError(t, err)

	broken, err := mtglib.GenerateSecretMode(mtglib.SecretModeDD, "")
	require.NoError(t, err)

	kept, err := mtglib.GenerateSecretMode(mtglib.SecretModeDD, "")
	require.NoError(t, err)

	misplaced, err := mtglib.GenerateSecretMode(mtglib.SecretModeDD, "")
	require.NoError(t, err)

	keptUntil := until.Add(48 * time.Hour)

	// The loop harness's file (a hostless dd secret: no start-up DNS lookup), with
	// debug and the API among the top-level keys, before the first table. The
	// [secrets] table holds only the mis-edit, so default is still the top-level
	// secret.
	raw := func(public, extra uint, api string) string {
		return fmt.Sprintf(`
secret = "%s"
bind-to = "127.0.0.1:%d"
debug = true
api-bind-to = "%s"

[domain-fronting]
host = "127.0.0.1"
port = 1

[network.timeout]
handshake = "300ms"

[[listener]]
bind-to = "127.0.0.1:%d"
accept = ["dd"]

[[retiring-secret]]
name = "default"
secret = "%s"
until = "%s"

[[retiring-secret]]
name = "default"
secret = "%s"
until = "the day after tomorrow"

[[retiring-secret]]
name = "default"
secret = "%s"
until = "%s"

[secrets]
retiring-secret = "%s"
`, primary.Hex(), public, api, extra, old.Hex(), rfc3339(until), broken.Hex(), kept.Hex(), rfc3339(keptUntil),
			misplaced.Hex())
	}

	// Read from the API handler's goroutine as well as this one.
	var wall atomic.Int64

	wall.Store(until.Add(time.Hour).UnixNano())

	now := func() time.Time { return time.Unix(0, wall.Load()).UTC() }

	// The API is up only once NewProxy has returned, and by then every read the
	// start makes of the clock is done: the start's report before NewProxy, the
	// first set's build inside it.
	run := startRotationRun(t, raw, now)

	// What the proxy holds: default with the one entry still in its overlap, and
	// not the one the mark has passed; and no secret named retiring-secret.
	requireServed := func(when string) {
		t.Helper()

		status, body, err := apiCall(t, http.MethodGet, "http://"+run.api+"/secrets/default")
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, status)

		var info mtglib.SecretInfo

		require.NoError(t, json.Unmarshal([]byte(body), &info))
		require.Equal(t, 1, info.RetiringKeys, when+": the proxy holds one previous key")
		require.NotNil(t, info.RetiringUntil)
		assert.True(t, info.RetiringUntil.Equal(keptUntil), when+": the previous key held is the one still in its overlap")

		status, _, err = apiCall(t, http.MethodGet, "http://"+run.api+"/secrets/retiring-secret")
		require.NoError(t, err)
		assert.Equal(t, http.StatusNotFound, status, when+": a [secrets] user named retiring-secret is served")
	}

	requireServed("at the start")

	wall.Store(until.Add(-time.Hour).UnixNano())

	status, _, err := apiCall(t, http.MethodPost, "http://"+run.api+"/reload")
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, status, "the reload is refused")

	requireServed("after the reload")

	require.NoError(t, run.end(t))

	// Every line the run wrote is read before anything is judged: the engine's
	// drop would come after the reloader's summary, so a look any earlier could
	// miss it. The leak check comes first, so no failing assertion prints a key.
	run.endLog()
	require.Empty(t, retiringLeaks(run.log.text(), old, broken, kept, misplaced), "the run's log carries a retiring key")

	const (
		expiredSummary = "retiring-secret entries past their until are ignored; rotate-secret --prune removes them"
		engineDrop     = "a retiring key was ignored"
		behind         = "the wall clock is behind the latest time seen; rotation overlaps are judged by the latest time"
		badBlock       = `retiring-secret #2 (name "default"): until is not an RFC 3339 date-time with an offset, ` +
			`such as 2026-10-09T09:30:00Z; the entry is ignored and its key is not accepted`
	)

	var (
		summaries, badBlocks, behinds, misEdits []map[string]any
		summaryAt                               []int
		apiAt                                   = -1
	)

	for i, entry := range run.log.entries(t) {
		switch entry["message"] {
		case expiredSummary:
			summaries = append(summaries, entry)
			summaryAt = append(summaryAt, i)
		case badBlock:
			badBlocks = append(badBlocks, entry)
		case misplacedUserLine:
			misEdits = append(misEdits, entry)
		case behind:
			behinds = append(behinds, entry)
		case apiStarted:
			apiAt = i
		case engineDrop:
			assert.NotEqual(t, "expired", entry["reason"],
				"the engine dropped an entry as expired: the reloader judged it on a clock of its own")
		}
	}

	// The start's summary and the reload's, each counting the one entry.
	require.Len(t, summaries, 2, "the reload's summary must count the entry the mark has passed")
	require.NotEqual(t, -1, apiAt)
	assert.Less(t, summaryAt[0], apiAt, "the start's summary comes before the proxy is built")
	assert.Greater(t, summaryAt[1], apiAt, "the reload's summary comes after")

	for _, entry := range summaries {
		assert.Equal(t, "info", entry["level"])
		assert.Equal(t, float64(1), entry["expired"], "a JSON number: the one expired entry")
	}

	// The malformed block and the mis-edit, each at the start and at the
	// reload, neither refused, both from the run's own logger.
	require.Len(t, badBlocks, 2)
	require.Len(t, misEdits, 2, "the [secrets] user named retiring-secret is warned about at the start and the reload")

	for _, entry := range append(badBlocks, misEdits...) {
		assert.Equal(t, "warn", entry["level"])
		assert.Equal(t, "", entry["logger"])
	}

	// The step back, reported once, by the run's own reporter: the proxy's
	// logger is named "proxy", the run's has no name.
	require.Len(t, behinds, 1, "the run's clock must report the step back once")
	assert.Equal(t, "warn", behinds[0]["level"])
	assert.Equal(t, "2h0m0s", behinds[0]["behind_by"])
	assert.Equal(t, "", behinds[0]["logger"], "the Warning must come from the run's reporter")
}
