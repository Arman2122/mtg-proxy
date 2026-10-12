package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Arman2122/mtg-proxy/internal/config"
	"github.com/Arman2122/mtg-proxy/mtglib"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// rotate-secret --reload (spec §7.5, D26; R10 and R7's reload half). Before
// anything is written it asks the running proxy's /stats whether it is there and
// knows the [[retiring-secret]] table; after the write it reloads it and reads
// back, for each name the run touched, what the written file says the proxy
// must now serve. The file is never rolled back.
//
// Every test here reads stdout or swaps a seam, so none runs in parallel, and
// every assertion that could print a secret runs after a leak check.

// reloadToken is the management API's token in these tests: a credential, so
// it is looked for in what a run prints, as the keys are.
const reloadToken = "the-api-token-of-a-reload-test"

// reloadFile is the loop harness's file -- a FakeTLS bind-to fronted at a port
// that refuses, a [[listener]] for dd, hostless dd secrets so that nothing
// reaches the internet -- with the management API on api behind reloadToken,
// the blocks, and [secrets] last. debug = true is what makes the proxy log that
// its API is up, which startRotationRun waits for; it sets zerolog's global
// level, which a test that starts the proxy puts back.
func reloadFile(public, extra uint, api string, secrets map[string]mtglib.Secret, blocks ...string) string {
	var out strings.Builder

	fmt.Fprintf(&out, "debug = true\nbind-to = \"127.0.0.1:%d\"\napi-bind-to = %q\napi-token = %q\n\n", public, api, reloadToken)
	out.WriteString("[domain-fronting]\nhost = \"127.0.0.1\"\nport = 1\n\n[network.timeout]\nhandshake = \"300ms\"\n\n")
	fmt.Fprintf(&out, "[[listener]]\nbind-to = \"127.0.0.1:%d\"\naccept = [\"dd\"]\n\n", extra)

	for _, block := range blocks {
		out.WriteString(block)
	}

	out.WriteString("[secrets]\n")

	for _, name := range slices.Sorted(maps.Keys(secrets)) {
		fmt.Fprintf(&out, "%s = %q\n", name, secrets[name].Hex())
	}

	return out.String()
}

// clockAt is a clock stopped at at: what the run, its read-back and the proxy
// read, so that both sides judge an until alike.
func clockAt(at time.Time) func() time.Time { return func() time.Time { return at } }

// startReloadRun starts the proxy on reloadFile, on proxyNow's clock.
func startReloadRun(
	t *testing.T, proxyNow func() time.Time, secrets map[string]mtglib.Secret, blocks ...string,
) *rotationRun {
	t.Helper()

	return startRotationRun(t, func(public, extra uint, api string) string {
		return reloadFile(public, extra, api, secrets, blocks...)
	}, proxyNow)
}

// secretOn is GET /secrets/{name} on the run's API, with the token.
func secretOn(t *testing.T, api, name string) mtglib.SecretInfo {
	t.Helper()

	status, body := apiGet(t, api, "/secrets/"+name)
	require.Equal(t, http.StatusOK, status, "GET /secrets/%s", name)

	var info mtglib.SecretInfo

	require.NoError(t, json.Unmarshal([]byte(body), &info))

	return info
}

// apiGet is one GET on api with the token: the status and the body.
func apiGet(t *testing.T, api, path string) (int, string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+api+path, nil)
	require.NoError(t, err)

	req.Header.Set("Authorization", "Bearer "+reloadToken)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)

	defer resp.Body.Close() //nolint: errcheck

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	return resp.StatusCode, string(body)
}

// newValue is the value a run printed on stdout, which must be exactly one
// line.
func newValue(t *testing.T, res rotateResult) mtglib.Secret {
	t.Helper()

	value, oneLine := res.oneLine()
	require.True(t, oneLine, "stdout is not exactly one line")

	secret, err := mtglib.ParseSecret(value)
	require.NoError(t, err)

	return secret
}

// requireQuiet is the leak check of a run: nothing it printed, on stderr or in
// its error, carries a spelling of the keys given -- the new one among them,
// which belongs on stdout only (R7) -- or the API's token.
func requireQuiet(t *testing.T, res rotateResult, keys ...mtglib.Secret) {
	t.Helper()

	require.Empty(t, retiringLeaks(res.printed(), keys...), "a message carries a key")
	require.NotContains(t, res.printed(), reloadToken, "a message carries the API's token")
}

// rewriteAfterTheRename runs edit over the file just after the run renamed it
// into place -- through the syncDir seam -- as another process could.
func rewriteAfterTheRename(t *testing.T, edit func(text string) string) {
	t.Helper()

	original := syncDir

	t.Cleanup(func() { syncDir = original })

	syncDir = func(dir string) error {
		path := dir + string(os.PathSeparator) + "config.toml"

		data, err := os.ReadFile(path)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(path, []byte(edit(string(data))), 0o600))

		return original(dir)
	}
}

// The likely causes §7.5 gives for each check.
const (
	primaryCauses = "a SECRET environment variable overriding [secrets]; a single-file bind mount that still " +
		"shows the old file (mount the config's directory instead); another process that rewrote the file"
	retiringCauses = "the proxy's clock is ahead of this machine's (its latest time judged an entry expired), " +
		"or the proxy logged a problem with a [[retiring-secret]] block"
	notServing = "the file is rotated but the proxy does not serve it: "
)

// R10. --reload against a real proxy: runProxyWith with its API, its reloader
// and its one rotation clock, through the loop harness.
func TestRotateSecretReloadsTheProxy(t *testing.T) {
	level := zerolog.GlobalLevel()
	t.Cleanup(func() { zerolog.SetGlobalLevel(level) })

	at := time.Now().UTC().Truncate(time.Second)
	clock := clockAt(at)

	alice := mustGenerate(t, mtglib.SecretModeDD, "")
	bob := mustGenerate(t, mtglib.SecretModeDD, "")
	older := mustGenerate(t, mtglib.SecretModeDD, "")
	primaries := map[string]mtglib.Secret{"alice": alice, "bob": bob}

	t.Run("a rotation is reloaded and read back", func(t *testing.T) {
		run := startReloadRun(t, clock, primaries)

		res := runRotate(t, RotateSecret{ConfigPath: run.path, Name: "alice", Overlap: "24h", Reload: true, now: clock})
		requireQuiet(t, res, alice, bob)

		renewed := newValue(t, res)
		requireQuiet(t, res, renewed)
		require.NoError(t, res.err)

		info := secretOn(t, run.api, "alice")
		assert.True(t, info.Secret == renewed.Base64(), "the proxy serves the new key")
		assert.Equal(t, 1, info.RetiringKeys)
		require.NotNil(t, info.RetiringUntil)
		assert.True(t, info.RetiringUntil.Equal(at.Add(24*time.Hour)))

		assert.Equal(t, strings.Join([]string{
			`rotated "alice" in ` + run.path,
			"the previous key is accepted until " + rfc3339(at.Add(24*time.Hour)) + " (24h0m0s from now)",
			"reloaded the proxy through its management API at " + run.api + "; it serves the file as written",
			"links: mtg-proxy access " + run.path,
		}, "\n")+"\n", res.stderr)
	})

	// Check 1 (m5′: its expected value is the written file's, not the proxy's).
	t.Run("check 1: the primary the proxy serves is not the written one", func(t *testing.T) {
		run := startReloadRun(t, clock, primaries)
		other := mustGenerate(t, mtglib.SecretModeDD, "")

		// Another process puts a key of its own into alice between the
		// write and the reload, and keeps the block.
		rewriteAfterTheRename(t, func(text string) string {
			conf, err := config.Parse([]byte(text))
			require.NoError(t, err)

			return strings.Replace(text, conf.Secrets["alice"].Hex(), other.Hex(), 1)
		})

		res := runRotate(t, RotateSecret{ConfigPath: run.path, Name: "alice", Overlap: "24h", Reload: true, now: clock})
		requireQuiet(t, res, alice, bob, other)

		renewed := newValue(t, res)
		requireQuiet(t, res, renewed)
		require.Error(t, res.err)

		assert.Equal(t, notServing+`the primary of "alice" differs (the written key, dd vs another key, dd); likely: `+
			primaryCauses, res.err.Error())
		assert.True(t, secretOn(t, run.api, "alice").Secret == other.Base64(), "the proxy serves another key")
	})

	// Check 2.
	t.Run("check 2: the proxy's clock is ahead", func(t *testing.T) {
		run := startReloadRun(t, clockAt(at.Add(25*time.Hour)), primaries)

		res := runRotate(t, RotateSecret{ConfigPath: run.path, Name: "alice", Overlap: "24h", Reload: true, now: clock})
		requireQuiet(t, res, alice, bob)

		renewed := newValue(t, res)
		requireQuiet(t, res, renewed)
		require.Error(t, res.err)

		assert.Equal(t, strings.Join([]string{
			notServing + `retiring_keys of "alice" differs (1 vs 0); likely: ` + retiringCauses,
			notServing + `retiring_until of "alice" differs (` + rfc3339(at.Add(24*time.Hour)) +
				` or later vs none); likely: ` + retiringCauses,
		}, "\n"), res.err.Error())
		assert.NotContains(t, res.err.Error(), "the primary of", "the primary is served")

		// The file is the truth, and stays as written.
		conf := readSecrets(t, run.path)
		assert.True(t, conf.Secrets["alice"] == renewed, "the file was rolled back")
		require.Equal(t, 1, len(conf.RetiringSecrets), "the file was rolled back")
		assert.True(t, conf.RetiringSecrets[0].Secret == alice.Hex(), "the file was rolled back")
	})

	// Check 3.
	t.Run("check 3: the overlap the proxy holds ends before the written one", func(t *testing.T) {
		run := startReloadRun(t, clock, primaries)

		rewriteAfterTheRename(t, func(text string) string {
			return strings.Replace(text, rfc3339(at.Add(24*time.Hour)), rfc3339(at.Add(12*time.Hour)), 1)
		})

		res := runRotate(t, RotateSecret{ConfigPath: run.path, Name: "alice", Overlap: "24h", Reload: true, now: clock})
		requireQuiet(t, res, alice, bob)

		renewed := newValue(t, res)
		requireQuiet(t, res, renewed)
		require.Error(t, res.err)

		assert.Equal(t, notServing+`retiring_until of "alice" differs (`+rfc3339(at.Add(24*time.Hour))+` or later vs `+
			rfc3339(at.Add(12*time.Hour))+`); likely: `+retiringCauses, res.err.Error())
	})

	// M1 of the review: retiring_until is the latest until of the name's
	// entries, so an earlier, longer overlap reports a later time than the one
	// just written -- and the name holds two previous keys.
	t.Run("a second rotation inside a longer earlier overlap passes", func(t *testing.T) {
		run := startReloadRun(t, clock, primaries, retiringBlock("alice", older, rfc3339(at.Add(48*time.Hour))))

		res := runRotate(t, RotateSecret{ConfigPath: run.path, Name: "alice", Overlap: "24h", Reload: true, now: clock})
		requireQuiet(t, res, alice, bob, older)

		renewed := newValue(t, res)
		requireQuiet(t, res, renewed)
		require.NoError(t, res.err)

		info := secretOn(t, run.api, "alice")
		assert.True(t, info.Secret == renewed.Base64())
		assert.Equal(t, 2, info.RetiringKeys)
		require.NotNil(t, info.RetiringUntil)
		assert.True(t, info.RetiringUntil.Equal(at.Add(48*time.Hour)), "the later until of the two")
	})

	t.Run("--overlap 0 counts the previous keys the name keeps", func(t *testing.T) {
		run := startReloadRun(t, clock, primaries, retiringBlock("alice", older, rfc3339(at.Add(48*time.Hour))))

		res := runRotate(t, RotateSecret{ConfigPath: run.path, Name: "alice", Overlap: "0", Reload: true, now: clock})
		requireQuiet(t, res, alice, bob, older)

		renewed := newValue(t, res)
		requireQuiet(t, res, renewed)
		require.NoError(t, res.err)

		info := secretOn(t, run.api, "alice")
		assert.True(t, info.Secret == renewed.Base64())
		assert.Equal(t, 1, info.RetiringKeys, "the earlier block, and nothing for the key just retired")
		assert.Contains(t, res.stderr, "reloaded the proxy through its management API at "+run.api)
	})

	t.Run("--end-overlap counts none", func(t *testing.T) {
		run := startReloadRun(t, clock, primaries, retiringBlock("alice", older, rfc3339(at.Add(48*time.Hour))))

		res := runRotate(t, RotateSecret{ConfigPath: run.path, Name: "alice", EndOverlap: true, Reload: true, now: clock})
		requireQuiet(t, res, alice, bob, older)
		require.NoError(t, res.err)
		assert.True(t, res.stdout == "", "stdout carries something")

		info := secretOn(t, run.api, "alice")
		assert.True(t, info.Secret == alice.Base64())
		assert.Zero(t, info.RetiringKeys)
		assert.Contains(t, res.stderr, "reloaded the proxy through its management API at "+run.api)
	})

	// m5′: check 1's expected primary is the written file's, so a rotation
	// written earlier without --reload is no false failure.
	t.Run("--end-overlap after a rotation written without --reload passes", func(t *testing.T) {
		run := startReloadRun(t, clock, primaries)

		first := runRotate(t, RotateSecret{ConfigPath: run.path, Name: "alice", Overlap: "24h", now: clock})
		requireQuiet(t, first, alice, bob)

		renewed := newValue(t, first)
		requireQuiet(t, first, renewed)
		require.NoError(t, first.err)
		assert.True(t, secretOn(t, run.api, "alice").Secret == alice.Base64(), "the proxy was reloaded without --reload")

		res := runRotate(t, RotateSecret{ConfigPath: run.path, Name: "alice", EndOverlap: true, Reload: true, now: clock})
		requireQuiet(t, res, alice, bob, renewed)
		require.NoError(t, res.err)

		info := secretOn(t, run.api, "alice")
		assert.True(t, info.Secret == renewed.Base64(), "the proxy serves the file's primary")
		assert.Zero(t, info.RetiringKeys)
	})

	// m5′: --prune alone reads back each pruned name still configured, and
	// nothing of a pruned name the file no longer has.
	t.Run("--prune alone passes", func(t *testing.T) {
		gone := mustGenerate(t, mtglib.SecretModeDD, "")
		bobsOld := mustGenerate(t, mtglib.SecretModeDD, "")

		run := startReloadRun(t, clock, primaries,
			retiringBlock("alice", older, rfc3339(at.Add(-time.Hour))),
			retiringBlock("carol", gone, rfc3339(at.Add(-2*time.Hour))),
			retiringBlock("bob", bobsOld, rfc3339(at.Add(24*time.Hour))))

		res := runRotate(t, RotateSecret{ConfigPath: run.path, Prune: true, Reload: true, now: clock})
		requireQuiet(t, res, alice, bob, older, gone, bobsOld)
		require.NoError(t, res.err)
		assert.True(t, res.stdout == "", "stdout carries something")

		assert.Zero(t, secretOn(t, run.api, "alice").RetiringKeys)
		assert.Equal(t, 1, secretOn(t, run.api, "bob").RetiringKeys)
		assert.Contains(t, res.stderr, "reloaded the proxy through its management API at "+run.api)
	})

	// The same read-back is a check: a pruned name the proxy counts otherwise
	// fails check 2, here because the proxy's clock is ahead.
	t.Run("--prune alone checks the previous keys of a pruned name", func(t *testing.T) {
		kept := mustGenerate(t, mtglib.SecretModeDD, "")

		run := startReloadRun(t, clockAt(at.Add(25*time.Hour)), primaries,
			retiringBlock("alice", older, rfc3339(at.Add(-time.Hour))),
			retiringBlock("alice", kept, rfc3339(at.Add(24*time.Hour))))

		res := runRotate(t, RotateSecret{ConfigPath: run.path, Prune: true, Reload: true, now: clock})
		requireQuiet(t, res, alice, bob, older, kept)
		require.Error(t, res.err)

		assert.Equal(t, notServing+`retiring_keys of "alice" differs (1 vs 0); likely: `+retiringCauses, res.err.Error())
	})
}

// A name that reads as a value is never printed (8a's m6, 9a's M2), and the
// read-back requests one in their path: a request that gets no answer is
// printed without its URL, and a name the proxy does not serve by its label.
func TestAReadBackNeverPrintsANameThatReadsAsAValue(t *testing.T) {
	const valueLike = "abcdefghijklmnopqrstuv"

	for _, tc := range []struct {
		name   string
		answer http.HandlerFunc
		want   string
	}{
		{
			name: "no answer",
			answer: func(w http.ResponseWriter, _ *http.Request) {
				conn, _, err := http.NewResponseController(w).Hijack()
				if err == nil {
					conn.Close() //nolint: errcheck
				}
			},
			want: "the file is rotated and the proxy reloaded it, but reading " + unnamed + " back got no answer (",
		},
		{
			name:   "not served",
			answer: http.NotFound,
			want: notServing + "the primary of " + unnamed + " differs (the written key, ee for old.example.com vs no " +
				"secret of that name); likely: " + primaryCauses,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mux := http.NewServeMux()
			mux.Handle("GET /stats", stubMux(everyFeature, nil))
			mux.HandleFunc("POST /reload", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
			mux.HandleFunc("GET /secrets/{name}", tc.answer)

			stub := newStubServer(t, mux)
			files := filesBehind(t, stub.addr)

			data, err := os.ReadFile(files.path)
			require.NoError(t, err)
			files.rewrite(t, strings.Replace(string(data), "\nalice = ", "\n"+valueLike+" = ", 1))

			res := runRotate(t, RotateSecret{ConfigPath: files.path, Name: valueLike, Overlap: "24h", Reload: true})
			requireQuiet(t, res, files.old()...)

			renewed := newValue(t, res)
			requireQuiet(t, res, renewed)
			require.NotContains(t, res.printed(), valueLike, "the name that reads as a value is printed")
			require.Error(t, res.err)

			assert.Contains(t, res.err.Error(), tc.want)

			// net/http retries a GET once on a reused connection that closes
			// before any answer.
			requests, _ := stub.asked()
			assert.Equal(t, []string{"GET /stats", "POST /reload", "GET /secrets/" + valueLike}, slices.Compact(requests))
		})
	}
}

// stubAPI is a management API that answers as a test says, and records what it
// was asked and with which credentials.
type stubAPI struct {
	server *httptest.Server
	addr   string

	mu       sync.Mutex
	requests []string
	auth     []string
}

// newStubAPI serves /stats with features, and POST /reload with reload.
func newStubAPI(t *testing.T, features []string, reload http.HandlerFunc) *stubAPI {
	t.Helper()

	return newStubServer(t, stubMux(features, reload))
}

// stubMux is /stats with features, and POST /reload with reload.
func stubMux(features []string, reload http.HandlerFunc) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /stats", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"features": features, "users": map[string]any{}}) //nolint: errcheck
	})

	if reload != nil {
		mux.HandleFunc("POST /reload", reload)
	}

	return mux
}

// newStubServer serves handler, recording every request first.
func newStubServer(t *testing.T, handler http.Handler) *stubAPI {
	t.Helper()

	stub := &stubAPI{}

	stub.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		stub.mu.Lock()
		stub.requests = append(stub.requests, r.Method+" "+r.URL.Path)
		stub.auth = append(stub.auth, r.Header.Get("Authorization"))
		stub.mu.Unlock()

		handler.ServeHTTP(w, r)
	}))

	// The connections first: a handler that stalls until its request ends
	// would otherwise hold Close until the client gives up.
	t.Cleanup(func() {
		stub.server.CloseClientConnections()
		stub.server.Close()
	})

	stub.addr = strings.TrimPrefix(stub.server.URL, "http://")

	return stub
}

func (s *stubAPI) asked() ([]string, []string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	return slices.Clone(s.requests), slices.Clone(s.auth)
}

// everyFeature is what a binary with secret-rotation advertises.
var everyFeature = []string{mtglib.FeatureSecretRead, mtglib.FeatureSecretRotation, mtglib.FeatureSecretsAPI}

// filesBehind is newRotateFiles with the management API at addr.
func filesBehind(t *testing.T, addr string) rotateFiles {
	t.Helper()

	files := newRotateFiles(t)

	data, err := os.ReadFile(files.path)
	require.NoError(t, err)

	files.rewrite(t, fmt.Sprintf("api-bind-to = %q\napi-token = %q\n", addr, reloadToken)+string(data))

	return files
}

// R10's pre-check, and the unreachable API: refusals before anything is
// written, and no key generated. --force goes past the missing feature, which
// is a guess, and never past an API that cannot be reached.
func TestTheReloadPreCheckRefusesBeforeWriting(t *testing.T) {
	refusedBy := func(t *testing.T, files rotateFiles, run RotateSecret, want string) {
		t.Helper()

		generated := recordGenerations(t, nil)
		before := listing(t, files.dir)

		run.ConfigPath, run.Reload = files.path, true

		res := runRotate(t, run)
		requireQuiet(t, res, files.old()...)
		require.Error(t, res.err)

		assert.Contains(t, res.err.Error(), want)
		assert.True(t, strings.HasSuffix(res.err.Error(), "nothing was written"), res.err.Error())
		assert.True(t, res.stdout == "", "stdout carries something")
		assert.Empty(t, generated.modes, "a refused run generated a key")
		assert.Equal(t, before, listing(t, files.dir), "a refused run changed the directory")
	}

	t.Run("an older binary, without secret-rotation", func(t *testing.T) {
		stub := newStubAPI(t, []string{mtglib.FeatureSecretsAPI}, func(w http.ResponseWriter, _ *http.Request) {
			t.Error("a refused run reloaded the proxy")
			w.WriteHeader(http.StatusOK)
		})

		refusedBy(t, filesBehind(t, stub.addr), RotateSecret{Name: "alice", Overlap: "24h"},
			"--reload: the running proxy does not advertise secret-rotation: it is an older binary, which ignores "+
				"the [[retiring-secret]] block and stops accepting the previous key at the reload; "+
				"upgrade it first, or give --force to reload it anyway")

		requests, auth := stub.asked()
		assert.Equal(t, []string{"GET /stats"}, requests, "the pre-check is GET /stats and nothing else")
		assert.Equal(t, []string{"Bearer " + reloadToken}, auth, "the token is the config's")
	})

	t.Run("an API that cannot be reached", func(t *testing.T) {
		closed := httptest.NewServer(http.NotFoundHandler())
		addr := strings.TrimPrefix(closed.URL, "http://")
		closed.Close()

		refusedBy(t, filesBehind(t, addr), RotateSecret{Name: "alice", Overlap: "24h"},
			"--reload: the proxy's management API at "+addr+" cannot be reached: ")
	})

	t.Run("an API that cannot be reached, with --force", func(t *testing.T) {
		closed := httptest.NewServer(http.NotFoundHandler())
		addr := strings.TrimPrefix(closed.URL, "http://")
		closed.Close()

		refusedBy(t, filesBehind(t, addr), RotateSecret{Name: "alice", Overlap: "24h", Force: true},
			"--reload: the proxy's management API at "+addr+" cannot be reached: ")
	})

	t.Run("a token the API refuses", func(t *testing.T) {
		stub := newStubServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "BODY: unauthorized", http.StatusUnauthorized)
		}))

		refusedBy(t, filesBehind(t, stub.addr), RotateSecret{Name: "alice", Overlap: "24h"},
			"--reload: GET /stats on the proxy's management API at "+stub.addr+" answered 401 Unauthorized")
	})

	t.Run("something else answering at the address", func(t *testing.T) {
		stub := newStubServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Write([]byte("<html>a web server</html>")) //nolint: errcheck
		}))

		refusedBy(t, filesBehind(t, stub.addr), RotateSecret{Name: "alice", Overlap: "24h", Force: true},
			"--reload: GET /stats on the proxy's management API at "+stub.addr+
				": the answer is not the JSON the management API sends")
	})

	t.Run("--force goes past the missing feature", func(t *testing.T) {
		stub := newStubAPI(t, []string{mtglib.FeatureSecretsAPI}, func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "no", http.StatusInternalServerError)
		})
		files := filesBehind(t, stub.addr)

		res := runRotate(t, RotateSecret{ConfigPath: files.path, Name: "alice", Overlap: "24h", Reload: true, Force: true})
		requireQuiet(t, res, files.old()...)

		renewed := newValue(t, res)
		requireQuiet(t, res, renewed)
		require.Error(t, res.err)

		requests, _ := stub.asked()
		assert.Equal(t, []string{"GET /stats", "POST /reload"}, requests)
		assert.Contains(t, res.stderr, "warning: the running proxy does not advertise secret-rotation; --force reloads "+
			"it anyway: an older binary stops accepting the previous key at the reload\n")
		assert.True(t, readSecrets(t, files.path).Secrets["alice"] == renewed, "the file is not rotated")
	})

	// The refusal of a file without an API comes before anything else the
	// reload does.
	t.Run("a dry run asks, and writes nothing", func(t *testing.T) {
		stub := newStubAPI(t, everyFeature, func(w http.ResponseWriter, _ *http.Request) {
			t.Error("a dry run reloaded the proxy")
			w.WriteHeader(http.StatusOK)
		})
		files := filesBehind(t, stub.addr)
		generated := recordGenerations(t, nil)
		before := listing(t, files.dir)

		res := runRotate(t, RotateSecret{ConfigPath: files.path, Name: "alice", Overlap: "24h", Reload: true, DryRun: true})
		requireQuiet(t, res, files.old()...)
		require.NoError(t, res.err)

		requests, _ := stub.asked()
		assert.Equal(t, []string{"GET /stats"}, requests)
		assert.Empty(t, generated.modes)
		assert.Equal(t, before, listing(t, files.dir))
		assert.Contains(t, res.stderr, "dry run: would reload the proxy through its management API at "+stub.addr+
			" and read the rotation back\n")
	})
}

// R7's reload half (m14 of the review). A refused reload is reported by its
// status line alone: the 500 body is the proxy's error text, which a CLI does
// not trust to be value-free -- here it holds the old value in every spelling.
// The file stays rotated: it is the truth, and a rollback would make the leaked
// key the primary again at the next restart.
func TestAFailedReloadPrintsOnlyTheStatusLine(t *testing.T) {
	var (
		mu   sync.Mutex
		body string
	)

	stub := newStubAPI(t, everyFeature, func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		defer mu.Unlock()

		http.Error(w, body, http.StatusInternalServerError)
	})
	files := filesBehind(t, stub.addr)

	mu.Lock()
	body = "BODY: cannot reload secrets: " + files.alice.Hex() + " " + files.alice.Base64() + " " + reloadToken
	mu.Unlock()

	res := runRotate(t, RotateSecret{ConfigPath: files.path, Name: "alice", Overlap: "24h", Reload: true})
	requireQuiet(t, res, files.old()...)

	renewed := newValue(t, res)
	requireQuiet(t, res, renewed)
	require.Error(t, res.err)

	assert.Equal(t, notServing+"POST /reload answered 500 Internal Server Error; the proxy keeps the secrets it had, "+
		"and its log says why: fix the file if it is refused, then POST /reload again, or restart the proxy", res.err.Error())
	assert.NotContains(t, res.printed(), "BODY", "the reload's body is printed")
	assert.NotContains(t, res.err.Error(), "nothing was written")

	conf := readSecrets(t, files.path)
	assert.True(t, conf.Secrets["alice"] == renewed, "the file was rolled back")
	require.Equal(t, 1, len(conf.RetiringSecrets), "the file was rolled back")
	assert.True(t, conf.RetiringSecrets[0].Secret == files.alice.Hex(), "the previous key's block is gone")
	assert.Equal(t, []string{"config.toml"}, names(listing(t, files.dir)), "a file besides the config is left")
}

// reloadTargetOf: api-bind-to, reached on loopback when it is a wildcard
// address, with the config's token; no api-bind-to is a refusal.
func TestTheReloadTargetIsTheConfigsAPI(t *testing.T) {
	t.Parallel()

	secret := mtglib.GenerateSecret("cover.example.com").Hex()

	for _, tc := range []struct {
		bind, base string
	}{
		{bind: "0.0.0.0:3129", base: "http://127.0.0.1:3129"},
		{bind: "[::]:3129", base: "http://[::1]:3129"},
		{bind: "127.0.0.2:80", base: "http://127.0.0.2:80"},
		{bind: "[::1]:8080", base: "http://[::1]:8080"},
		{bind: "192.0.2.10:3129", base: "http://192.0.2.10:3129"},
	} {
		conf, err := config.Parse([]byte(fmt.Sprintf("secret = %q\nbind-to = \"127.0.0.1:3128\"\napi-bind-to = %q\n"+
			"api-token = %q\n", secret, tc.bind, reloadToken)))
		require.NoError(t, err)

		target, err := reloadTargetOf(conf)
		require.NoError(t, err, tc.bind)
		assert.Equal(t, tc.base, target.base, tc.bind)
		assert.Equal(t, reloadToken, target.token, tc.bind)
		require.NotNil(t, target.client, tc.bind)
	}

	conf, err := config.Parse([]byte(fmt.Sprintf("secret = %q\nbind-to = \"127.0.0.1:3128\"\n", secret)))
	require.NoError(t, err)

	_, err = reloadTargetOf(conf)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--reload needs the proxy's management API, and the config sets no api-bind-to")
}

// interruptSeam catches the run's interrupt channel through notifySignals, and
// returns what delivers the first interrupt to it.
func interruptSeam(t *testing.T) func() {
	t.Helper()

	var (
		mu         sync.Mutex
		interrupts chan<- os.Signal
		notify     = notifySignals
		ignored    = signalIgnored
	)

	t.Cleanup(func() { notifySignals, signalIgnored = notify, ignored })

	signalIgnored = func(os.Signal) bool { return false }
	notifySignals = func(c chan<- os.Signal, signals ...os.Signal) {
		if slices.Contains(signals, os.Interrupt) {
			mu.Lock()
			interrupts = c
			mu.Unlock()
		}
	}

	return func() {
		mu.Lock()
		c := interrupts
		mu.Unlock()

		c <- os.Interrupt
	}
}

// rotateWithin is runRotate with a bound: a run that does not end within it
// fails the test rather than hanging it.
func rotateWithin(t *testing.T, bound time.Duration, run RotateSecret) rotateResult {
	t.Helper()

	done := make(chan rotateResult, 1)

	go func() { done <- runRotate(t, run) }()

	select {
	case res := <-done:
		return res
	case <-time.After(bound):
		t.Fatal("the run did not end: a stalled API holds it")

		return rotateResult{}
	}
}

// Task 9b's carry: the first interrupt, which the run already catches, ends a
// wait on the network too. Before the rename nothing is written; after it the
// rotation is complete in the file, the run says the reload was not finished,
// and exits 0, as an interrupt after the rename always does.
func TestAnInterruptEndsAStalledReload(t *testing.T) {
	stall := func(t *testing.T, interrupt func()) http.HandlerFunc {
		t.Helper()

		released := make(chan struct{})
		t.Cleanup(func() { close(released) })

		return func(_ http.ResponseWriter, r *http.Request) {
			interrupt()

			select {
			case <-r.Context().Done():
			case <-released:
			}
		}
	}

	t.Run("in the pre-check", func(t *testing.T) {
		interrupt := interruptSeam(t)
		generated := recordGenerations(t, nil)

		stub := newStubServer(t, stall(t, interrupt))
		files := filesBehind(t, stub.addr)
		before := listing(t, files.dir)

		res := rotateWithin(t, 10*time.Second, RotateSecret{ConfigPath: files.path, Name: "alice", Overlap: "24h", Reload: true})
		requireQuiet(t, res, files.old()...)
		require.Error(t, res.err)

		assert.Equal(t, "interrupted; nothing was written", res.err.Error())
		assert.True(t, res.stdout == "", "stdout carries something")
		assert.Empty(t, generated.modes)
		assert.Equal(t, before, listing(t, files.dir))
	})

	t.Run("in the reload, after the rename", func(t *testing.T) {
		interrupt := interruptSeam(t)

		stub := newStubAPI(t, everyFeature, stall(t, interrupt))
		files := filesBehind(t, stub.addr)

		res := rotateWithin(t, 10*time.Second, RotateSecret{ConfigPath: files.path, Name: "alice", Overlap: "24h", Reload: true})
		requireQuiet(t, res, files.old()...)

		renewed := newValue(t, res)
		requireQuiet(t, res, renewed)
		require.NoError(t, res.err, "a rotation the interrupt came too late to stop is a success")

		assert.Contains(t, res.stderr, "warning: interrupted after the file was written; the rotation is complete, "+
			"but the proxy's reload was not finished or not read back: POST /reload on its management API, or restart it\n")
		assert.NotContains(t, res.stderr, "the rotation is complete\n", "the warning says nothing of the reload")
		assert.NotContains(t, res.stderr, "reloaded the proxy")
		assert.True(t, readSecrets(t, files.path).Secrets["alice"] == renewed, "the file is not rotated")
		assert.Equal(t, []string{"config.toml"}, names(listing(t, files.dir)), "the lock or a temporary file is left")
	})
}
