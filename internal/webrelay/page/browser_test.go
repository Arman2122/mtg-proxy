package page_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/Arman2122/mtg-proxy/internal/webrelay/page"
	"github.com/stretchr/testify/require"
)

// harnessDir is the browser harness, relative to this package.
const harnessDir = "../../../test/webbridge"

// TestBridgeInABrowser runs the real generated document in a real browser
// engine, under a second Content-Security-Policy standing in for the one the
// Telegram client injects at document start.
//
// It is the only test here that can catch the failure this transport actually
// has: a page that is correct by every static reading and still does nothing
// inside the client's WebView. Everything it asserts -- the init handshake, the
// verbatim HELLO, one-frame-per-message downlink splitting, the close ladder --
// is invisible to a test that only reads the HTML.
//
// It skips rather than fails when the harness is not installed, because it needs
// Node and a browser download that a plain `go test` has no business demanding.
// Install it with `npm install` in test/webbridge.
//
// It SKIPS when the harness is not installed, because a plain `go test ./...`
// has no business demanding Node and a browser download -- and that is as true
// of the CI job that runs the whole tree as it is of a laptop.
//
// The one place it must not skip is the job that exists to run it, and that job
// says so by setting MTG_REQUIRE_BROWSER_HARNESS. There the same conditions
// become failures, because a skip on a dashboard is indistinguishable from a
// pass: for the whole of v1.1.0 and v1.1.1 nothing installed a browser, this
// test skipped silently on every run, and the accept-key defect it exists to
// catch shipped twice.
func TestBridgeInABrowser(t *testing.T) {
	t.Parallel()

	node, err := exec.LookPath("node")
	if err != nil {
		requireHarness(t, "node is not installed; see test/webbridge/README.md")
	}

	if _, err := os.Stat(filepath.Join(harnessDir, "node_modules")); err != nil {
		requireHarness(t, "browser harness is not installed; run `npm install` in test/webbridge")
	}

	bridge, err := page.New("proxy.example.test")
	require.NoError(t, err)

	doc, err := bridge.Render(testToken)
	require.NoError(t, err)

	headers := make(map[string]string, len(doc.Header))
	for key := range doc.Header {
		headers[key] = doc.Header.Get(key)
	}

	fixture, err := json.Marshal(map[string]any{
		"html":       string(doc.HTML),
		"headers":    headers,
		"capability": testToken,
	})
	require.NoError(t, err)

	path := filepath.Join(t.TempDir(), "fixture.json")
	require.NoError(t, os.WriteFile(path, fixture, 0o600))

	absolute, err := filepath.Abs(path)
	require.NoError(t, err)

	ctx, cancel := contextWithTimeout(t, 3*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, node, "harness.mjs", absolute)
	cmd.Dir = harnessDir

	output, err := cmd.CombinedOutput()
	t.Log("\n" + string(output))

	// The harness reports an unusable environment as exit 2 -- no browser
	// binary, or one Playwright will not drive. That is a skip; anything else is
	// the page failing, which is the whole point of the test.
	var exit *exec.ExitError
	if errors.As(err, &exit) && exit.ExitCode() == 2 {
		requireHarness(t,
			"no usable browser: run `npx playwright install chromium-headless-shell` in test/webbridge")
	}

	require.NoError(t, err, "the bridge page failed in a real browser")
}

// requireHarness skips when the browser harness is merely absent, and fails when
// something has declared that it must be there.
//
// Deliberately NOT keyed on CI. Every job in a GitHub Actions run has CI set,
// including the one that runs the whole tree without installing a browser, so
// using it would turn an honest skip into a failure in a job that never asked
// for the harness. Only the job built to run it sets
// MTG_REQUIRE_BROWSER_HARNESS, and only there is a missing browser a defect
// rather than a fact.
func requireHarness(t *testing.T, reason string) {
	t.Helper()

	if os.Getenv("MTG_REQUIRE_BROWSER_HARNESS") != "" {
		t.Fatalf("this job exists to run the browser harness, but %s", reason)
	}

	t.Skip(reason)
}

func contextWithTimeout(t *testing.T, d time.Duration) (context.Context, context.CancelFunc) {
	t.Helper()

	return context.WithTimeout(t.Context(), d)
}
