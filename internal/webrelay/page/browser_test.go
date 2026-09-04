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
// Locally it SKIPS when the harness is not installed, because a plain `go test`
// has no business demanding Node and a browser download. Under CI it does the
// opposite and FAILS, because a skip there is indistinguishable from a pass and
// that is not a theoretical concern: for the whole of v1.1.0 and v1.1.1 no
// workflow installed a browser, this test skipped silently on every run, and
// the accept-key defect it exists to catch shipped twice. An environment that
// sets CI has asked for the real thing.
func TestBridgeInABrowser(t *testing.T) {
	t.Parallel()

	node, err := exec.LookPath("node")
	if err != nil {
		skipUnlessCI(t, "node is not installed; see test/webbridge/README.md")
	}

	if _, err := os.Stat(filepath.Join(harnessDir, "node_modules")); err != nil {
		skipUnlessCI(t, "browser harness is not installed; run `npm install` in test/webbridge")
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
		skipUnlessCI(t,
			"no usable browser: run `npx playwright install chromium-headless-shell` in test/webbridge")
	}

	require.NoError(t, err, "the bridge page failed in a real browser")
}

// skipUnlessCI skips a missing harness locally and fails it under CI.
//
// The asymmetry is the point. Locally, demanding Node and a browser download
// from anyone running `go test ./...` would be rude. Under CI the harness is
// installed on purpose, so its absence means the job is not running what it
// believes it is running -- and a silent skip there reads as a pass on every
// dashboard, which is exactly how this test managed to protect nothing through
// two releases.
func skipUnlessCI(t *testing.T, reason string) {
	t.Helper()

	if os.Getenv("CI") != "" {
		t.Fatalf("the browser harness must run in CI, but %s", reason)
	}

	t.Skip(reason)
}

func contextWithTimeout(t *testing.T, d time.Duration) (context.Context, context.CancelFunc) {
	t.Helper()

	return context.WithTimeout(t.Context(), d)
}
