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
// NOTHING RUNS THIS AUTOMATICALLY. No workflow installs Node or a browser, so
// in CI it skips, every time, silently -- a skip is not a failure and the job
// stays green. This comment used to claim CI ran it as its own job, which was
// never true, and the claim is worse than the gap: it is why the accept-key
// defect in v1.1.2 was looked for everywhere except the one layer that had
// never actually executed. Run it by hand before shipping a change to the
// bridge, and read a green build as saying nothing about this file.
func TestBridgeInABrowser(t *testing.T) {
	t.Parallel()

	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is not installed; see test/webbridge/README.md")
	}

	if _, err := os.Stat(filepath.Join(harnessDir, "node_modules")); err != nil {
		t.Skip("browser harness is not installed; run `npm install` in test/webbridge")
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
		t.Skip("no usable browser: run `npx playwright install chromium-headless-shell` in test/webbridge")
	}

	require.NoError(t, err, "the bridge page failed in a real browser")
}

func contextWithTimeout(t *testing.T, d time.Duration) (context.Context, context.CancelFunc) {
	t.Helper()

	return context.WithTimeout(t.Context(), d)
}
