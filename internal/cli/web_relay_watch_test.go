package cli

import (
	"os"
	"testing"
	"time"

	"github.com/Arman2122/mtg-proxy/internal/utils"
	"github.com/Arman2122/mtg-proxy/internal/webrelay"
	"github.com/stretchr/testify/require"
)

// watchedRelay is a relay built from a one-client file, with its reloader
// driven by hand: tick() is what the real ticker calls, so every test here is
// the running relay's own code path with the clock taken out.
type watchedRelay struct {
	dir      string
	path     string
	origin   *webrelay.Origin
	counters *webrelay.Counters
	reloader *profileReloader
	log      *recordingLogger
}

func newWatchedRelay(t *testing.T) *watchedRelay {
	t.Helper()

	dir := t.TempDir()
	path := writeReloadConfig(t, dir, nil, "", oneSecret)

	conf, err := utils.ReadConfig(path)
	require.NoError(t, err)
	require.NoError(t, conf.ValidateWeb())

	log := newRecordingLogger()
	counters := webrelay.NewCounters(time.Now())

	origin, _, err := buildOrigin(conf, counters, log)
	require.NoError(t, err)

	structure, err := webStructure(conf)
	require.NoError(t, err)

	return &watchedRelay{
		dir:      dir,
		path:     path,
		origin:   origin,
		counters: counters,
		reloader: newProfileReloader(conf, path, origin, counters, structure, log),
		log:      log,
	}
}

func (w *watchedRelay) ticks(n int) {
	for range n {
		w.reloader.tick()
	}
}

func (w *watchedRelay) stats() webrelay.RelayStats {
	return w.counters.Snapshot(time.Now(), 0, 0)
}

// The relay learns about a new client from the file alone. This is the test
// that fails if the watcher is removed: nothing here sends a signal.
func TestAChangedFileIsAppliedWithoutASignal(t *testing.T) {
	t.Parallel()

	w := newWatchedRelay(t)

	writeReloadConfig(t, w.dir, nil, "", twoSecrets)
	require.False(t, servesBridge(t, w.origin, w.path, "bob"), "an unconfigured client was already being served")

	w.ticks(2)

	require.Equal(t, 2, w.origin.Profiles(), "the added client never reached the running relay")
	require.True(t, servesBridge(t, w.origin, w.path, "bob"), "the added client is counted but not served")
	require.True(t, servesBridge(t, w.origin, w.path, "alice"), "the existing client stopped being served")
	require.Equal(t, int64(1), w.stats().Reloads)
	require.Zero(t, w.stats().ReloadFails)
	require.Empty(t, w.log.recorded(), "a clean reload must report nothing")
}

// A change is applied only once it has held still across two looks. The panel
// writes the file and then tells the proxy, and a read that lands between
// those two steps sees half a file -- which must be neither applied nor
// counted as a failure, because it is not one.
func TestAChangeMustSettleBeforeItIsApplied(t *testing.T) {
	t.Parallel()

	w := newWatchedRelay(t)

	// Half a file, as a save in progress looks from outside.
	require.NoError(t, os.WriteFile(w.path, []byte("[web] enabled = tr"), 0o600))
	w.ticks(1)

	// The save completes before the next look.
	writeReloadConfig(t, w.dir, nil, "", twoSecrets)
	w.ticks(1)

	require.Equal(t, 1, w.origin.Profiles(), "applied before the file had settled")
	require.Zero(t, w.stats().ReloadFails, "a save in progress was counted as a failed reload")

	w.ticks(1)

	require.Equal(t, 2, w.origin.Profiles(), "a settled change was not applied")
	require.Equal(t, int64(1), w.stats().Reloads)
	require.Zero(t, w.stats().ReloadFails)
}

// A broken file is refused once, loudly, and the running set is kept. When it
// is fixed, the fix is applied. In between, the same broken file is not
// refused again on every tick: the failure counter has to stay trustworthy,
// and a number that climbs by itself every two seconds is not.
func TestABrokenFileFailsOnceThenAppliesWhenFixed(t *testing.T) {
	t.Parallel()

	w := newWatchedRelay(t)

	require.NoError(t, os.WriteFile(w.path, []byte("this is not toml at all ]["), 0o600))
	w.ticks(2)

	require.Equal(t, 1, w.origin.Profiles(), "a broken file emptied the registry")
	require.Equal(t, int64(1), w.stats().ReloadFails, "a broken file that settled was not reported")
	require.NotEmpty(t, w.log.recorded(), "a failed reload said nothing")

	w.ticks(10)
	require.Equal(t, int64(1), w.stats().ReloadFails, "the same broken file was refused again on a later tick")

	writeReloadConfig(t, w.dir, nil, "", twoSecrets)
	w.ticks(2)

	require.Equal(t, 2, w.origin.Profiles(), "the fixed file was not applied")
	require.Equal(t, int64(1), w.stats().Reloads)
	require.Equal(t, int64(1), w.stats().ReloadFails)
}

// A structural change is refused whole, once.
func TestARefusedChangeIsNotRetriedEveryTick(t *testing.T) {
	t.Parallel()

	w := newWatchedRelay(t)

	writeReloadConfig(t, w.dir, map[string]string{"host": `"other.example.com"`}, "", twoSecrets)
	w.ticks(2)

	require.Equal(t, 1, w.origin.Profiles(), "a structural change was partly applied")
	require.Equal(t, int64(1), w.stats().ReloadFails)

	w.ticks(10)
	require.Equal(t, int64(1), w.stats().ReloadFails, "the same refused file was refused again on a later tick")
}

// A file that changed without changing the profiles -- a comment, a limit, the
// proxy's own settings -- is not a reload, and is not reported as one.
func TestAnEditThatChangesNoProfileIsNotAReload(t *testing.T) {
	t.Parallel()

	w := newWatchedRelay(t)

	writeReloadConfig(t, w.dir, nil, "", oneSecret+"  # edited by hand")
	w.ticks(2)

	require.Equal(t, 1, w.origin.Profiles())
	require.Zero(t, w.stats().Reloads, "an edit that changed no profile was reported as a reload")
	require.Zero(t, w.stats().ReloadFails)
}

// A signal is different: an operator who sent one is asking whether it landed,
// and the counter is how they find out. So it is counted even when it changed
// nothing.
func TestASignalReloadIsCountedEvenWhenNothingChanged(t *testing.T) {
	t.Parallel()

	w := newWatchedRelay(t)

	w.reloader.reload(reloadTriggerSignal)

	require.Equal(t, 1, w.origin.Profiles())
	require.Equal(t, int64(1), w.stats().Reloads, "a signal that landed was not reported")
}

// The two triggers share one memory. A change the signal applied is not
// applied a second time when the watcher notices the same file a moment later,
// so a supervisor's reload hook does not double every count.
func TestTheWatcherDoesNotReapplyWhatASignalApplied(t *testing.T) {
	t.Parallel()

	w := newWatchedRelay(t)

	writeReloadConfig(t, w.dir, nil, "", twoSecrets)
	w.reloader.reload(reloadTriggerSignal)
	require.Equal(t, 2, w.origin.Profiles())
	require.Equal(t, int64(1), w.stats().Reloads)

	w.ticks(2)

	require.Equal(t, int64(1), w.stats().Reloads, "the watcher re-applied a change the signal had already applied")
}

// A file that is missing -- mid-rename, or gone -- is not a failed reload:
// nothing was attempted. And whatever was pending is forgotten, so a file that
// comes back has to hold still again before it is trusted.
func TestAMissingFileIsNotAFailure(t *testing.T) {
	t.Parallel()

	w := newWatchedRelay(t)

	writeReloadConfig(t, w.dir, nil, "", twoSecrets)
	w.ticks(1)

	require.NoError(t, os.Remove(w.path))
	w.ticks(1)

	require.Equal(t, 1, w.origin.Profiles())
	require.Zero(t, w.stats().ReloadFails, "a file that was not there was counted as a failed reload")

	writeReloadConfig(t, w.dir, nil, "", twoSecrets)
	w.ticks(1)
	require.Equal(t, 1, w.origin.Profiles(), "a file that came back was trusted before it had settled")

	w.ticks(1)
	require.Equal(t, 2, w.origin.Profiles())
}
