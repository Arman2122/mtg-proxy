package cli

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/Arman2122/mtg-proxy/internal/config"
	"github.com/Arman2122/mtg-proxy/internal/rotation"
	"github.com/Arman2122/mtg-proxy/mtglib"
)

// RotateSecret is `mtg-proxy rotate-secret` (spec §7): it gives a secret a new
// key and keeps the previous one accepted until an overlap ends, by an edit of
// the config file -- the only place a previous key lives (D1). The edit is
// internal/rotation's; this is its I/O: the flags, the lock, the checks and
// the atomic write (§7.4), what is printed (§7.2), and with --reload the
// running proxy's reload and read-back (§7.5, rotate_secret_reload.go) -- the
// one network access the command makes.
//
// stdout carries one line, the new value, and only after a rotation was
// written. Nothing the command prints, on either stream or in its error, holds
// a previous value or key: the edit's refusals, warnings and summary are
// value-free by construction, and this file formats no Secret but the new one,
// on stdout.
type RotateSecret struct {
	ConfigPath string `kong:"arg,required,type='existingfile',help='Path to the configuration file.',name='config-path'"`                                                                                    //nolint: lll
	Name       string `kong:"arg,optional,help='The secret to rotate, or whose overlap ends: a name from [secrets], or default for the single top-level secret. Not given with --prune alone.',name='name'"` //nolint: lll
	Overlap    string `kong:"help='How long the previous key stays accepted, a Go duration from 0 to 720h (0 retires it at once). Required for a rotation.',name='overlap'"`                                 //nolint: lll
	Host       string `kong:"help='ee only: the fronting hostname of the new key. Without it the current one is kept.',name='host'"`                                                                         //nolint: lll
	EndOverlap bool   `kong:"help='Remove every [[retiring-secret]] block of the name: its previous keys stop being accepted at the reload.',name='end-overlap'"`                                            //nolint: lll
	Prune      bool   `kong:"help='Remove every expired [[retiring-secret]] block, of any name.',name='prune'"`
	DryRun     bool   `kong:"help='Print on stderr what the run would do, and write nothing.',name='dry-run'"`
	Reload     bool   `kong:"help='Reload the running proxy through its management API (api-bind-to) and read the rotation back.',name='reload'"`                                                 //nolint: lll
	Force      bool   `kong:"help='Proceed although the file looks like one the Penhoon panel generates, or (with --reload) the running proxy does not advertise secret-rotation.',name='force'"` //nolint: lll

	// out is where the new value goes, errOut everything for people, and now
	// the run's one instant; Run points them at stdout, stderr and the wall
	// clock when they are not set.
	out    io.Writer
	errOut io.Writer
	now    func() time.Time
}

// generateSecret makes the new key: mtglib.GenerateSecretMode, a variable so
// that a test can count the calls -- a dry run, a no-op and every refusal make
// none -- and run something between the run's read of the file and its write.
var generateSecret = mtglib.GenerateSecretMode

// nothingWritten ends every refusal, and every failure before the rename (§7.7).
const nothingWritten = "nothing was written"

// notifySignals, stopSignals and signalIgnored are signal.Notify, signal.Stop
// and signal.Ignored, variables so that a test can deliver an interrupt at a
// chosen point of a run, and say which signals the run started with ignored.
var (
	notifySignals = signal.Notify
	stopSignals   = signal.Stop
	signalIgnored = signal.Ignored
)

// errInterrupted is an interrupt that arrived before the rename: the run
// stops there, and its defers remove the temporary file and the lock.
var errInterrupted = errors.New("interrupted; nothing was written")

// errOverlapMissing is a rotation without --overlap: for a security action the
// grant must be stated (D32).
var errOverlapMissing = errors.New("say how long the previous key stays accepted: " +
	"--overlap 24h, or --overlap 0 to retire it at once")

// panelRefusal is §7.6's: the panel rewrites the file from its own records,
// with the leaked key as the primary.
const panelRefusal = "this looks like a config the Penhoon panel generates (…/mtproto/mtg-N.toml); the panel " +
	"rewrites it from its own records and would make the old key the primary again; " +
	"re-key the client in the panel instead"

// panelFileName is the base name of a config the panel writes, mtg-<id>.toml.
var panelFileName = regexp.MustCompile(`^mtg-[0-9]+\.toml$`)

// unnamed is what is printed for a name that reads as a secret value, which is
// never echoed (rotation.Summary.Name is empty then).
const unnamed = "the secret asked for (its name reads as a secret value and is not shown)"

func (r *RotateSecret) Run(_ *CLI, _ string) error {
	if r.out == nil {
		r.out = os.Stdout
	}

	if r.errOut == nil {
		r.errOut = os.Stderr
	}

	if r.now == nil {
		r.now = time.Now
	}

	if signals := pipeSignals(); len(signals) > 0 {
		pipe := make(chan os.Signal, 1)

		notifySignals(pipe, signals...)
		defer stopSignals(pipe)
	}

	written, err := r.run()
	if err == nil || written {
		return err
	}

	if strings.Contains(err.Error(), nothingWritten) {
		return err
	}

	return fmt.Errorf("%w; %s", err, nothingWritten)
}

// say writes one line for people. It is best-effort output to a terminal, so
// a failed write is not consulted, as in doctor.
func (r *RotateSecret) say(format string, args ...any) {
	fmt.Fprintf(r.errOut, format+"\n", args...) //nolint: errcheck
}

// run is the flow of the task's plan, steps 1 to 12. It reports whether the
// file was written: after that no error may say "nothing was written".
func (r *RotateSecret) run() (bool, error) {
	// 1. The flags.
	overlap, err := r.checkFlags()
	if err != nil {
		return false, err
	}

	rotate := r.Name != "" && !r.EndOverlap

	// The run's one instant: wall time only, as every until it is judged
	// against is.
	now := r.now().Round(0)

	// 2. The panel heuristic, on the path as given.
	if err := r.checkPanelPath(r.ConfigPath); err != nil {
		return false, err
	}

	// 3. The target: a symlink's is written, next to it go the lock and the
	// temporary file, and it is judged by the heuristic too.
	target, err := filepath.EvalSymlinks(r.ConfigPath)
	if err != nil {
		return false, fmt.Errorf("cannot resolve %s: %w", r.ConfigPath, err)
	}

	if err := r.checkPanelPath(target); err != nil {
		return false, err
	}

	// 4. The file must be writable. Whether its directory can take a new
	// file is the lock's own creation, the first new file the run puts there.
	info, err := checkWritable(target)
	if err != nil {
		return false, err
	}

	names := linkCount(target, info)

	// From here the first interrupt (Ctrl-C, SIGTERM, or SIGHUP from a
	// dropped session) does not kill the process: it is noted, the run stops
	// cleanly at the rename if it came before it, and the defers below -- the
	// lock's removal first -- run either way. No cleanup is done inside a
	// signal handler. The run is milliseconds of local file work; if it is
	// stuck in the file system instead, a second interrupt kills it as by
	// default, which leaves the lock (and before the rename the temporary
	// file) for the next run's refusal to name. Two interrupts within
	// microseconds of each other can both be absorbed; a third kills.
	//
	// A signal the run started with ignored -- SIGHUP under nohup, Ctrl-C in a
	// background job -- is not asked for: Notify would make it count, and
	// abort the run. With every one ignored nothing is asked for at all, as
	// Notify with no signal relays them all.
	//
	// The first interrupt also cancels ctx, which every wait of --reload on the
	// network runs under: a stalled management API ends there, and is never
	// waited out. Before the rename that is the same clean stop; after it, the
	// rotation is complete and the run says the reload was not finished.
	notify, stop, ignored := notifySignals, stopSignals, signalIgnored
	interrupts := make(chan os.Signal, 1)
	finished := make(chan struct{})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var caught atomic.Bool

	var asked []os.Signal

	for _, sig := range []os.Signal{os.Interrupt, syscall.SIGTERM, syscall.SIGHUP} {
		if !ignored(sig) {
			asked = append(asked, sig)
		}
	}

	if len(asked) > 0 {
		notify(interrupts, asked...)
	}

	defer func() {
		close(finished)
		stop(interrupts)
	}()

	go func() {
		select {
		case <-interrupts:
			caught.Store(true)
			cancel()
			stop(interrupts) // the default disposition again: a second interrupt kills
		case <-finished:
		}
	}()

	interrupted := caught.Load

	// 5. The lock, held until the run ends.
	lock, err := takeLock(target, now)
	if err != nil {
		return false, err
	}

	defer func() {
		if err := os.Remove(lock); err != nil {
			r.say("warning: cannot remove the lock %s: %s; remove it by hand", lock, err.Error())
		}
	}()

	// 6. Read, judge, and warn about the problems the file already has.
	doc, err := os.ReadFile(target)
	if err != nil {
		return false, fmt.Errorf("cannot read %s: %w", target, err)
	}

	readSum := sha256.Sum256(doc)

	conf, err := config.Parse(doc)
	if err != nil {
		// Flattened, so that nothing above can reach the parser's error and
		// its String(), which quotes the document.
		return false, errors.New("the config does not load: " + explainConfigError(err).Error())
	}

	// --reload needs the management API the file names (§7.5).
	var api reloadTarget

	if r.Reload {
		if api, err = reloadTargetOf(conf); err != nil {
			return false, err
		}
	}

	req := rotation.Request{Name: r.Name, Rotate: rotate, EndOverlap: r.EndOverlap, Prune: r.Prune, Now: now}
	if rotate && overlap > 0 {
		req.Until = now.Add(overlap)
	}

	// The edit's refusals are written for the operator, and passed on as
	// they are.
	prepared, err := rotation.Prepare(doc, req)
	if err != nil {
		return false, err
	}

	for _, line := range prepared.Warnings() {
		r.say("warning: %s", line)
	}

	summary := prepared.Summary()

	mode, host, err := r.newKeyShape(prepared.Primary(), summary, rotate)
	if err != nil {
		return false, err
	}

	if summary.NoOp {
		r.say("%s", r.noOp(summary))

		return false, nil
	}

	// --reload's question to the running proxy, before a key is generated or
	// a byte written: is it there, and does it know the table (§7.5)?
	var features apiFeatures

	if r.Reload {
		features, err = api.preCheck(ctx, r.Force)

		switch {
		case err != nil && interrupted():
			return false, errInterrupted
		case err != nil:
			return false, err
		case features.forced:
			r.say("warning: the running proxy does not advertise %s; --force reloads it anyway: "+
				"an older binary stops accepting the previous key at the reload", mtglib.FeatureSecretRotation)
		}
	}

	report := r.report(summary, rotate, overlap, conf.Web.Enabled.Get(false))

	// 7. A dry run stops here: no key, no write.
	if r.DryRun {
		for _, line := range report(wouldDo) {
			r.say("dry run: %s", line)
		}

		if r.Reload {
			r.say("dry run: would reload the proxy through its management API at %s and read the rotation back",
				api.addr())
		}

		r.say("dry run: %s, and no key was generated", nothingWritten)

		return false, nil
	}

	// 8, 9. The new key, in the current primary's mode and host, and the
	// edit, verified by re-parse inside Apply.
	var newPrimary mtglib.Secret

	if rotate {
		if newPrimary, err = generateSecret(mode, host); err != nil {
			return false, fmt.Errorf("cannot generate the new key: %w", err)
		}
	}

	edited, err := prepared.Apply(newPrimary)
	if err != nil {
		return false, err
	}

	// 10, 11. The atomic write; just before its rename, an interrupt stops
	// the run and the hash check aborts on another writer.
	beforeRename := func() error {
		if interrupted() {
			return errInterrupted
		}

		return nil
	}

	if err := writeAtomically(target, info, edited, readSum, beforeRename); err != nil {
		return false, err
	}

	syncErr := syncDir(filepath.Dir(target))

	// 12. The new value, once, on stdout, right after the rename and its
	// directory sync; then what happened, for people, on stderr; then, with
	// --reload, the reload and what it read back. The value comes first (Task
	// 10's review, M-5; final review B, n-1): the two streams are separate, so a
	// stderr that blocks -- a full pipe nobody drains -- does not hold it back,
	// and a run killed while it waits there or while the API stalls -- by a
	// second interrupt, kill or a closed terminal -- has printed it. The file
	// holds it whatever happens after.
	var printErr error

	if rotate {
		if _, err := fmt.Fprintln(r.out, prepared.ValueText(newPrimary)); err != nil {
			printErr = fmt.Errorf("the file is written, but the new value could not be printed: %w; "+
				"mtg-proxy access %s shows it", err, r.ConfigPath)
		}
	}

	if syncErr != nil {
		r.say("warning: the file is written, but its directory could not be synced: %s", syncErr.Error())
	}

	for _, line := range report(done) {
		r.say("%s", line)
	}

	if names > 1 {
		r.say("warning: the config has %d names (hard links); the others keep the previous file: replace them by hand",
			names)
	}

	var reloadErr error

	if r.Reload {
		reloadErr = r.reload(ctx, api, features, conf, edited, summary)

		if rotate {
			r.say("links: mtg-proxy access %s", r.ConfigPath)
		}
	}

	// An interrupt after the rename stops nothing: the rotation is complete,
	// and exiting non-zero would invite a second one. It is said, and the run
	// ends as the success it is. One that cut --reload's reload or read-back
	// short leaves the proxy unconfirmed, which is said instead -- and when the
	// read-back had already proven failures for earlier names, those are still
	// the run's error (Task 10's second review, N-D).
	reloadCut := reloadErr != nil && interrupted() && errors.Is(reloadErr, context.Canceled)

	var proven *readBackCut
	if reloadCut && !errors.As(reloadErr, &proven) {
		reloadErr = nil
	}

	defer func() {
		switch {
		case reloadCut:
			r.say("warning: interrupted after the file was written; the rotation is complete, but the proxy's " +
				"reload was not finished or not read back: POST /reload on its management API, or restart it")
		case interrupted():
			r.say("warning: interrupted after the file was written; the rotation is complete")
		}
	}()

	return true, errors.Join(printErr, reloadErr)
}

// reload is --reload after the write (§7.5): the proxy reloads, and what it
// serves of each name the run touched is read back against the written bytes,
// parsed once here. It says so when all of it holds, and returns what did not;
// the file is never rolled back. before is the file as the run read it, so
// that the names whose expired blocks --prune removed can be told; features is
// what the pre-check learned of the proxy.
func (r *RotateSecret) reload(ctx context.Context, api reloadTarget, features apiFeatures, before *config.Config,
	written []byte, summary rotation.Summary,
) error {
	// Nothing more is asked of the API after this run.
	defer api.client.CloseIdleConnections()

	after, err := config.Parse(written)
	if err != nil {
		return fmt.Errorf("internal error: the file written does not parse again: %w", err)
	}

	back := readBack{
		named:    r.Name,
		pruned:   prunedNames(before, after, r.Name),
		features: features,
		label: func(name string) string {
			switch {
			case name == r.Name:
				return label(summary.Name)
			case config.ReadsAsAValue(name):
				return "a secret whose name reads as a secret value (not shown)"
			default:
				return fmt.Sprintf("%q", name)
			}
		},
	}

	if err := api.reloadAndCheck(ctx, after, back, summary.Until, r.now); err != nil {
		return err
	}

	r.say("reloaded the proxy through its management API at %s; it serves the file as written", api.addr())

	return nil
}

// checkFlags is §7.1: one of the three forms, and an overlap from 0 to 720h
// for a rotation, which it returns. No refusal echoes the name, which may read
// as a value.
func (r *RotateSecret) checkFlags() (time.Duration, error) {
	switch {
	case r.Overlap != "" && r.EndOverlap:
		return 0, errors.New("--overlap and --end-overlap cannot be given together: --overlap rotates the key, " +
			"--end-overlap ends the overlap of an earlier rotation")
	case r.Name == "" && r.Overlap != "":
		return 0, errors.New("a rotation needs a name: rotate-secret <config> <name> --overlap 24h")
	case r.Name == "" && r.EndOverlap:
		return 0, errors.New("--end-overlap needs a name: rotate-secret <config> <name> --end-overlap")
	case r.Name == "" && !r.Prune:
		return 0, errors.New("name the secret to rotate (rotate-secret <config> <name> --overlap 24h), " +
			"or give --prune to remove the expired [[retiring-secret]] blocks")
	case r.Host != "" && (r.Name == "" || r.EndOverlap):
		return 0, errors.New("--host is for a rotation only: it is the fronting hostname of the new key")
	case r.Name != "" && !r.EndOverlap && r.Overlap == "":
		return 0, errOverlapMissing
	case r.Overlap == "":
		return 0, nil
	}

	overlap, err := time.ParseDuration(r.Overlap)

	switch {
	case err != nil:
		return 0, errors.New("--overlap takes a Go duration such as 24h, 90m or 0")
	case overlap < 0:
		return 0, errors.New("--overlap cannot be negative: say how long the previous key stays accepted, " +
			"or 0 to retire it at once")
	case overlap > mtglib.MaxRetiringOverlap:
		return 0, errors.New("--overlap is at most 720h: an overlap is a migration window, not a second key")
	case overlap > 0 && overlap < time.Second:
		return 0, errors.New("--overlap below 1s cannot be written: an until is whole seconds; " +
			"give at least 1s, or 0 to retire the key at once")
	}

	return overlap, nil
}

// checkPanelPath is §7.6's guess: …/mtproto/mtg-<digits>.toml is the panel's,
// unless --force says otherwise.
func (r *RotateSecret) checkPanelPath(path string) error {
	if r.Force {
		return nil
	}

	if abs, err := filepath.Abs(path); err == nil {
		path = abs
	}

	if panelFileName.MatchString(filepath.Base(path)) && filepath.Base(filepath.Dir(path)) == "mtproto" {
		return errors.New(panelRefusal)
	}

	return nil
}

// newKeyShape is the mode and host the new key is generated with: the current
// primary's (D22), or --host's hostname for ee. --host with dd or plain is a
// refusal: neither carries a hostname.
func (r *RotateSecret) newKeyShape(primary mtglib.Secret, summary rotation.Summary,
	rotate bool,
) (mtglib.SecretMode, string, error) {
	if !rotate {
		return 0, "", nil
	}

	if primary.Mode != mtglib.SecretModeFakeTLS {
		if r.Host != "" {
			return 0, "", fmt.Errorf("--host is for an ee secret only: %s is a %s secret, which carries no hostname",
				label(summary.Name), primary.Mode.String())
		}

		return primary.Mode, "", nil
	}

	if r.Host != "" {
		return primary.Mode, r.Host, nil
	}

	return primary.Mode, primary.Host, nil
}

// label is a name as the run prints it: quoted, or a phrase when the edit
// withheld it.
func label(name string) string {
	if name == "" {
		return unnamed
	}

	return fmt.Sprintf("%q", name)
}

// noOp is §7.7's line for a run with nothing to do.
func (r *RotateSecret) noOp(summary rotation.Summary) string {
	switch {
	case r.EndOverlap && r.Prune:
		return fmt.Sprintf("nothing to do: %s has no [[retiring-secret]] block, and no block has expired, in %s; %s",
			label(summary.Name), r.ConfigPath, nothingWritten)
	case r.EndOverlap:
		return fmt.Sprintf("nothing to do: %s has no [[retiring-secret]] block in %s; %s",
			label(summary.Name), r.ConfigPath, nothingWritten)
	default:
		return fmt.Sprintf("nothing to do: no [[retiring-secret]] block has expired in %s; %s",
			r.ConfigPath, nothingWritten)
	}
}

// phrasing is the verbs of the summary, for a run that did it or a dry run
// that would.
type phrasing struct {
	rotated, accepted, notKept, removed, ended, pruned, change string
	afterwards                                                 bool // the reload and links lines
}

var (
	done = phrasing{
		rotated: "rotated", accepted: "is accepted", notKept: "is not kept", removed: "removed",
		ended: "ended", pruned: "pruned", change: "change now", afterwards: true,
	}
	wouldDo = phrasing{
		rotated: "would rotate", accepted: "would be accepted", notKept: "would not be kept", removed: "would remove",
		ended: "would end", pruned: "would prune", change: "would change at once",
	}
)

// report is §7.2's stderr for the run: what it did (or would do), never a
// value -- names and instants only, as the edit's Summary gives them.
func (r *RotateSecret) report(summary rotation.Summary, rotate bool, overlap time.Duration,
	web bool,
) func(phrasing) []string {
	return func(p phrasing) []string {
		var lines []string

		switch {
		case rotate:
			lines = append(lines, fmt.Sprintf("%s %s in %s", p.rotated, label(summary.Name), r.ConfigPath))

			if summary.Until.IsZero() {
				lines = append(lines, fmt.Sprintf("the previous key %s (--overlap 0): "+
					"it stops being accepted when the proxy reloads or restarts", p.notKept))
			} else {
				lines = append(lines, fmt.Sprintf("the previous key %s until %s (%s from now)",
					p.accepted, summary.Until.UTC().Format(time.RFC3339), overlap.String()))
			}
		case r.EndOverlap:
			lines = append(lines, fmt.Sprintf("%s the overlap of %s in %s: "+
				"its previous keys stop being accepted when the proxy reloads or restarts",
				p.ended, label(summary.Name), r.ConfigPath))
		default:
			lines = append(lines, fmt.Sprintf("%s the expired [[retiring-secret]] blocks of %s", p.pruned, r.ConfigPath))
		}

		for _, removed := range summary.Removed {
			name := "name not shown"
			if removed.Name != "" {
				name = fmt.Sprintf("name %q", removed.Name)
			}

			until := "until not an RFC 3339 instant"
			if removed.Until != "" {
				until = "until " + removed.Until
			}

			lines = append(lines, fmt.Sprintf("%s a [[retiring-secret]] block: %s, %s", p.removed, name, until))
		}

		if rotate && web {
			lines = append(lines, fmt.Sprintf("WEB links of %s %s; the WEB transport has no overlap (see WEB-Proxy-Setup)",
				label(summary.Name), p.change))
		}

		// With --reload, the run reloads the proxy and says how that went
		// before the links line.
		if p.afterwards && !r.Reload {
			lines = append(lines,
				"the running proxy does not know yet: POST /reload on its management API, or restart it")

			if rotate {
				lines = append(lines, "links: mtg-proxy access "+r.ConfigPath)
			}
		}

		return lines
	}
}
