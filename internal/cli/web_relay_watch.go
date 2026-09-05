package cli

import (
	"crypto/sha256"
	"os"
	"slices"
	"time"

	"github.com/Arman2122/mtg-proxy/internal/config"
	"github.com/Arman2122/mtg-proxy/internal/utils"
	"github.com/Arman2122/mtg-proxy/internal/webrelay"
	"github.com/Arman2122/mtg-proxy/mtglib"
)

// webWatchInterval is how often the relay looks at its config file.
//
// The file is the source of truth for who may connect: the panel writes it and
// then tells the proxy, and the proxy's own reload re-reads it. A relay that
// only reloaded on a signal was a second source of truth that had to be told
// separately, and every path that forgot to tell it left a new client's WEB
// link answered by the cover site -- which, from that client's side, is
// indistinguishable from the censorship the relay exists to get around.
//
// Two seconds is far below what a person notices between saving a client and
// sending them a link, and reading one small file that often costs nothing.
// The file is hashed rather than stat'ed, because an editor that rewrites a
// file in place can leave the size and, on a coarse clock, the mtime alone.
const webWatchInterval = 2 * time.Second

// What asked for a reload. It is on the log line so an operator can tell a
// change the relay found from one they sent, and it decides one thing: whether
// a reload that found nothing to change is still reported as a reload.
const (
	reloadTriggerSignal = "signal"
	reloadTriggerFile   = "file"
)

// profileReloader is everything a reload of the relay's profile set needs, and
// the one thing a reload changes: the set being served now.
//
// One instance, driven from one goroutine, so two reloads can never interleave
// whichever way they were triggered.
type profileReloader struct {
	configPath string
	origin     *webrelay.Origin
	counters   *webrelay.Counters
	structure  string
	log        mtglib.Logger

	// current is the last set applied, in profile order. A file that changed
	// without changing it -- a comment, a limit, the proxy's own settings -- is
	// not a reload, and must not be reported as one.
	current []mtglib.Secret

	// The watcher's memory of the file. pending is the content seen on the
	// previous tick, so a change is applied only once it has held still across
	// two of them: the panel writes the file and then tells the proxy, and a
	// read that lands between those two steps sees half a file. attempted is
	// the last content a reload was run for, whatever the outcome and
	// whichever trigger asked, so a file the reload refused is refused once --
	// not again on the next tick because a signal was what refused it, and not
	// on every tick until someone fixes it.
	pending    [sha256.Size]byte
	hasPending bool
	attempted  [sha256.Size]byte

	// readFailing is set while the file cannot be read, so that state is
	// reported once when it begins rather than every two seconds or never.
	readFailing bool
}

func newProfileReloader(
	conf *config.Config, configPath string, origin *webrelay.Origin,
	counters *webrelay.Counters, structure string, log mtglib.Logger,
) *profileReloader {
	_, current := orderedSecrets(conf)

	return &profileReloader{
		configPath: configPath,
		origin:     origin,
		counters:   counters,
		structure:  structure,
		log:        log,
		current:    current,
	}
}

// tick looks at the file once and reloads if it has changed and settled.
//
// A file that cannot be read is not a failed reload -- nothing was attempted --
// and it forgets whatever was pending, so a file that is being replaced by
// rename has to hold still again once it is back. It is reported once, when it
// starts: a rename is over in a moment, a permissions change is not, and a
// watcher that went quiet forever over the second would be worse than none.
func (r *profileReloader) tick() {
	data, err := os.ReadFile(r.configPath)
	if err != nil {
		r.hasPending = false

		if !r.readFailing {
			r.readFailing = true
			r.log.WarningError("web relay: cannot read the config file, watching for it to come back", err)
		}

		return
	}

	if r.readFailing {
		r.readFailing = false
		r.log.Info("web relay: the config file is readable again")
	}

	sum := sha256.Sum256(data)

	if sum == r.attempted {
		return
	}

	if !r.hasPending || sum != r.pending {
		r.pending, r.hasPending = sum, true

		return
	}

	r.apply(data, reloadTriggerFile)
}

// reload re-reads the config file on request and swaps the profile set in.
// This is the signal path; the watcher goes through apply directly with the
// bytes it already has.
func (r *profileReloader) reload(trigger string) {
	data, err := os.ReadFile(r.configPath)
	if err != nil {
		// Counted like every other refusal. An operator whose signal hit a
		// file that was not there, and saw neither a reload nor a failure,
		// would be back to guessing whether it was delivered at all.
		r.counters.OnReload(time.Now(), err)
		r.log.BindStr("trigger", trigger).
			WarningError("web relay reload: cannot read the config, keeping the current profiles", err)

		return
	}

	r.apply(data, trigger)
}

// apply parses one snapshot of the file and swaps the profile set in.
//
// Every failure leaves the running set alone and says so. A relay that emptied
// its registry because someone saved a broken file would serve the cover site
// to every real user while reporting nothing wrong, and that failure is far
// worse than a stale profile list.
func (r *profileReloader) apply(data []byte, trigger string) {
	log := r.log.BindStr("trigger", trigger)

	// Remembered before the outcome is known, and whichever trigger asked. A
	// file a signal refused would otherwise be refused a second time by the
	// watcher two ticks later -- the exact sequence a supervisor's reload hook
	// produces -- and the failure counter would say two for one.
	r.attempted = sha256.Sum256(data)
	r.hasPending = false

	conf, err := utils.ParseConfig(data)
	if err != nil {
		// Counted like every other refusal. An operator whose signal hit an
		// unparseable file, and saw neither a reload nor a failure, would be
		// back to guessing whether it was delivered at all.
		r.counters.OnReload(time.Now(), err)
		log.WarningError("web relay reload: cannot read the config, keeping the current profiles", err)

		return
	}

	// The same validation startup ran, so a reload can never accept a file that
	// --check would refuse.
	if err := conf.ValidateWeb(); err != nil {
		r.counters.OnReload(time.Now(), err)
		log.WarningError("web relay reload: the config is unusable, keeping the current profiles", err)

		return
	}

	next, err := webStructure(conf)
	if err != nil {
		r.counters.OnReload(time.Now(), err)
		log.WarningError("web relay reload: cannot read the backend listener, keeping the current profiles", err)

		return
	}

	// Only the profile set is reloadable, and the rest is refused rather than
	// half-applied. The host is baked into every capability the clients already
	// hold, the token key has to outlive the tokens it signed, and the backend,
	// the cover site and the bound address are what the process was built
	// around. Applying some of a changed file and not the rest is how a relay
	// ends up in a state no configuration describes.
	if next != r.structure {
		r.counters.OnReload(time.Now(), errRestartRequired)
		log.Warning("web relay reload: [web] changed in a way that needs a restart, profiles left unchanged")

		return
	}

	names, secrets := orderedSecrets(conf)

	// A change the watcher found that leaves the profiles alone is not a
	// reload. A signal is different: an operator who sent one is asking
	// whether it landed, and the counter is how they find out.
	if trigger == reloadTriggerFile && slices.Equal(secrets, r.current) {
		log.Debug("web relay: the config changed but the profiles did not")

		return
	}

	if err := r.origin.SetSecrets(secrets); err != nil {
		r.counters.OnReload(time.Now(), err)
		log.WarningError("web relay reload: the new profile set cannot be served, keeping the current one", err)

		return
	}

	r.current = secrets

	r.counters.SetProfiles(names)
	r.counters.OnReload(time.Now(), nil)

	log.BindInt("profiles", len(secrets)).Info("web relay reloaded its profiles")
}
