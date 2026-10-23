package doppel

import (
	"context"
	"fmt"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Arman2122/mtg-proxy/essentials"
	"github.com/Arman2122/mtg-proxy/mtglib/internal/tls"
)

const (
	DoppelGangerMaxDurations  = 4096
	DoppelGangerScoutRaidEach = 6 * time.Hour
	DoppelGangerScoutRepeats  = 10

	MinCertSizesToCalculate = 3
)

// NoiseParams holds the measured cert chain size for FakeTLS noise calibration.
// If Mean is 0, the caller should use a legacy fallback.
type NoiseParams struct {
	Mean   int
	Jitter int
}

// CoverHost is a cover site an ee secret names, and the address domain
// fronting dials for it -- which is where it is measured, so a deployment
// whose cover host resolves back to this server does not measure itself.
type CoverHost struct {
	Host string
	Addr string
}

type scoutRaidResult struct {
	durations []time.Duration
	certSizes []int

	// hostCertSizes is what a raid of the cover hosts measured, per host.
	hostCertSizes map[string][]int
}

type gangerConnRequest struct {
	ret     chan<- Conn
	payload essentials.Conn
}

type Ganger struct {
	ctx       context.Context
	ctxCancel context.CancelFunc
	logger    Logger
	wg        sync.WaitGroup

	scout            Scout
	scoutRaidEach    time.Duration
	scoutRaidRepeats int

	drs     bool
	shaping Shaping

	// scoutCovers turns on measuring the cover hosts when no URLs are
	// configured.
	scoutCovers bool

	stats     Stats
	durations []time.Duration
	certSizes []int

	noiseParams atomic.Pointer[NoiseParams]

	// The cover hosts the secrets name, set from outside at any time;
	// coversChanged tells the run loop.
	coverMu       sync.Mutex
	covers        []CoverHost
	coversChanged chan struct{}

	// Owned by the run loop: hosts a raid has been started for, and each
	// host's measured sizes. hostNoise is what handshakes read.
	raided    map[string]bool
	hostSizes map[string][]int
	hostNoise atomic.Pointer[map[string]NoiseParams]

	connRequests chan gangerConnRequest
}

func (g *Ganger) Shutdown() {
	g.ctxCancel()
	g.wg.Wait()
}

func (g *Ganger) Run() {
	g.wg.Go(func() {
		g.run()
	})
}

// Unpace makes the connections this ganger hands out emit their records back
// to back: no delay is drawn between them. Record sizing is left as it was.
//
// No production caller uses it. It is for a harness that times something else
// through a FakeTLS stream -- a speed limit -- where the deliberate,
// heavy-tailed delay between records would otherwise be part of the number:
// under the default model a single record waits over half a second about once
// in five thousand. Call it before Run; from then on the run loop owns the
// timing model, and a scout raid that gathers enough samples replaces it.
func (g *Ganger) Unpace() {
	// k = 1 rather than the zero value: Delay raises to 1/k, and 1/0 would turn
	// λ = 0 into 0·Inf = NaN instead of a zero wait.
	g.stats = Stats{k: 1, lambda: 0, drs: g.drs}
}

// NoiseParams returns the current cert-size-based noise parameters.
// Returns zero-value NoiseParams if not yet measured (caller should use fallback).
func (g *Ganger) NoiseParams() NoiseParams {
	if p := g.noiseParams.Load(); p != nil {
		return *p
	}

	return NoiseParams{}
}

// NoiseParamsFor returns the noise sizing measured for the cover site host,
// or the global NoiseParams when that host has not been measured.
func (g *Ganger) NoiseParamsFor(host string) NoiseParams {
	if perHost := g.hostNoise.Load(); perHost != nil {
		if np, ok := (*perHost)[host]; ok {
			return np
		}
	}

	return g.NoiseParams()
}

// SetCoverHosts records the cover sites the secrets name. It is safe at any
// time; with cover scouting on and no URLs configured, a host never measured
// before is measured promptly, the rest on the raid cadence.
func (g *Ganger) SetCoverHosts(hosts []CoverHost) {
	g.coverMu.Lock()
	g.covers = slices.Clone(hosts)
	g.coverMu.Unlock()

	select {
	case g.coversChanged <- struct{}{}:
	default:
	}
}

// CoverHosts returns a copy of the cover sites last set.
func (g *Ganger) CoverHosts() []CoverHost {
	g.coverMu.Lock()
	defer g.coverMu.Unlock()

	return slices.Clone(g.covers)
}

// coverMode is whether raids measure the cover hosts: only when asked to and
// when no URLs are configured, which keep their old meaning.
func (g *Ganger) coverMode() bool {
	return g.scoutCovers && len(g.scout.urls) == 0
}

// unraided returns the cover hosts no raid has been started for, and marks
// them. Run loop only.
func (g *Ganger) unraided() []CoverHost {
	var fresh []CoverHost

	for _, h := range g.CoverHosts() {
		if !g.raided[h.Host] {
			g.raided[h.Host] = true
			fresh = append(fresh, h)
		}
	}

	return fresh
}

func (g *Ganger) NewConn(conn essentials.Conn) (Conn, error) {
	// Room for exactly the one answer, and never closed: the run loop may hold
	// this request when the context ends and this call leaves, and its answer
	// must then land in the buffer rather than block, or meet a closed channel
	// and panic a goroutine nothing recovers. An answer nobody takes is a Conn
	// on the ganger's context, which is done, so its writer ends on its own.
	rvChan := make(chan Conn, 1)
	req := gangerConnRequest{
		ret:     rvChan,
		payload: conn,
	}

	select {
	case <-g.ctx.Done():
		return Conn{}, context.Cause(g.ctx)
	case g.connRequests <- req:
	}

	select {
	case <-g.ctx.Done():
		return Conn{}, context.Cause(g.ctx)
	case conn := <-rvChan:
		return conn, nil
	}
}

func (g *Ganger) run() {
	scoutTicker := time.NewTicker(g.scoutRaidEach)
	defer func() {
		scoutTicker.Stop()

		select {
		case <-scoutTicker.C:
		default:
		}
	}()

	scoutCollectedChan := make(chan scoutRaidResult)
	currentScoutCollectedChan := scoutCollectedChan

	updatedStatsChan := make(chan Stats)

	var first []CoverHost
	if g.coverMode() {
		first = g.unraided()
	}

	g.wg.Go(func() {
		g.runScoutRaid(scoutCollectedChan, first)
	})

	for {
		select {
		case <-g.ctx.Done():
			return
		case <-g.coversChanged:
			if !g.coverMode() {
				continue
			}

			if fresh := g.unraided(); len(fresh) > 0 {
				g.wg.Go(func() {
					g.runScoutRaid(scoutCollectedChan, fresh)
				})
			}
		case result := <-currentScoutCollectedChan:
			if len(result.hostCertSizes) > 0 {
				g.updateHostNoise(result.hostCertSizes)
			}

			g.durations = append(g.durations, result.durations...)

			if len(g.durations) > DoppelGangerMaxDurations {
				copy(g.durations, g.durations[len(g.durations)-DoppelGangerMaxDurations:])
				g.durations = g.durations[:DoppelGangerMaxDurations]
			}

			// Update cert sizes and recompute noise params.
			g.certSizes = append(g.certSizes, result.certSizes...)
			if len(g.certSizes) > DoppelGangerMaxDurations {
				g.certSizes = g.certSizes[len(g.certSizes)-DoppelGangerMaxDurations:]
			}

			if len(g.certSizes) >= MinCertSizesToCalculate {
				g.updateNoiseParams()
			}

			if len(g.durations) < MinDurationsToCalculate {
				continue
			}

			durations := g.durations
			currentScoutCollectedChan = nil
			g.wg.Go(func() {
				select {
				case <-g.ctx.Done():
				case updatedStatsChan <- NewStats(durations, g.drs):
				}
			})
		case stats := <-updatedStatsChan:
			g.adopt(stats)
			currentScoutCollectedChan = scoutCollectedChan
		case <-scoutTicker.C:
			var all []CoverHost
			if g.coverMode() {
				all = g.CoverHosts()
			}

			g.wg.Go(func() {
				g.runScoutRaid(scoutCollectedChan, all)
			})
		case req := <-g.connRequests:
			// Never blocks: ret has room for this one answer (see NewConn).
			req.ret <- NewConn(g.ctx, req.payload, g.stats, g.shaping)
		}
	}
}

// adopt makes a fitted model the one new connections are paced by, if it is
// usable; otherwise the current one stays. Run loop only.
func (g *Ganger) adopt(stats Stats) {
	if !stats.usable() {
		g.logger.WarningError("measured record timing does not fit; keeping the current model",
			fmt.Errorf("k=%g lambda=%g", stats.k, stats.lambda)) //nolint: err113

		return
	}

	g.stats = stats
}

func (g *Ganger) updateNoiseParams() {
	np, ok := noiseFromSizes(g.certSizes)
	if !ok {
		return
	}

	g.noiseParams.Store(&np)

	g.logger.Info(fmt.Sprintf(
		"updated noise params: mean=%d jitter=%d samples=%d",
		np.Mean, np.Jitter, len(g.certSizes),
	))
}

// updateHostNoise adds a raid's per-host sizes and republishes the per-host
// sizing. Run loop only; readers see a whole new map or the old one.
func (g *Ganger) updateHostNoise(sizes map[string][]int) {
	perHost := make(map[string]NoiseParams)

	if old := g.hostNoise.Load(); old != nil {
		for host, np := range *old {
			perHost[host] = np
		}
	}

	for host, measured := range sizes {
		all := append(g.hostSizes[host], measured...)
		if len(all) > DoppelGangerMaxDurations {
			all = all[len(all)-DoppelGangerMaxDurations:]
		}

		g.hostSizes[host] = all

		if np, ok := noiseFromSizes(all); ok {
			perHost[host] = np

			g.logger.Info(fmt.Sprintf(
				"updated noise params for %s: mean=%d jitter=%d samples=%d",
				host, np.Mean, np.Jitter, len(all),
			))
		}
	}

	g.hostNoise.Store(&perHost)
}

// noiseFromSizes turns measured certificate-flight sizes into a noise draw:
// their mean, and a jitter of their largest deviation (at least 100 bytes),
// kept inside one TLS record. It needs MinCertSizesToCalculate samples.
func noiseFromSizes(sizes []int) (NoiseParams, bool) {
	if len(sizes) < MinCertSizesToCalculate {
		return NoiseParams{}, false
	}

	sum := 0
	for _, s := range sizes {
		sum += s
	}

	mean := sum / len(sizes)

	maxDev := 0
	for _, s := range sizes {
		d := s - mean
		if d < 0 {
			d = -d
		}

		if d > maxDev {
			maxDev = d
		}
	}

	if maxDev < 100 {
		maxDev = 100
	}

	// The noise draw is mean±jitter and has to fit a single TLS record: an
	// oversized payload makes WriteRecord fail, and the noise path suppresses
	// that error, so the record is dropped entirely and the client's handshake
	// HMAC - computed over it - no longer matches. The sizes are a sum over the
	// whole server flight, so they can exceed one record on their own.
	if maxDev > tls.MaxRecordPayloadSize/2 {
		maxDev = tls.MaxRecordPayloadSize / 2
	}

	mean = min(mean, tls.MaxRecordPayloadSize-maxDev)

	return NoiseParams{Mean: mean, Jitter: maxDev}, true
}

// runScoutRaid measures, scoutRaidRepeats times: the cover hosts given, in
// cover mode, or the configured URLs otherwise. Cover raids measure
// certificate flights only. Their record timing is left out: it would replace
// the model every connection is paced by, a change a censor can see, as a
// side effect of naming a cover host -- timing changes ship behind shaping
// and a canary. Configured URLs feed the timing model, as they always have.
func (g *Ganger) runScoutRaid(rvChan chan<- scoutRaidResult, covers []CoverHost) {
	var result scoutRaidResult

	if g.coverMode() {
		result.hostCertSizes = make(map[string][]int)

		for range g.scoutRaidRepeats {
			for _, h := range covers {
				learned, err := g.scout.LearnCover(g.ctx, h)
				if err != nil {
					g.logger.WarningError("cannot learn cover host "+h.Host, err)

					continue
				}

				if learned.CertSize > 0 {
					result.hostCertSizes[h.Host] = append(result.hostCertSizes[h.Host], learned.CertSize)
				}
			}
		}

		select {
		case <-g.ctx.Done():
		case rvChan <- result:
		}

		return
	}

	for range g.scoutRaidRepeats {
		learned, err := g.scout.Learn(g.ctx)
		if err != nil {
			g.logger.WarningError("cannot learn", err)
			continue
		}

		result.durations = append(result.durations, learned.Durations...)

		if learned.CertSize > 0 {
			result.certSizes = append(result.certSizes, learned.CertSize)
		}
	}

	select {
	case <-g.ctx.Done():
		return
	case rvChan <- result:
	}
}

func NewGanger(
	ctx context.Context,
	network Network,
	logger Logger,
	scoutEach time.Duration,
	scoutRepeats int,
	urls []string,
	drs bool,
	shaping Shaping,
	scoutCovers bool,
) *Ganger {
	ctx, cancel := context.WithCancel(ctx)

	if scoutEach == 0 {
		scoutEach = DoppelGangerScoutRaidEach
	}

	if scoutRepeats == 0 {
		scoutRepeats = DoppelGangerScoutRepeats
	}

	return &Ganger{
		ctx:              ctx,
		ctxCancel:        cancel,
		logger:           logger,
		scoutRaidEach:    scoutEach,
		scoutRaidRepeats: scoutRepeats,
		drs:              drs,
		shaping:          shaping,
		scoutCovers:      scoutCovers,
		stats: Stats{
			k:      StatsDefaultK,
			lambda: StatsDefaultLambda,
			drs:    drs,
		},
		scout:         NewScout(network, urls),
		connRequests:  make(chan gangerConnRequest),
		coversChanged: make(chan struct{}, 1),
		raided:        make(map[string]bool),
		hostSizes:     make(map[string][]int),
	}
}
