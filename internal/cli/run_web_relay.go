package cli

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Arman2122/mtg-proxy/internal/config"
	"github.com/Arman2122/mtg-proxy/internal/proxyprotocol"
	"github.com/Arman2122/mtg-proxy/internal/utils"
	"github.com/Arman2122/mtg-proxy/internal/webrelay"
	"github.com/Arman2122/mtg-proxy/internal/webrelay/frame"
	"github.com/Arman2122/mtg-proxy/mtglib"
	"github.com/pires/go-proxyproto"
)

// Deadlines for the origin. They are shorter than the management API's because
// every request here is either a small document or an upgrade: nothing streams
// over HTTP, so a slow one is a client that is not really sending.
const (
	webReadHeaderTimeout = 5 * time.Second
	webReadTimeout       = 30 * time.Second
	webIdleTimeout       = 120 * time.Second
	webShutdownTimeout   = 10 * time.Second
	webBackendKeepAlive  = 30 * time.Second
)

// WebRelay serves the WEB proxy v1 carrier for the secrets in a config file.
//
// It is a separate process from the proxy, reading the same file. That is a
// deliberate shape rather than an accident of packaging: the relay terminates
// requests from a browser, parses HTTP and WebSocket frames from the open
// internet, and runs a page's worth of protocol on their behalf. The MTProto
// port has none of that surface and should not inherit it. They meet at one
// loopback socket that already exists.
type WebRelay struct {
	ConfigPath string `kong:"arg,required,type='existingfile',help='Path to the configuration file.',name='config-path'"` //nolint: lll
	Check      bool   `kong:"help='Verify the [web] configuration and exit without listening.'"`
}

func (w *WebRelay) Run(_ *CLI, version string) error {
	conf, err := utils.ReadConfig(w.ConfigPath)
	if err != nil {
		return fmt.Errorf("cannot init config: %w", err)
	}

	return runWebRelay(conf, w.ConfigPath, version, w.Check)
}

// GenerateWebKey writes the relay's token signing key.
//
// It is a command rather than something the relay does on first run, because a
// key invented at startup works perfectly until the process restarts and then
// silently breaks the one thing it exists for -- recognising this relay's own
// tokens after a restart, so they get a local 404 instead of being handed to
// the cover site.
type GenerateWebKey struct {
	Path string `kong:"arg,required,help='Where to write the 32-byte signing key.',name='path'"`
}

func (g *GenerateWebKey) Run(_ *CLI) error {
	if err := webrelay.GenerateTokenKey(g.Path); err != nil {
		return err
	}

	fmt.Printf("Wrote a WEB relay signing key to %s\n", g.Path) //nolint: forbidigo // this command's whole output

	return nil
}

func runWebRelay(conf *config.Config, configPath, version string, checkOnly bool) error {
	if err := conf.ValidateWeb(); err != nil {
		return err
	}

	log := makeLogger(conf).Named("web-relay")
	warnUnknownKeys(log, conf)

	counters := webrelay.NewCounters(time.Now())

	origin, backendAddr, err := buildOrigin(conf, counters, log)
	if err != nil {
		return err
	}

	structure, err := webStructure(conf)
	if err != nil {
		return err
	}

	if checkOnly {
		fmt.Printf("mtg-proxy %s: [web] configuration is usable\n", version) //nolint: forbidigo // the point of --check
		fmt.Printf("  host      %s\n", conf.Web.Host.Get(""))                //nolint: forbidigo
		fmt.Printf("  listen    %s\n", conf.Web.BindTo.Get(""))              //nolint: forbidigo
		fmt.Printf("  backend   %s\n", backendAddr)                          //nolint: forbidigo
		fmt.Printf("  profiles  %d\n", len(conf.GetSecrets()))               //nolint: forbidigo
		fmt.Printf("  client-ip %s\n", conf.Web.ClientIP.String())           //nolint: forbidigo
		fmt.Printf("  stats     %s\n", conf.Web.StatsBindTo.Get("(off)"))    //nolint: forbidigo

		return nil
	}

	listener, err := webListener(conf)
	if err != nil {
		return err
	}

	defer listener.Close() //nolint: errcheck // best effort on shutdown

	server := &http.Server{
		Handler:           origin,
		ReadHeaderTimeout: webReadHeaderTimeout,
		ReadTimeout:       webReadTimeout,
		IdleTimeout:       webIdleTimeout,
		ErrorLog:          nil,
	}

	// A WebSocket lives far past any write deadline, and the hijacked
	// connection carries its own. WriteTimeout is therefore deliberately unset
	// rather than merely forgotten.
	go func() {
		if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.WarningError("web relay origin stopped", err)
		}
	}()

	// A SECOND socket, deliberately. The origin above is published to the
	// internet by a front proxy, and everything on it that is not a client this
	// relay minted a credential for is answered by the cover site -- so an
	// endpoint there would be a fingerprint no matter how it was gated.
	// ValidateWeb has already refused any address that is not loopback.
	statsServer, err := startStatsServer(conf, origin, log)
	if err != nil {
		return err
	}

	if statsServer != nil {
		defer shutdownStatsServer(statsServer, log)
	}

	log.BindStr("host", conf.Web.Host.Get("")).
		BindStr("listen", conf.Web.BindTo.Get("")).
		BindStr("backend", backendAddr).
		BindStr("stats", conf.Web.StatsBindTo.Get("(off)")).
		BindInt("profiles", len(conf.GetSecrets())).
		Info("web relay is running")

	waitForShutdown(newProfileReloader(conf, configPath, origin, counters, structure, log))

	ctx, cancel := context.WithTimeout(context.Background(), webShutdownTimeout)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		return fmt.Errorf("cannot shut the web relay down: %w", err)
	}

	return nil
}

// waitForShutdown runs until the process is asked to stop, reloading profiles
// in between: whenever the config file changes, and on every SIGHUP.
//
// The file is watched because it is the source of truth for who may connect,
// and the panel writes it before it tells the proxy. The signal is kept because
// it is immediate, and because it is what every supervisor's reload already
// sends. Both land on one goroutine, one at a time, so two reloads can never
// interleave whichever way they arrived.
func waitForShutdown(reloader *profileReloader) {
	stop := utils.RootContext()

	// Buffered: a HUP that arrives while one is being applied is remembered
	// rather than dropped, and more than one pending reload is the same reload.
	// On a platform with no reload signal nothing is ever sent here, and the
	// watcher is the only trigger.
	hup := make(chan os.Signal, 1)

	if signals := reloadSignals(); len(signals) > 0 {
		signal.Notify(hup, signals...)
		defer signal.Stop(hup)
	}

	watch := time.NewTicker(webWatchInterval)
	defer watch.Stop()

	for {
		select {
		case <-stop.Done():
			return
		case <-hup:
			reloader.reload(reloadTriggerSignal)
		case <-watch.C:
			reloader.tick()
		}
	}
}

// startStatsServer brings up the relay's own counters socket, or nothing when
// no address is configured.
//
// A failure to bind here is fatal, unlike an extra [[listener]] on the proxy.
// The reasoning is opposite: there, losing one socket must not take the public
// port down, because clients are on it. Here, an operator asked for
// observability and would otherwise get a relay that runs while silently
// reporting nothing -- which is the state this whole feature exists to end.
func startStatsServer(
	conf *config.Config, origin *webrelay.Origin, log mtglib.Logger,
) (*http.Server, error) {
	addr := conf.Web.StatsBindTo.Get("")
	if addr == "" {
		return nil, nil //nolint: nilnil // "no server" is not an error
	}

	// The same helper every other socket in this process is built with, so the
	// stats listener gets the project's TCP options rather than the runtime
	// defaults, and the linter's ban on a bare net.Listen holds here too.
	listener, err := utils.NewListener(addr, 0)
	if err != nil {
		return nil, fmt.Errorf("cannot bind the web relay stats address %s: %w", addr, err)
	}

	server := &http.Server{
		Handler:           origin.StatsHandler(time.Now),
		ReadHeaderTimeout: webReadHeaderTimeout,
		ReadTimeout:       webReadTimeout,
		IdleTimeout:       webIdleTimeout,
	}

	go func() {
		if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.WarningError("web relay stats server stopped", err)
		}
	}()

	return server, nil
}

// shutdownStatsServer stops the counters socket on the way out.
func shutdownStatsServer(server *http.Server, log mtglib.Logger) {
	ctx, cancel := context.WithTimeout(context.Background(), webShutdownTimeout)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		log.WarningError("cannot shut the web relay stats server down", err)
	}
}

// errRestartRequired is what a reload records when the file changed in a way
// only a restart can apply. It is never returned to a caller -- it exists so
// the refusal lands in the failure counter, because an operator watching that
// number has to be able to tell "my SIGHUP did nothing" from "my SIGHUP was
// never delivered".
var errRestartRequired = errors.New("[web] changed in a way that needs a restart")

// webStructure renders everything about a relay that a reload must not change.
//
// It is every field of [web] -- the table holds no secrets, so all of it is
// structural -- plus the one thing the relay reads from outside it: whether the
// backend listener expects a PROXY header. A field added to ConfigWeb and not
// added here would become silently reloadable, so a test asserts this covers
// the struct.
func webStructure(conf *config.Config) (string, error) {
	listener, found := conf.WebBackendListener()
	if !found {
		return "", fmt.Errorf("[web] backend names no [[listener]]")
	}

	policy, err := listener.Policy()
	if err != nil {
		return "", fmt.Errorf("[web] backend listener: %w", err)
	}

	return strings.Join([]string{
		conf.Web.Host.Get(""),
		conf.Web.BindTo.Get(""),
		conf.Web.Backend.Get(""),
		conf.Web.TokenKey,
		conf.Web.CoverDir,
		conf.Web.CoverUpstream,
		conf.Web.ClientIP.String(),
		strconv.Itoa(int(conf.Web.MaxSessions.Get(0))),
		strconv.Itoa(int(conf.Web.MaxStreams.Get(0))),
		strconv.FormatInt(conf.Web.MaxPayload.Get(0), 10),
		strconv.FormatInt(conf.Web.BatchBytes.Get(0), 10),
		// Structural: it is a socket bound once at startup, and moving it means
		// binding a different one. A reload that accepted a new address would
		// report success while the counters went on answering at the old one.
		conf.Web.StatsBindTo.Get(""),
		strconv.FormatBool(policy.ProxyProtocol),
	}, "\x00"), nil
}

func buildOrigin(
	conf *config.Config, counters *webrelay.Counters, log mtglib.Logger,
) (*webrelay.Origin, string, error) {
	listener, found := conf.WebBackendListener()
	if !found {
		return nil, "", fmt.Errorf("[web] backend names no [[listener]]")
	}

	policy, err := listener.Policy()
	if err != nil {
		return nil, "", fmt.Errorf("[web] backend listener: %w", err)
	}

	backendAddr := conf.Web.Backend.Get("")

	// The PROXY-protocol decision comes from the listener's own stanza, never
	// from a setting of the relay's. Two places to say it is two places to
	// disagree, and a header the listener is not expecting is consumed as the
	// first bytes of the client's obfuscated handshake.
	backend, err := webrelay.NewTCPBackend(backendAddr, policy.ProxyProtocol, webBackendKeepAlive)
	if err != nil {
		return nil, "", err
	}

	cover, err := buildCover(conf)
	if err != nil {
		return nil, "", err
	}

	signer, err := webrelay.LoadTokenKey(conf.Web.TokenKey)
	if err != nil {
		return nil, "", err
	}

	limits := frame.Limits{
		MaxPayload: int(conf.Web.MaxPayload.Get(0)), //nolint: gosec // a configured bound, validated below
		BatchBytes: conf.Web.BatchBytes.Get(0),
	}

	if err := limits.Validate(); err != nil {
		return nil, "", fmt.Errorf("[web] limits: %w", err)
	}

	names, secrets := orderedSecrets(conf)
	counters.SetProfiles(names)

	origin, err := webrelay.NewOrigin(webrelay.OriginOptions{
		Host:    conf.Web.Host.Get(""),
		Secrets: secrets,
		// The relay serves primaries only (orderedSecrets). The keys a rotation
		// retired are only recognised, so their holders get the local 404
		// instead of the cover site (Task 11); the registry trims the list.
		Retired:     conf.RetiringValues(),
		Counters:    counters,
		Signer:      signer,
		Cover:       cover,
		Backend:     backend,
		Limits:      limits,
		MaxSessions: int(conf.Web.MaxSessions.Get(webrelay.DefaultMaxSessions)),
		MaxStreams:  int(conf.Web.MaxStreams.Get(webrelay.DefaultMaxStreams)),
		DialTimeout: webrelay.DefaultDialTimeout,
		ClientIP:    clientIPResolver(conf.Web.ClientIP.Get(config.ClientIPProxyProtocol)),
		Logger:      log,
	})
	if err != nil {
		return nil, "", err
	}

	return origin, backendAddr, nil
}

func buildCover(conf *config.Config) (http.Handler, error) {
	if conf.Web.CoverDir != "" {
		return webrelay.NewStaticCover(conf.Web.CoverDir)
	}

	return webrelay.NewUpstreamCover(conf.Web.CoverUpstream)
}

// webListener binds the origin's socket, wrapping it in the PROXY-protocol
// adapter when that is where the client address comes from.
func webListener(conf *config.Config) (net.Listener, error) {
	base, err := utils.NewListener(conf.Web.BindTo.Get(""), 0)
	if err != nil {
		return nil, fmt.Errorf("cannot bind the web relay to %s: %w", conf.Web.BindTo.Get(""), err)
	}

	if conf.Web.ClientIP.Get(config.ClientIPProxyProtocol) != config.ClientIPProxyProtocol {
		return base, nil
	}

	return &proxyprotocol.ListenerAdapter{
		Listener: proxyproto.Listener{
			Listener: base,
			// REQUIRE, not the library's permissive default. Without a header
			// the default would hand back the front proxy's own address, and
			// the relay would run perfectly while every WEB user appeared to
			// the proxy as the loopback: the blocklist would stop matching, the
			// per-IP limits would stop counting, and nothing would say so. A
			// front proxy configured without proxy_protocol should fail
			// loudly on the first connection instead.
			ConnPolicy: func(proxyproto.ConnPolicyOptions) (proxyproto.Policy, error) {
				return proxyproto.REQUIRE, nil
			},
		},
	}, nil
}

// clientIPResolver builds the function that says who is connecting.
//
// There is no fallback to the socket's own peer. Behind a front proxy that is
// loopback for every user alive, and stamping it into the backend header would
// quietly disable the blocklist, the per-IP limits and every log line that names
// a user -- while the relay kept working perfectly. A stream whose client cannot
// be identified is refused instead.
func clientIPResolver(source config.ClientIPSource) func(*http.Request) net.Addr {
	if source == config.ClientIPProxyProtocol {
		// The listener adapter already rewrote RemoteAddr from the header the
		// front proxy wrote, so the socket IS the answer here.
		return func(r *http.Request) net.Addr {
			addr, err := net.ResolveTCPAddr("tcp", r.RemoteAddr)
			if err != nil {
				return nil
			}

			return addr
		}
	}

	return func(r *http.Request) net.Addr {
		peer, err := net.ResolveTCPAddr("tcp", r.RemoteAddr)
		if err != nil {
			return nil
		}

		// The header is only meaningful from the hop that appends it. A
		// non-loopback peer is not the configured front proxy, so its claim
		// about who it is forwarding for is worth nothing.
		if !peer.IP.IsLoopback() {
			return nil
		}

		values := r.Header.Values("X-Forwarded-For")
		if len(values) == 0 {
			return nil
		}

		// Right-most entry of the last field: that is what the nearest trusted
		// hop appended. Everything to its left was written by whoever was
		// speaking before it, which includes the client.
		entries := strings.Split(values[len(values)-1], ",")

		ip := net.ParseIP(strings.TrimSpace(entries[len(entries)-1]))
		if ip == nil {
			return nil
		}

		return &net.TCPAddr{IP: ip, Port: peer.Port}
	}
}

// orderedSecrets flattens the secret map into a stable order.
//
// The order is the profile numbering, and it appears in logs and metrics, so it
// has to survive a restart that did not change the configuration. A map range
// would renumber every profile on every start for no reason at all.
func orderedSecrets(conf *config.Config) ([]string, []mtglib.Secret) {
	named := conf.GetSecrets()
	names := make([]string, 0, len(named))

	for name := range named {
		names = append(names, name)
	}

	sort.Strings(names)

	secrets := make([]mtglib.Secret, 0, len(names))
	for _, name := range names {
		secrets = append(secrets, named[name])
	}

	// Returned together, from one walk of one sorted key list, so the two
	// slices cannot come to disagree about which name belongs to which profile.
	return names, secrets
}
