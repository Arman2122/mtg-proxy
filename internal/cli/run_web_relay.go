package cli

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sort"
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

	return runWebRelay(conf, version, w.Check)
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

func runWebRelay(conf *config.Config, version string, checkOnly bool) error {
	if err := conf.ValidateWeb(); err != nil {
		return err
	}

	log := makeLogger(conf).Named("web-relay")

	origin, backendAddr, err := buildOrigin(conf, log)
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

		return nil
	}

	listener, err := webListener(conf)
	if err != nil {
		return err
	}

	defer listener.Close()

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

	log.BindStr("host", conf.Web.Host.Get("")).
		BindStr("listen", conf.Web.BindTo.Get("")).
		BindStr("backend", backendAddr).
		BindInt("profiles", len(conf.GetSecrets())).
		Info("web relay is running")

	<-utils.RootContext().Done()

	ctx, cancel := context.WithTimeout(context.Background(), webShutdownTimeout)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		return fmt.Errorf("cannot shut the web relay down: %w", err)
	}

	return nil
}

func buildOrigin(conf *config.Config, log mtglib.Logger) (*webrelay.Origin, string, error) {
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
		MaxPayload: int(conf.Web.MaxPayload.Get(0)),   //nolint: gosec // a configured bound, validated below
		BatchBytes: int64(conf.Web.BatchBytes.Get(0)), //nolint: gosec // ditto
	}

	if err := limits.Validate(); err != nil {
		return nil, "", fmt.Errorf("[web] limits: %w", err)
	}

	secrets := orderedSecrets(conf)

	origin, err := webrelay.NewOrigin(webrelay.OriginOptions{
		Host:        conf.Web.Host.Get(""),
		Secrets:     secrets,
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
func orderedSecrets(conf *config.Config) []mtglib.Secret {
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

	return secrets
}
