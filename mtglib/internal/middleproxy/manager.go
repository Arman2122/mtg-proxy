package middleproxy

import (
	"bufio"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Arman2122/mtg-proxy/essentials"
)

const (
	// G101: a public Telegram endpoint, not a credential. gosec matches the
	// identifier, not the value. The proxy secret this URL RETURNS is held
	// only in memory, in middleproxy.Manager.
	secretURL     = "https://core.telegram.org/getProxySecret" //nolint:gosec
	configURLv4   = "https://core.telegram.org/getProxyConfig"
	configURLv6   = "https://core.telegram.org/getProxyConfigV6"
	refreshPeriod = time.Hour
	fetchTimeout  = 30 * time.Second

	// retryPeriod is how long the manager waits after a failed fetch before
	// trying again, in the background. Nothing in a client's path ever waits
	// for that retry: see ensureReady.
	retryPeriod = time.Minute
)

// errFetching is what a dial gets while the very first fetch is still in
// flight. It is an error and not a wait, because the fetch can take up to
// three times fetchTimeout, and a client that queued behind it would sit there
// for the whole of that with its connection open and nothing happening.
var errFetching = errors.New("middle-proxy config is still being fetched")

// Dialer is the subset of mtglib.Network the manager needs to reach a middle
// proxy. It is declared here to keep this internal package free of an import
// cycle back to mtglib.
type Dialer interface {
	Dial(network, address string) (essentials.Conn, error)
}

// Logger is the minimal logging surface used by the background refresh loop.
// mtglib.Logger satisfies it.
type Logger interface {
	Info(string)
	Warning(string)
}

// Manager fetches and caches Telegram's proxy secret and middle-proxy address
// lists, and dials RPC proxy streams that carry an ad_tag. It fetches lazily on
// first use (so a proxy without advertising never touches the network) and then
// refreshes hourly. It is safe for concurrent use.
//
// Exactly one fetch is ever in a client's path: the first. Every later one runs
// in the background, and a dial that arrives while the manager is not ready is
// told so at once and takes the direct route. This is the whole design: a fetch
// is three sequential HTTP requests of up to fetchTimeout each against a host
// the network may well be blocking, and an earlier version queued every
// ad-tagged dial behind it, so a proxy whose ad-tag was configured on a network
// that could not reach core.telegram.org held every client for up to ninety
// seconds, one after another, before letting each one through direct.
type Manager struct {
	ctx        context.Context
	httpClient *http.Client
	logger     Logger
	preferIP   string

	// retryPeriod is a field so a test can shorten it.
	retryPeriod time.Duration

	mu       sync.RWMutex
	ready    bool
	secret   []byte
	middleV4 map[int][]string
	middleV6 map[int][]string

	// fetching says the first fetch is in flight. lastErr is why the manager is
	// not ready, kept so a dial that arrives before the next retry can be told
	// why without waiting for it.
	fetching bool
	lastErr  error

	refreshOnce sync.Once
}

// NewManager builds a Manager. httpClient should be built with the proxy's
// network settings (e.g. mtglib.Network.MakeHTTPClient) so DNS and upstream
// proxying apply. preferIP is the proxy's IP connectivity preference. The
// refresh loop and any in-flight fetches stop when ctx is cancelled.
func NewManager(ctx context.Context, httpClient *http.Client, logger Logger, preferIP string) *Manager {
	return &Manager{
		ctx:         ctx,
		httpClient:  httpClient,
		logger:      logger,
		preferIP:    preferIP,
		retryPeriod: retryPeriod,
	}
}

// Warm triggers an initial fetch in the background. Call it at startup when
// advertising is configured so the first client does not pay the fetch latency.
func (m *Manager) Warm() {
	go func() {
		if err := m.ensureReady(); err != nil {
			m.logger.Warning("cannot fetch middle-proxy config: " + err.Error())
		}
	}()
}

// ensureReady makes sure the config has been fetched, without making the caller
// wait for anything but the very first attempt.
//
// After that attempt the answer is immediate whatever the state: ready, still
// fetching, or failed and waiting for the background retry. The refresh loop
// starts after the first attempt regardless of how it went, so a proxy that
// came up on a network that was blocking Telegram recovers by itself once the
// network does, with no client ever having paid for the outage.
func (m *Manager) ensureReady() error {
	m.mu.Lock()

	switch {
	case m.ready:
		m.mu.Unlock()

		return nil
	case m.fetching:
		m.mu.Unlock()

		return errFetching
	case m.lastErr != nil:
		err := m.lastErr
		m.mu.Unlock()

		return err
	}

	m.fetching = true
	m.mu.Unlock()

	err := m.fetch(m.ctx)

	m.startRefresh()

	return err
}

// startRefresh begins the background loop, once. It re-fetches every
// refreshPeriod while the config is loaded, and every retryPeriod until it is.
func (m *Manager) startRefresh() {
	m.refreshOnce.Do(func() {
		go m.refreshLoop()
	})
}

func (m *Manager) refreshLoop() {
	for {
		wait := refreshPeriod
		if !m.Ready() {
			wait = m.retryPeriod
		}

		timer := time.NewTimer(wait)

		select {
		case <-m.ctx.Done():
			timer.Stop()

			return
		case <-timer.C:
		}

		if err := m.fetch(m.ctx); err != nil {
			m.logger.Warning("cannot refresh middle-proxy config: " + err.Error())
		}
	}
}

// Ready reports whether the proxy secret and at least one middle-proxy address
// have been fetched.
func (m *Manager) Ready() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return m.ready
}

func (m *Manager) proxySecret() []byte {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return m.secret
}

// fetch runs one complete fetch and records how it went. It is called from one
// place at a time -- the first ensureReady, then only the refresh loop -- so it
// takes no lock of its own around the network round trips.
func (m *Manager) fetch(ctx context.Context) error {
	err := m.fetchAll(ctx)

	m.mu.Lock()
	m.fetching = false

	if err != nil {
		m.lastErr = fmt.Errorf("middle-proxy config unavailable, retrying in the background: %w", err)
	} else {
		m.lastErr = nil
	}

	m.mu.Unlock()

	return err
}

func (m *Manager) fetchAll(ctx context.Context) error {
	secret, err := m.fetchBytes(ctx, secretURL)
	if err != nil {
		return fmt.Errorf("cannot fetch proxy secret: %w", err)
	}

	v4, err := m.fetchConfig(ctx, configURLv4)
	if err != nil {
		return fmt.Errorf("cannot fetch proxy config v4: %w", err)
	}

	v6, err := m.fetchConfig(ctx, configURLv6)
	if err != nil {
		// IPv6 config is optional; keep going with v4 only.
		m.logger.Warning("cannot fetch proxy config v6: " + err.Error())

		v6 = map[int][]string{}
	}

	m.mu.Lock()
	m.secret = secret
	m.middleV4 = v4
	m.middleV6 = v6
	m.ready = len(secret) > 0 && (len(v4) > 0 || len(v6) > 0)
	m.mu.Unlock()

	m.logger.Info(fmt.Sprintf("middle-proxy config loaded: %d v4 DCs, %d v6 DCs", len(v4), len(v6)))

	return nil
}

func (m *Manager) fetchBytes(ctx context.Context, url string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, fetchTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err //nolint: wrapcheck
	}

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("cannot GET %s: %w", url, err)
	}

	defer resp.Body.Close() //nolint: errcheck

	if resp.StatusCode >= http.StatusBadRequest {
		io.Copy(io.Discard, resp.Body) //nolint: errcheck

		return nil, fmt.Errorf("unexpected status %d from %s", resp.StatusCode, url)
	}

	return io.ReadAll(resp.Body) //nolint: wrapcheck
}

func (m *Manager) fetchConfig(ctx context.Context, url string) (map[int][]string, error) {
	data, err := m.fetchBytes(ctx, url)
	if err != nil {
		return nil, err
	}

	return parseMiddleConfig(data)
}

// parseMiddleConfig parses a getProxyConfig body, collecting every
// "proxy_for <dc> <ip:port>;" line keyed by the signed DC id. Comment and
// "default" lines are ignored.
func parseMiddleConfig(data []byte) (map[int][]string, error) {
	out := map[int][]string{}
	scanner := bufio.NewScanner(strings.NewReader(string(data)))

	for scanner.Scan() {
		text := strings.TrimSpace(scanner.Text())

		if !strings.HasPrefix(text, "proxy_for") {
			continue
		}

		fields := strings.Fields(text)
		if len(fields) < 3 {
			continue
		}

		dc, err := strconv.Atoi(fields[1])
		if err != nil {
			continue
		}

		addr := strings.TrimRight(fields[2], ";")
		if _, _, err := net.SplitHostPort(addr); err != nil {
			continue
		}

		out[dc] = append(out[dc], addr)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("cannot parse proxy config: %w", err)
	}

	return out, nil
}

type middleAddress struct {
	network string
	addr    string
}

// orderedAddresses returns the middle-proxy addresses to try for dc, honoring
// the IP-family preference and including both DC signs (Telegram lists +N and
// -N separately). The requested dc is passed as its absolute value; both +dc
// and -dc entries are returned.
func (m *Manager) orderedAddresses(dc int) []middleAddress {
	m.mu.RLock()
	defer m.mu.RUnlock()

	v6First := strings.Contains(m.preferIP, "ipv6")
	onlyV4 := m.preferIP == "only-ipv4"
	onlyV6 := m.preferIP == "only-ipv6"

	var out []middleAddress

	appendFamily := func(table map[int][]string, network string) {
		for _, key := range []int{dc, -dc} {
			for _, addr := range table[key] {
				out = append(out, middleAddress{network: network, addr: addr})
			}
		}
	}

	if v6First {
		if !onlyV4 {
			appendFamily(m.middleV6, "tcp6")
		}

		if !onlyV6 {
			appendFamily(m.middleV4, "tcp4")
		}
	} else {
		if !onlyV6 {
			appendFamily(m.middleV4, "tcp4")
		}

		if !onlyV4 {
			appendFamily(m.middleV6, "tcp6")
		}
	}

	return out
}

// DialParams carries the addressing the proxy contributes to a middle-proxy
// dial. ClientAddr is the real client's address (put in RPC_PROXY_REQ). PublicIPv4
// and PublicIPv6 optionally override the address the middle proxy sees as our
// source (needed on multi-homed hosts); the family matching the dialed socket
// is used. AdvertisedPort is the port reported as ours in RPC_PROXY_REQ.
type DialParams struct {
	DC         int
	ClientAddr *net.TCPAddr
	PublicIPv4 net.IP
	PublicIPv6 net.IP
	// PaddedIntermediate says the client's transport is 0xdddddddd, the only
	// one whose frames carry 0-15 bytes of trailing padding. It drives RPC_F_PAD
	// and the alignment trim, both of which are a lie for plain intermediate.
	PaddedIntermediate bool
	AdvertisedPort     int
	AdTag              [adTagLength]byte
}

// DialProxyStream connects to a middle proxy for params.DC, performs the RPC
// handshake, and returns an essentials.Conn that transparently carries the
// client's traffic wrapped in RPC_PROXY_REQ with the ad_tag. It also returns
// the middle-proxy IP for the connected-to-DC event.
func (m *Manager) DialProxyStream(dialer Dialer, params DialParams) (essentials.Conn, net.IP, error) {
	if err := m.ensureReady(); err != nil {
		return nil, nil, err
	}

	secret := m.proxySecret()
	if len(secret) == 0 {
		return nil, nil, fmt.Errorf("middle-proxy secret is not available")
	}

	addresses := m.orderedAddresses(params.DC)
	if len(addresses) == 0 {
		return nil, nil, fmt.Errorf("no middle proxy address for dc %d", params.DC)
	}

	var lastErr error

	for _, a := range addresses {
		conn, err := dialer.Dial(a.network, a.addr)
		if err != nil {
			lastErr = err

			continue
		}

		local := toTCPAddr(conn.LocalAddr())
		remote := toTCPAddr(conn.RemoteAddr())

		// Pick the advertised public IP whose family matches the socket, so the
		// key schedule and RPC_PROXY_REQ agree with what the middle proxy sees.
		publicIP := params.PublicIPv4
		if local.IP.To4() == nil {
			publicIP = params.PublicIPv6
		}

		// The key schedule uses our source IP as the middle proxy sees it. On a
		// public host that is conn.LocalAddr(); the operator can override the IP
		// (keeping the ephemeral source port) for multi-homed hosts.
		keyLocal := local
		if publicIP != nil {
			keyLocal = &net.TCPAddr{IP: publicIP, Port: local.Port}
		}

		frame, err := doHandshake(conn, secret, keyLocal, remote)
		if err != nil {
			conn.Close() //nolint: errcheck
			lastErr = err

			continue
		}

		rpcIP := local.IP
		if publicIP != nil {
			rpcIP = publicIP
		}

		rpcOurAddr := &net.TCPAddr{IP: rpcIP, Port: params.AdvertisedPort}

		var connID [8]byte
		if _, err := rand.Read(connID[:]); err != nil {
			conn.Close() //nolint: errcheck

			return nil, nil, err //nolint: wrapcheck
		}

		return newMiddleConn(conn, frame, connID, params.AdTag,
			params.ClientAddr, rpcOurAddr, params.PaddedIntermediate), remote.IP, nil
	}

	return nil, nil, fmt.Errorf("cannot connect to any middle proxy for dc %d: %w", params.DC, lastErr)
}

func toTCPAddr(addr net.Addr) *net.TCPAddr {
	if tcp, ok := addr.(*net.TCPAddr); ok {
		return tcp
	}

	return &net.TCPAddr{}
}
