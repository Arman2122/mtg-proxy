package cli

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"sort"
	"strconv"
	"sync"

	"github.com/Arman2122/mtg-proxy/internal/config"
	"github.com/Arman2122/mtg-proxy/internal/utils"
	"github.com/Arman2122/mtg-proxy/mtglib"
)

type accessResponseSecret struct {
	Hex    string `json:"hex"`
	Base64 string `json:"base64"`
}

type accessResponse struct {
	IPv4    *accessResponseURLs             `json:"ipv4,omitempty"`
	IPv6    *accessResponseURLs             `json:"ipv6,omitempty"`
	Secret  accessResponseSecret            `json:"secret"`
	Secrets map[string]accessResponseSecret `json:"secrets,omitempty"`

	// Listeners is omitted entirely when no [[listener]] is configured, so a
	// deployment that never declared one gets the output it always got.
	Listeners []accessResponseListener `json:"listeners,omitempty"`

	Web *accessResponseWeb `json:"web,omitempty"`
}

// accessResponseWeb is how a client reaches this proxy over the WEB transport.
//
// Two things are different from every other link here, and both come from the
// client rather than from us:
//
// The secret is the dd form. A WEB-capable client refuses an ee secret outright,
// before any network activity, so the ee spelling of the same key -- the one the
// panel mints and every other link uses -- is unusable here. These are the same
// sixteen bytes told differently.
//
// There is no address and no port. The client's WEB proxy form has one field, a
// hostname; the scheme is fixed to https and the port to 443. So a WEB link is
// not tied to an IP, and changing the hostname invalidates every link ever
// issued -- exactly like the fronting domain of an ee secret.
type accessResponseWeb struct {
	Host    string                             `json:"host"`
	Secret  accessResponseWebSecret            `json:"secret"`
	Secrets map[string]accessResponseWebSecret `json:"secrets,omitempty"`
}

type accessResponseWebSecret struct {
	// Secret is the dd form, which is what the client's own field expects.
	Secret string `json:"secret"`

	// TgURL is the deep link. Only the tg:// form is emitted: the client routes
	// both tg://webproxy and t.me/webproxy, but t.me has not registered the
	// route, so an https link resolves as the USERNAME @webproxy and shows a
	// stranger's contact page.
	//
	// The parameter names mirror tg://proxy, which is the only published
	// precedent -- they are not confirmed against a real client, and confirming
	// them is an item on the acceptance checklist. The host and secret above are
	// what an operator types into the client's own two fields, so this output
	// stays usable either way.
	TgURL string `json:"tg_url"` //nolint: tagliatelle

	TgQrCode string `json:"tg_qrcode"` //nolint: tagliatelle
}

// accessResponseListener is one [[listener]] and the links that reach it.
//
// The links are separate from the top-level ipv4/ipv6 pair because they are not
// the same offer: bind-to is FakeTLS and always hands out an ee secret, while a
// listener hands out the wire form that socket accepts. The same user appears
// in both, with the same sixteen key bytes spelled two ways, and that is the
// point -- one account, three doors.
type accessResponseListener struct {
	BindTo string   `json:"bind_to"` //nolint: tagliatelle
	Accept []string `json:"accept"`
	Public bool     `json:"public"`

	// Unreachable says why this listener has no links, and is set for exactly
	// one reason: it is bound to loopback. That is not a misconfiguration --
	// it is what a WEB relay backend is supposed to look like -- so it is
	// reported rather than warned about.
	Unreachable string `json:"unreachable,omitempty"`

	IPv4 *accessResponseListenerURLs `json:"ipv4,omitempty"`
	IPv6 *accessResponseListenerURLs `json:"ipv6,omitempty"`
}

// accessResponseListenerURLs is one address family's view of one listener.
type accessResponseListenerURLs struct {
	IP   string `json:"ip"`
	Port uint   `json:"port"`

	// Secrets is keyed by user name, then by wire form: a listener accepting
	// both dd and plain offers each user a link in each, because which one a
	// given client will take is the client's business.
	Secrets map[string]map[string]accessResponseModeURLs `json:"secrets"`
}

// accessResponseModeURLs is one user's link in one wire form on one listener.
type accessResponseModeURLs struct {
	Secret    string `json:"secret"`
	TgURL     string `json:"tg_url"`     //nolint: tagliatelle
	TgQrCode  string `json:"tg_qrcode"`  //nolint: tagliatelle
	TmeURL    string `json:"tme_url"`    //nolint: tagliatelle
	TmeQrCode string `json:"tme_qrcode"` //nolint: tagliatelle
}

type accessResponseURLs struct {
	IP        net.IP `json:"ip"`
	Port      uint   `json:"port"`
	TgURL     string `json:"tg_url"`     //nolint: tagliatelle
	TgQrCode  string `json:"tg_qrcode"`  //nolint: tagliatelle
	TmeURL    string `json:"tme_url"`    //nolint: tagliatelle
	TmeQrCode string `json:"tme_qrcode"` //nolint: tagliatelle
}

type Access struct {
	ConfigPath string `kong:"arg,required,type='existingfile',help='Path to the configuration file.',name='config-path'"`                 //nolint: lll
	PublicIPv4 net.IP `kong:"help='Public IPv4 address for proxy. By default it is resolved via remote website',name='ipv4',short='i'"`   //nolint: lll
	PublicIPv6 net.IP `kong:"help='Public IPv6 address for proxy. By default it is resolved via remote website',name='ipv6',short='I'"`   //nolint: lll
	Port       uint   `kong:"help='Port number. Default port is taken from configuration file, bind-to parameter',type:'uint',short='p'"` //nolint: lll
	Hex        bool   `kong:"help='Print secret in hex encoding.',short='x'"`
}

func (a *Access) Run(cli *CLI, version string) error {
	conf, err := utils.ReadConfig(a.ConfigPath)
	if err != nil {
		return fmt.Errorf("cannot init config: %w", err)
	}

	resp := &accessResponse{}
	secrets := conf.GetSecrets()

	// Sort secret names for deterministic "first secret" selection.
	sortedNames := make([]string, 0, len(secrets))
	for name := range secrets {
		sortedNames = append(sortedNames, name)
	}

	sort.Strings(sortedNames)

	// For backward compatibility, populate the single Secret field with the
	// first secret (sorted alphabetically).
	if len(sortedNames) > 0 {
		first := secrets[sortedNames[0]]
		resp.Secret.Base64 = first.Base64()
		resp.Secret.Hex = first.Hex()
	}

	if len(secrets) > 1 {
		resp.Secrets = make(map[string]accessResponseSecret, len(secrets))

		for name, s := range secrets {
			resp.Secrets[name] = accessResponseSecret{
				Hex:    s.Hex(),
				Base64: s.Base64(),
			}
		}
	}

	resp.Web = makeWebAccess(conf, secrets, sortedNames)

	ntw, err := makeNetwork(conf, version)
	if err != nil {
		return fmt.Errorf("cannot init network: %w", err)
	}

	wg := &sync.WaitGroup{}

	wg.Go(func() {
		ip := a.PublicIPv4
		if ip == nil {
			ip = conf.PublicIPv4.Get(nil)
		}
		if ip == nil {
			ip = getIP(ntw, "tcp4")
		}

		if ip != nil {
			ip = ip.To4()
		}

		resp.IPv4 = a.makeURLs(conf, ip)
	})
	wg.Go(func() {
		ip := a.PublicIPv6
		if ip == nil {
			ip = conf.PublicIPv6.Get(nil)
		}
		if ip == nil {
			ip = getIP(ntw, "tcp6")
		}

		if ip != nil {
			ip = ip.To16()
		}

		resp.IPv6 = a.makeURLs(conf, ip)
	})

	wg.Wait()

	resp.Listeners = makeListenerAccess(conf, secrets, sortedNames, resp.IPv4, resp.IPv6)

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")

	if err := encoder.Encode(resp); err != nil {
		return fmt.Errorf("cannot dump access json: %w", err)
	}

	return nil
}

func (a *Access) makeURLs(conf *config.Config, ip net.IP) *accessResponseURLs {
	if ip == nil {
		return nil
	}

	portNo := a.Port
	if portNo == 0 {
		portNo = conf.GetFirstBindPort()
	}

	values := url.Values{}
	values.Set("server", ip.String())
	values.Set("port", strconv.Itoa(int(portNo)))

	// Use the first available secret (sorted) for URL generation.
	secrets := conf.GetSecrets()
	names := make([]string, 0, len(secrets))

	for name := range secrets {
		names = append(names, name)
	}

	sort.Strings(names)

	var firstSecret mtglib.Secret
	if len(names) > 0 {
		firstSecret = secrets[names[0]]
	}

	if a.Hex {
		values.Set("secret", firstSecret.Hex())
	} else {
		values.Set("secret", firstSecret.Base64())
	}

	urlQuery := values.Encode()

	rv := &accessResponseURLs{
		IP:   ip,
		Port: portNo,
		TgURL: (&url.URL{
			Scheme:   "tg",
			Host:     "proxy",
			RawQuery: urlQuery,
		}).String(),
		TmeURL: (&url.URL{
			Scheme:   "https",
			Host:     "t.me",
			Path:     "proxy",
			RawQuery: urlQuery,
		}).String(),
	}
	rv.TgQrCode = utils.MakeQRCodeURL(rv.TgURL)
	rv.TmeQrCode = utils.MakeQRCodeURL(rv.TmeURL)

	return rv
}

// makeListenerAccess builds the links for every configured [[listener]].
//
// It exists because bind-to is not the only door any more and access only ever
// described that one: it prints the ee secret against the FakeTLS port, which
// is the one form a client arriving on an obfuscated2 socket will not take. An
// operator who added a listener had no way to hand a user a link for it.
//
// The addresses come from the already-resolved ipv4/ipv6 blocks rather than
// being looked up again -- the public address of the host does not depend on
// which of its sockets is being described, and resolving it twice would mean
// two trips to a remote service for one command.
func makeListenerAccess(
	conf *config.Config, secrets map[string]mtglib.Secret, names []string,
	ipv4, ipv6 *accessResponseURLs,
) []accessResponseListener {
	if len(conf.Listeners) == 0 {
		return nil
	}

	rv := make([]accessResponseListener, 0, len(conf.Listeners))

	for _, listener := range conf.Listeners {
		bindTo := listener.BindTo.Get("")

		entry := accessResponseListener{
			BindTo: bindTo,
			Accept: make([]string, 0, len(listener.Accept)),
			Public: listener.Public.Get(false),
		}

		for _, mode := range listener.Accept {
			entry.Accept = append(entry.Accept, mode.String())
		}

		port, loopback := listenerPort(bindTo)

		switch {
		case port == 0:
			entry.Unreachable = "this listener has no port to advertise"
		case loopback:
			// The expected case for a WEB relay backend, and the reason this
			// says what it says rather than nothing: an operator seeing no
			// links here should know it is by design.
			entry.Unreachable = "bound to loopback, so it is reachable only from this host " +
				"(a WEB relay backend is meant to look like this)"
		default:
			entry.IPv4 = makeListenerURLs(listener, secrets, names, ipv4, port)
			entry.IPv6 = makeListenerURLs(listener, secrets, names, ipv6, port)
		}

		rv = append(rv, entry)
	}

	return rv
}

// listenerPort pulls the port out of a listener's bind-to, and says whether the
// address it is bound to can be reached from anywhere but this host.
func listenerPort(bindTo string) (uint, bool) {
	host, port, err := net.SplitHostPort(bindTo)
	if err != nil {
		return 0, false
	}

	portNo, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return 0, false
	}

	ip := net.ParseIP(host)

	return uint(portNo), ip != nil && ip.IsLoopback()
}

// makeListenerURLs builds one address family's links for one listener, in every
// wire form that socket accepts.
func makeListenerURLs(
	listener config.ConfigListener, secrets map[string]mtglib.Secret, names []string,
	family *accessResponseURLs, port uint,
) *accessResponseListenerURLs {
	if family == nil || family.IP == nil {
		return nil
	}

	rv := &accessResponseListenerURLs{
		IP:      family.IP.String(),
		Port:    port,
		Secrets: make(map[string]map[string]accessResponseModeURLs, len(names)),
	}

	for _, name := range names {
		secret := secrets[name]
		forms := make(map[string]accessResponseModeURLs, len(listener.Accept))

		for _, mode := range listener.Accept {
			// The same sixteen key bytes, spelled the way this socket expects.
			// A secret is not re-issued to be offered here: the prefix is a
			// statement about the door, not about the account.
			var text string

			switch mode.Get() {
			case mtglib.SecretModeDD:
				text = secret.DDHex()
			case mtglib.SecretModePlain:
				text = secret.PlainHex()
			case mtglib.SecretModeFakeTLS:
				// Not reachable: a [[listener]] rejects "ee" at config
				// validation, because one socket never serves both entry
				// paths. Skipped rather than guessed at.
				continue
			default:
				continue
			}

			forms[mode.String()] = makeModeURLs(rv.IP, port, text)
		}

		if len(forms) > 0 {
			rv.Secrets[name] = forms
		}
	}

	return rv
}

// makeModeURLs renders one link, in both the tg:// and t.me spellings.
func makeModeURLs(ip string, port uint, secret string) accessResponseModeURLs {
	values := url.Values{}
	values.Set("server", ip)
	values.Set("port", strconv.Itoa(int(port)))
	values.Set("secret", secret)

	query := values.Encode()

	rv := accessResponseModeURLs{
		Secret: secret,
		TgURL: (&url.URL{
			Scheme:   "tg",
			Host:     "proxy",
			RawQuery: query,
		}).String(),
		TmeURL: (&url.URL{
			Scheme:   "https",
			Host:     "t.me",
			Path:     "proxy",
			RawQuery: query,
		}).String(),
	}

	rv.TgQrCode = utils.MakeQRCodeURL(rv.TgURL)
	rv.TmeQrCode = utils.MakeQRCodeURL(rv.TmeURL)

	return rv
}

// makeWebAccess builds the WEB links, or nothing when this proxy has no relay.
func makeWebAccess(conf *config.Config, secrets map[string]mtglib.Secret, names []string) *accessResponseWeb {
	host := conf.Web.Host.Get("")
	if !conf.Web.Enabled.Get(false) || host == "" {
		return nil
	}

	// A host the config refuses gets no WEB link: the relay will not start on
	// it, and it may be a secret value pasted where the host goes (Task 10's
	// second review, N-A). A host it accepts is printed as written, as before.
	if _, err := conf.WebHost(); err != nil {
		return nil
	}

	web := &accessResponseWeb{Host: host}

	if len(names) > 0 {
		web.Secret = makeWebSecret(host, secrets[names[0]])
	}

	if len(names) > 1 {
		web.Secrets = make(map[string]accessResponseWebSecret, len(names))

		for _, name := range names {
			web.Secrets[name] = makeWebSecret(host, secrets[name])
		}
	}

	return web
}

func makeWebSecret(host string, secret mtglib.Secret) accessResponseWebSecret {
	values := url.Values{}
	values.Set("server", host)
	values.Set("secret", secret.DDHex())

	link := (&url.URL{Scheme: "tg", Host: "webproxy", RawQuery: values.Encode()}).String()

	return accessResponseWebSecret{
		Secret:   secret.DDHex(),
		TgURL:    link,
		TgQrCode: utils.MakeQRCodeURL(link),
	}
}
