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
	Web     *accessResponseWeb              `json:"web,omitempty"`
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

// makeWebAccess builds the WEB links, or nothing when this proxy has no relay.
func makeWebAccess(conf *config.Config, secrets map[string]mtglib.Secret, names []string) *accessResponseWeb {
	host := conf.Web.Host.Get("")
	if !conf.Web.Enabled.Get(false) || host == "" {
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
