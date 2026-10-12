package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"text/template"
	"time"

	"github.com/Arman2122/mtg-proxy/essentials"
	"github.com/Arman2122/mtg-proxy/internal/config"
	"github.com/Arman2122/mtg-proxy/internal/utils"
	"github.com/Arman2122/mtg-proxy/mtglib"
	"github.com/Arman2122/mtg-proxy/mtglib/dcprobe"
	"github.com/Arman2122/mtg-proxy/network/v2"
	"github.com/beevik/ntp"
)

var (
	tplError = template.Must(
		template.New("").Parse("  ‼️ {{ .description }}: {{ .error }}\n"),
	)

	tplWDeprecatedConfig = template.Must(
		template.New("").
			Parse(`  ⚠️ Option {{ .old | printf "%q" }}{{ if .old_section }} from section [{{ .old_section }}]{{ end }} is deprecated and will be removed in v{{ .when }}. Please use {{ .new | printf "%q" }}{{ if .new_section }} in [{{ .new_section }}] section{{ end }} instead.` + "\n"),
	)

	tplOTimeSkewness = template.Must(
		template.New("").
			Parse("  ✅ Time drift is {{ .drift }}, but tolerate-time-skewness is {{ .value }}\n"),
	)
	tplWTimeSkewness = template.Must(
		template.New("").
			Parse("  ⚠️ Time drift is {{ .drift }}, but tolerate-time-skewness is {{ .value }}. Please check ntp.\n"),
	)
	tplETimeSkewness = template.Must(
		template.New("").
			Parse("  ❌ Time drift is {{ .drift }}, but tolerate-time-skewness is {{ .value }}. You will get many rejected connections!\n"),
	)

	tplODCConnect = template.Must(
		template.New("").Parse("  ✅ DC {{ .dc }} (rpc {{ .rtt }})\n"),
	)
	tplEDCConnect = template.Must(
		template.New("").Parse("  ❌ DC {{ .dc }}: {{ .error }}\n"),
	)

	tplODNSSNIMatch = template.Must(
		template.New("").Parse("  ✅ IP address {{ .ip }} matches secret hostname {{ .hostname }}\n"),
	)
	tplEDNSSNIMatch = template.Must(
		template.New("").Parse("  ❌ Hostname {{ .hostname }} {{ if .resolved }}resolves to {{ .resolved }}, but the proxy's public IP is {{ if .ip4 }}{{ .ip4 }}{{ else }}<not detected>{{ end }} (IPv4) / {{ if .ip6 }}{{ .ip6 }}{{ else }}<not detected>{{ end }} (IPv6) — none of the resolved addresses match{{ else }}cannot be resolved to any host{{ end }}\n"),
	)

	tplOFrontingDomain = template.Must(
		template.New("").Parse("  ✅ {{ .address }} is reachable\n"),
	)
	tplEFrontingDomain = template.Must(
		template.New("").Parse("  ❌ {{ .address }}: {{ .error }}\n"),
	)
)

// Doctor is `mtg doctor`: the checks an operator runs when a proxy does not
// work. It is the one command whose own correctness nobody can check in the
// field -- a ✅ for a broken thing or a ❌ for a working one sends them the
// wrong way -- so every way it reaches the world is a seam a test can drive:
// the network and the resolver come in through diagnose, and the NTP query and
// the output are fields.
type Doctor struct {
	conf *config.Config

	// out is where the report goes; Run points it at stdout.
	out io.Writer
	// queryNTP is how the skew check learns the clock offset; Run points it
	// at the real pool.
	queryNTP ntpOffset

	ConfigPath      string `kong:"arg,required,type='existingfile',help='Path to the configuration file.',name='config-path'"`                                                                       //nolint: lll
	SkipNativeCheck bool   `kong:"help='Skip the native network connectivity check (useful when proxy chaining is configured and direct egress is not expected to work).',name='skip-native-check'"` //nolint: lll
}

// ntpOffset asks one NTP host for this machine's clock offset.
type ntpOffset func(host string) (time.Duration, error)

// ntpPool is the host the real query goes to.
const ntpPool = "0.pool.ntp.org"

// say writes one line of the report. The report is best-effort output to a
// terminal: a failed write is not a diagnosis and must not change the verdict,
// so the error is deliberately not consulted.
func (d *Doctor) say(format string, args ...any) {
	fmt.Fprintf(d.out, format+"\n", args...) //nolint: errcheck
}

func queryNTPOffset(host string) (time.Duration, error) {
	response, err := ntp.Query(host)
	if err != nil {
		return 0, err //nolint: wrapcheck // the report prints it as the pool's own error
	}

	return response.ClockOffset, nil
}

func (d *Doctor) Run(cli *CLI, version string) error {
	conf, err := utils.ReadConfig(d.ConfigPath)
	if err != nil {
		return fmt.Errorf("cannot init config: %w", explainConfigError(err))
	}

	d.conf = conf
	d.out = os.Stdout
	d.queryNTP = queryNTPOffset

	resolver, err := network.GetDNS(conf.GetDNS())
	if err != nil {
		return fmt.Errorf("cannot create DNS resolver: %w", err)
	}

	// The socket option takes a machine word, so an oversized watermark is
	// refused here rather than wrapped on the 32-bit builds we ship.
	lowat, err := conf.Network.TCPNotSentLowat.GetUint(network.DefaultTCPNotSentLowat)
	if err != nil {
		return fmt.Errorf("incorrect tcp-not-sent-lowat: %w", err)
	}

	base := network.New(
		resolver,
		"",
		conf.Network.Timeout.TCP.Get(10*time.Second),
		conf.Network.Timeout.HTTP.Get(0),
		conf.Network.Timeout.Idle.Get(0),
		net.KeepAliveConfig{
			Enable:   !conf.Network.KeepAlive.Disabled.Get(false),
			Idle:     conf.Network.KeepAlive.Idle.Get(0),
			Interval: conf.Network.KeepAlive.Interval.Get(0),
			Count:    int(conf.Network.KeepAlive.Count.Get(0)),
		},
		int(lowat),
	)

	ok, err := d.diagnose(base, resolver)
	if err != nil {
		return err
	}

	if !ok {
		os.Exit(1)
	}

	return nil
}

// diagnose runs every check, in the order the report shows them, against the
// network and resolver it is given, and says whether all of them passed. Run
// hands it the real ones; a test hands it fakes, which is what makes the checks
// testable at all. The verdict is the conjunction of every check, so a check
// that is dropped from it here is a check the operator silently stops getting.
// checkUnknownKeys names every key in the file this binary does not know. The
// proxy logs the same list at startup, but the doctor is what an operator runs
// when a setting "does nothing", and this is the usual reason it does nothing.
func (d *Doctor) checkUnknownKeys() bool {
	if len(d.conf.UnknownKeys) == 0 {
		d.say("  ✅ Every key in the file is known to this binary")

		return true
	}

	for _, warning := range d.conf.UnknownKeyWarnings() {
		d.say("  ⚠️  %s", warning)
	}

	return false
}

// checkRetiringSecrets reads the [[retiring-secret]] table as run --check does,
// at the wall clock: the doctor is a separate process with no high-water
// history. Every problem or warning run would log is listed and fails the
// verdict, as an unknown key does; so does a [secrets] user named
// retiring-secret, which is never served. Entries past their until are inert:
// they are counted, with the way to remove them, and do not fail it. Every line
// names an entry by its position and name, never by its key.
//
// It prints its section only when it has one of those to show, so the report
// of a config without the table -- the panel's -- reads as it did.
func (d *Doctor) checkRetiringSecrets() bool {
	report := d.conf.GetRetiringSecrets(time.Now())

	if len(report.Lines) == 0 && report.Expired == 0 {
		return true
	}

	d.say("Retiring secrets")

	for _, line := range report.Lines {
		d.say("  ⚠️  %s", line)
	}

	switch {
	case report.Expired == 1:
		d.say("  ℹ️  1 retiring-secret entry is past its until and ignored; rotate-secret --prune removes it")
	case report.Expired > 1:
		d.say("  ℹ️  %d retiring-secret entries are past their until and ignored; rotate-secret --prune removes them",
			report.Expired)
	}

	return len(report.Lines) == 0
}

func (d *Doctor) diagnose(base mtglib.Network, resolver ipLookup) (bool, error) {
	d.say("Deprecated options")
	everythingOK := d.checkDeprecatedConfig()

	d.say("Unknown config keys")
	everythingOK = d.checkUnknownKeys() && everythingOK

	// Its own header, printed only when it has something to say.
	everythingOK = d.checkRetiringSecrets() && everythingOK

	d.say("Time skewness")
	everythingOK = d.checkTimeSkewness() && everythingOK

	d.say("Validate native network connectivity")
	if d.SkipNativeCheck {
		d.say("  ⏭ Skipped (--skip-native-check)")
	} else {
		everythingOK = d.checkNetwork(base) && everythingOK
	}

	for _, url := range d.conf.Network.Proxies {
		value, err := network.NewProxyNetwork(base, url.Get(nil))
		if err != nil {
			return false, err //nolint: wrapcheck // named by the caller's own message
		}

		d.say("Validate network connectivity with proxy %s", url.Get(nil))
		everythingOK = d.checkNetwork(value) && everythingOK
	}

	d.say("Validate fronting domain connectivity")
	everythingOK = d.checkFrontingDomain(base) && everythingOK

	d.say("Validate SNI-DNS match")
	everythingOK = d.checkSecretHost(resolver, base) && everythingOK

	return everythingOK, nil
}

func (d *Doctor) checkDeprecatedConfig() bool {
	ok := true

	if d.conf.DomainFrontingIP.Value != nil {
		ok = false
		tplWDeprecatedConfig.Execute(d.out, map[string]string{ //nolint: errcheck
			"when":        "2.3.0",
			"old":         "domain-fronting-ip",
			"old_section": "",
			"new":         "host",
			"new_section": "domain-fronting",
		})
	}

	if d.conf.DomainFronting.IP.Value != nil {
		ok = false
		tplWDeprecatedConfig.Execute(d.out, map[string]string{ //nolint: errcheck
			"when":        "2.4.0",
			"old":         "ip",
			"old_section": "domain-fronting",
			"new":         "host",
			"new_section": "domain-fronting",
		})
	}

	if d.conf.DomainFrontingPort.Value != 0 {
		ok = false
		tplWDeprecatedConfig.Execute(d.out, map[string]string{ //nolint: errcheck
			"when":        "2.3.0",
			"old":         "domain-fronting-port",
			"old_section": "",
			"new":         "port",
			"new_section": "domain-fronting",
		})
	}

	if d.conf.DomainFrontingProxyProtocol.Value {
		ok = false
		tplWDeprecatedConfig.Execute(d.out, map[string]string{ //nolint: errcheck
			"when":        "2.3.0",
			"old":         "domain-fronting-proxy-protocol",
			"old_section": "",
			"new":         "proxy-protocol",
			"new_section": "domain-fronting",
		})
	}

	if d.conf.Network.DOHIP.Value != nil {
		ok = false
		tplWDeprecatedConfig.Execute(d.out, map[string]string{ //nolint: errcheck
			"when":        "2.3.0",
			"old":         "doh-ip",
			"old_section": "network",
			"new":         "dns",
			"new_section": "network",
		})
	}

	if ok {
		d.say("  ✅ All good")
	}

	return ok
}

func (d *Doctor) checkTimeSkewness() bool {
	offset, err := d.queryNTP(ntpPool)
	if err != nil {
		tplError.Execute(d.out, map[string]any{ //nolint: errcheck
			"description": "cannot access ntp pool",
			"error":       err,
		})
		return false
	}

	skewness := offset.Abs()
	confValue := d.conf.TolerateTimeSkewness.Get(mtglib.DefaultTolerateTimeSkewness)
	diff := float64(skewness) / float64(confValue)
	tplData := map[string]any{
		"drift": offset,
		"value": confValue,
	}

	switch {
	case diff < 0.3:
		tplOTimeSkewness.Execute(d.out, tplData) //nolint: errcheck
		return true
	case diff < 0.7:
		tplWTimeSkewness.Execute(d.out, tplData) //nolint: errcheck
	default:
		tplETimeSkewness.Execute(d.out, tplData) //nolint: errcheck
	}

	return false
}

func (d *Doctor) checkNetwork(ntw mtglib.Network) bool {
	dcs := slices.Collect(maps.Keys(essentials.TelegramCoreAddresses))
	slices.Sort(dcs)

	type dcResult struct {
		rtt time.Duration
		err error
	}
	results := make([]dcResult, len(dcs))

	var wg sync.WaitGroup
	for i, dc := range dcs {
		wg.Go(func() {
			defer func() {
				if r := recover(); r != nil {
					results[i].err = fmt.Errorf("panic: %v", r)
				}
			}()
			results[i].rtt, results[i].err = d.checkNetworkAddresses(ntw, dc, essentials.TelegramCoreAddresses[dc])
		})
	}
	wg.Wait()

	ok := true

	for i, dc := range dcs {
		if results[i].err == nil {
			tplODCConnect.Execute(d.out, map[string]any{ //nolint: errcheck
				"dc":  dc,
				"rtt": results[i].rtt.Round(time.Microsecond),
			})
		} else {
			tplEDCConnect.Execute(d.out, map[string]any{ //nolint: errcheck
				"dc":    dc,
				"error": results[i].err,
			})
			ok = false
		}
	}

	return ok
}

func (d *Doctor) checkNetworkAddresses(ntw mtglib.Network, dc int, addresses []string) (time.Duration, error) {
	checkAddresses := []string{}

	switch d.conf.PreferIP.Get("prefer-ip4") {
	case "only-ipv4":
		for _, addr := range addresses {
			host, _, err := net.SplitHostPort(addr)
			if err != nil {
				panic(err)
			}

			if ip := net.ParseIP(host); ip != nil && ip.To4() != nil {
				checkAddresses = append(checkAddresses, addr)
			}
		}
	case "only-ipv6":
		for _, addr := range addresses {
			host, _, err := net.SplitHostPort(addr)
			if err != nil {
				panic(err)
			}

			if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
				checkAddresses = append(checkAddresses, addr)
			}
		}
	default:
		checkAddresses = addresses
	}

	if len(checkAddresses) == 0 {
		return 0, fmt.Errorf("no suitable addresses after IP version filtering")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var lastErr error

	for _, addr := range checkAddresses {
		conn, err := ntw.DialContext(ctx, "tcp", addr)
		if err != nil {
			lastErr = fmt.Errorf("tcp connect to %s: %w", addr, err)
			continue
		}

		rtt, err := dcprobe.Probe(ctx, conn, dc)
		conn.Close() //nolint: errcheck

		if err != nil {
			lastErr = fmt.Errorf("rpc handshake to %s: %w", addr, err)
			continue
		}

		return rtt, nil
	}

	return 0, lastErr
}

func (d *Doctor) getFirstSecretHost() string {
	for _, s := range d.conf.GetSecrets() {
		return s.Host
	}

	return ""
}

func (d *Doctor) checkFrontingDomain(ntw mtglib.Network) bool {
	host := d.getFirstSecretHost()
	if override := d.conf.GetDomainFrontingHost(); override != "" {
		host = override
	}

	port := d.conf.GetDomainFrontingPort(mtglib.DefaultDomainFrontingPort)
	address := net.JoinHostPort(host, strconv.Itoa(int(port)))

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	dialer := ntw.NativeDialer()

	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		tplEFrontingDomain.Execute(d.out, map[string]any{ //nolint: errcheck
			"address": address,
			"error":   err,
		})
		return false
	}

	conn.Close() //nolint: errcheck

	tplOFrontingDomain.Execute(d.out, map[string]any{ //nolint: errcheck
		"address": address,
	})

	return true
}

func (d *Doctor) checkSecretHost(resolver ipLookup, ntw mtglib.Network) bool {
	host := d.getFirstSecretHost()

	res := runSNICheck(context.Background(), resolver, d.conf, ntw, host)

	if res.ResolveErr != nil {
		tplError.Execute(d.out, map[string]any{ //nolint: errcheck
			"description": fmt.Sprintf("cannot resolve DNS name of %s", host),
			"error":       res.ResolveErr,
		})
		return false
	}

	if !res.PublicIPKnown() {
		tplError.Execute(d.out, map[string]any{ //nolint: errcheck
			"description": "cannot detect public IP address",
			"error":       errors.New("cannot detect automatically and public-ipv4/public-ipv6 are not set in config"),
		})
		return false
	}

	if res.IPv4Match || res.IPv6Match {
		var matched net.IP

		for _, ip := range res.Resolved {
			if (res.OurIPv4 != nil && ip.String() == res.OurIPv4.String()) ||
				(res.OurIPv6 != nil && ip.String() == res.OurIPv6.String()) {
				matched = ip
				break
			}
		}

		tplODNSSNIMatch.Execute(d.out, map[string]any{ //nolint: errcheck
			"ip":       matched,
			"hostname": host,
		})
		return true
	}

	strAddresses := make([]string, 0, len(res.Resolved))
	for _, ip := range res.Resolved {
		strAddresses = append(strAddresses, `"`+ip.String()+`"`)
	}

	tplEDNSSNIMatch.Execute(d.out, map[string]any{ //nolint: errcheck
		"hostname": host,
		"resolved": strings.Join(strAddresses, ", "),
		"ip4":      res.OurIPv4,
		"ip6":      res.OurIPv6,
	})

	return false
}
