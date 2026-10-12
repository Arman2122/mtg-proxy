package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Arman2122/mtg-proxy/internal/config"
	"github.com/Arman2122/mtg-proxy/mtglib"
)

// rotate-secret --reload (spec §7.5, D26): the running proxy is asked, before
// anything is written, whether it is there and knows the [[retiring-secret]]
// table; after the write it is reloaded, and what it serves is read back and
// compared with what the written file says it must serve. Every expected value
// comes from the written bytes alone, never from the proxy's earlier state (m5′
// of the second review): an earlier rotation written without --reload, or a
// re-key through the API since, is then no false failure.
//
// Nothing here prints a key. The answers carry the proxy's primaries, and a
// failed POST /reload's body is the proxy's error text: a mismatch is described
// by mode, host and "the same key" or "another key", a refused reload by its
// status code and the standard text for it, and a transport error without its
// URL, which can hold a name that reads as a value. The API's token is sent and
// never printed. The file is never rolled back: it is the truth, and a rollback
// would make the leaked key the primary again at the next restart.

// reloadRequestTimeout bounds each request to the management API. It is the
// proxy's own write deadline (apiWriteTimeout), which a POST /reload of a large
// file may use up; a stalled API is ended sooner by the run's first interrupt.
const reloadRequestTimeout = 60 * time.Second

// reloadAnswerLimit bounds what is read of an answer: GET /stats lists every
// user.
const reloadAnswerLimit = 64 << 20

// The likely causes §7.5 gives for a failed check:
//   - the primary (check 1, and a name the proxy does not serve at all);
//   - fewer previous keys, or an earlier end, than the file says (checks 2 and
//     3), with forcedCause before them when --force went past a proxy without
//     secret-rotation;
//   - more previous keys than the file says (check 2; revision 4, Task 10's
//     review, M-2): a clock ahead can only take keys away, so the proxy reads
//     another file, or this machine's clock is the one ahead;
//   - a 404 or 405 from a proxy without secret-read (M-3), which does not
//     serve the route at all.
const (
	primaryMismatchCauses = "a SECRET environment variable overriding [secrets]; a single-file bind mount that still " +
		"shows the old file (mount the config's directory instead); another process that rewrote the file"
	retiringMismatchCauses = "the proxy's clock is ahead of this machine's (its latest time judged an entry expired), " +
		"or the proxy logged a problem with a [[retiring-secret]] block"
	retiringSurplusCauses = "the proxy reads a file other than this one (a single-file bind mount that still shows " +
		"the old file; another process that rewrote the file), or this machine's clock is ahead of the proxy's"
	forcedCause       = "the running proxy is an older binary (--force), which ignores [[retiring-secret]]; "
	noSecretReadCause = "the running proxy does not serve GET /secrets/{name} (an older binary)"
)

// fileRotatedNotServed opens every failure after the write that the read-back,
// or the reload's own answer, proves.
const fileRotatedNotServed = "the file is rotated but the proxy does not serve it: "

// errNotJSON is a 200 whose body is not the JSON asked for: something else
// answers at the API's address.
var errNotJSON = errors.New("the answer is not the JSON the management API sends")

// errReloadWithoutAPI is --reload on a file that names no management API: a
// refusal before anything is written.
var errReloadWithoutAPI = errors.New("--reload needs the proxy's management API, and the config sets no " +
	"api-bind-to: rotate without --reload, then POST /reload on the proxy's management API or restart the proxy")

// reloadTarget is the running proxy's management API, as the config file
// gives it: base is http://host:port, token the bearer token ("" for none).
type reloadTarget struct {
	base, token string
	client      *http.Client
}

// reloadTargetOf is the API that api-bind-to and api-token name. A wildcard
// host is reached on the loopback of its family: 0.0.0.0 at 127.0.0.1, :: at
// ::1. No proxy from the environment is used -- the token would go through it
// -- and no redirect is followed.
func reloadTargetOf(conf *config.Config) (reloadTarget, error) {
	if conf.APIBindTo.Get("") == "" {
		return reloadTarget{}, errReloadWithoutAPI
	}

	host := conf.APIBindTo.Host

	if ip := net.ParseIP(host); ip != nil && ip.IsUnspecified() {
		host = "::1"
		if ip.To4() != nil {
			host = "127.0.0.1"
		}
	}

	transport, _ := http.DefaultTransport.(*http.Transport)
	if transport == nil {
		transport = &http.Transport{}
	}

	transport = transport.Clone()
	transport.Proxy = nil

	return reloadTarget{
		base:  "http://" + net.JoinHostPort(host, strconv.FormatUint(uint64(conf.APIBindTo.Port), 10)),
		token: conf.GetAPIToken(),
		client: &http.Client{
			Transport: transport,
			Timeout:   reloadRequestTimeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

// addr is the API's host:port, as the run prints it.
func (t reloadTarget) addr() string { return strings.TrimPrefix(t.base, "http://") }

// call makes one request with the token and returns the answer's status code;
// a 200's JSON body is decoded into into, when it is given. err is a request
// that got no answer -- value-free, and wrapping the context's error when the
// context ended it -- or errNotJSON.
func (t reloadTarget) call(ctx context.Context, method, path string, into any) (int, error) {
	req, err := http.NewRequestWithContext(ctx, method, t.base+path, nil)
	if err != nil {
		return 0, fmt.Errorf("cannot make the request: %w", err)
	}

	if t.token != "" {
		req.Header.Set("Authorization", "Bearer "+t.token)
	}

	resp, err := t.client.Do(req)
	if err != nil {
		// Its URL is not printed: the path can hold a name that reads as a
		// value.
		if urlErr := (*url.Error)(nil); errors.As(err, &urlErr) {
			err = urlErr.Err
		}

		return 0, err
	}

	defer resp.Body.Close() //nolint: errcheck

	body := io.LimitReader(resp.Body, reloadAnswerLimit)

	if resp.StatusCode == http.StatusOK && into != nil {
		if err := json.NewDecoder(body).Decode(into); err != nil {
			// A body cut short by the context is an interrupt, not an answer
			// of the wrong kind (Task 10's review, M-4).
			if ctx.Err() != nil {
				return 0, ctx.Err()
			}

			return resp.StatusCode, errNotJSON
		}
	}

	io.Copy(io.Discard, body) //nolint: errcheck // only so that the connection can be reused

	return resp.StatusCode, nil
}

// statusLine is an answer's status as the run prints it: the code and the
// standard text for it, never the reason phrase the server sent; the code
// alone when it has no standard text.
func statusLine(code int) string {
	if text := http.StatusText(code); text != "" {
		return strconv.Itoa(code) + " " + text
	}

	return strconv.Itoa(code)
}

// apiFeatures is what the pre-check learned of the running proxy, for the
// read-back's causes.
type apiFeatures struct {
	// forced: it lacks secret-rotation, and --force went past that.
	forced bool
	// secretRead: it advertises GET /secrets/{name}.
	secretRead bool
}

// preCheck is §7.5's question before anything is written: GET /stats, and
// nothing else. An API that cannot be reached, or does not answer 200, is a
// refusal; so is a proxy whose features lack secret-rotation -- an older
// binary, which ignores the [[retiring-secret]] block and so kills the previous
// key at the reload -- unless force, which it reports as forced. An error that
// the context ended wraps the context's error.
func (t reloadTarget) preCheck(ctx context.Context, force bool) (apiFeatures, error) {
	var stats struct {
		Features []string `json:"features"`
	}

	code, err := t.call(ctx, http.MethodGet, "/stats", &stats)

	features := apiFeatures{secretRead: slices.Contains(stats.Features, mtglib.FeatureSecretRead)}

	switch {
	case errors.Is(err, errNotJSON):
		return apiFeatures{}, fmt.Errorf("--reload: GET /stats on the proxy's management API at %s: %w", t.addr(), err)
	case err != nil:
		return apiFeatures{}, fmt.Errorf("--reload: the proxy's management API at %s cannot be reached: %w", t.addr(), err)
	case code != http.StatusOK:
		return apiFeatures{}, fmt.Errorf("--reload: GET /stats on the proxy's management API at %s answered %s",
			t.addr(), statusLine(code))
	case slices.Contains(stats.Features, mtglib.FeatureSecretRotation):
		return features, nil
	case force:
		features.forced = true

		return features, nil
	default:
		return apiFeatures{}, fmt.Errorf("--reload: the running proxy does not advertise %s: it is an older binary, "+
			"which ignores the [[retiring-secret]] block and stops accepting the previous key at the reload; "+
			"upgrade it first, or give --force to reload it anyway", mtglib.FeatureSecretRotation)
	}
}

// readBack is what reloadAndCheck reads back after the reload: the name the
// run rotated or ended, and the names whose expired blocks it pruned that the
// written file still configures. The named one gets all three checks of §7.5,
// each pruned one check 2 (§7.5, "--prune alone"). label is how each is
// printed: never a name that reads as a value. features is the pre-check's,
// which the causes follow.
type readBack struct {
	named    string
	pruned   []string
	label    func(name string) string
	features apiFeatures
}

// reloadAndCheck is §7.5 after the write: POST /reload, which must answer
// 200, then GET /secrets/{name} for each name of back, compared with what the
// written file, after, says:
//
//  1. the named name's primary: the same key, mode and host as the written
//     primary, compared parsed, never as strings;
//  2. retiring_keys (absent means 0): the name's usable entries. The proxy
//     judges them when it handles the GET, after this machine read its clock
//     (Task 10's review, M-1), so now is read just before and just after each
//     GET, and any count from the one after to the one before is right: an
//     entry that expires during the GET is no mismatch, and a proxy whose
//     clock is ahead by more than the round trip is still caught;
//  3. retiring_until, when the run added a block (newUntil is not zero): not
//     before newUntil while that block is usable just after the GET, and
//     otherwise absent or not before it (M-1: an --overlap 1s can end before
//     the read-back). It is the latest until of the name's entries, so an
//     earlier, longer overlap reports a later one (M1 of the review).
//
// Every check that fails is a line of the error, with its likely causes, which
// depend on which way it differs and on the pre-check's features. A refused
// reload is its status line only. An error that the context ended wraps the
// context's error.
func (t reloadTarget) reloadAndCheck(
	ctx context.Context, after *config.Config, back readBack, newUntil time.Time, now func() time.Time,
) error {
	code, err := t.call(ctx, http.MethodPost, "/reload", nil)

	switch {
	case ctx.Err() != nil:
		return fmt.Errorf("the reload was interrupted: %w", ctx.Err())
	case err != nil:
		return fmt.Errorf("the file is rotated, but whether the proxy reloaded it is not known: POST /reload on its "+
			"management API at %s got no answer (%w); POST /reload again, or restart the proxy", t.addr(), err)
	case code != http.StatusOK:
		return fmt.Errorf("%sPOST /reload answered %s; the proxy keeps the secrets it had, and its log says why: "+
			"fix the file if it is refused, then POST /reload again, or restart the proxy",
			fileRotatedNotServed, statusLine(code))
	}

	primaries := after.GetSecrets()

	names := back.pruned
	if back.named != "" {
		names = append([]string{back.named}, back.pruned...)
	}

	var failures []string

	for _, name := range names {
		var info mtglib.SecretInfo

		before := after.GetRetiringSecrets(now())
		code, err := t.call(ctx, http.MethodGet, "/secrets/"+url.PathEscape(name), &info)
		since := after.GetRetiringSecrets(now())

		switch {
		case ctx.Err() != nil && len(failures) > 0:
			return &readBackCut{failures: failures}
		case ctx.Err() != nil:
			return fmt.Errorf("the read-back was interrupted: %w", ctx.Err())
		case errors.Is(err, errNotJSON):
			return fmt.Errorf("the file is rotated and the proxy reloaded it, but GET /secrets/{name} for %s: %w",
				back.label(name), err)
		case err != nil:
			return fmt.Errorf("the file is rotated and the proxy reloaded it, but reading %s back got no answer "+
				"(%w): GET /secrets/{name} on its management API shows what it serves", back.label(name), err)
		case !back.features.secretRead && (code == http.StatusNotFound || code == http.StatusMethodNotAllowed):
			reported := "no secret of that name"
			if code == http.StatusMethodNotAllowed {
				reported = statusLine(code)
			}

			failures = append(failures, fmt.Sprintf("the primary of %s differs (%s vs %s); likely: %s",
				back.label(name), describeWritten(primaries[name]), reported, noSecretReadCause))

			continue
		case code == http.StatusNotFound:
			failures = append(failures, fmt.Sprintf("the primary of %s differs (%s vs no secret of that name); likely: %s",
				back.label(name), describeWritten(primaries[name]), primaryMismatchCauses))

			continue
		case code != http.StatusOK:
			return fmt.Errorf("the file is rotated and the proxy reloaded it, but GET /secrets/{name} for %s answered %s",
				back.label(name), statusLine(code))
		}

		if name == back.named {
			if reported, same := describeServed(primaries[name], info.Secret); !same {
				failures = append(failures, fmt.Sprintf("the primary of %s differs (%s vs %s); likely: %s",
					back.label(name), describeWritten(primaries[name]), reported, primaryMismatchCauses))
			}
		}

		failures = append(failures, back.checkKeys(name, info, before, since)...)

		if name == back.named && !newUntil.IsZero() {
			failures = append(failures, back.checkUntil(name, info, since, newUntil)...)
		}
	}

	if len(failures) == 0 {
		return nil
	}

	return errors.New(fileRotatedNotServed + strings.Join(failures, "\n"+fileRotatedNotServed))
}

// readBackCut is a read-back the first interrupt ended after it had already
// proven failures for earlier names (Task 10's second review, N-D). The
// failures are its text, which the run returns as its error; it wraps
// context.Canceled, so that the run also says the read-back was not finished.
type readBackCut struct {
	failures []string
}

func (c *readBackCut) Error() string {
	return fileRotatedNotServed + strings.Join(c.failures, "\n"+fileRotatedNotServed)
}

func (c *readBackCut) Unwrap() error { return context.Canceled }

// fewerCauses are the causes of a proxy holding fewer previous keys, or an
// earlier end, than the file says.
func (b readBack) fewerCauses() string {
	if b.features.forced {
		return forcedCause + retiringMismatchCauses
	}

	return retiringMismatchCauses
}

// checkKeys is check 2: retiring_keys from the count just after the GET to the
// one just before it.
func (b readBack) checkKeys(name string, info mtglib.SecretInfo, before, since config.RetiringReport) []string {
	most, least := usableOf(before, name), usableOf(since, name)

	expected := strconv.Itoa(most)
	if least != most {
		expected = strconv.Itoa(least) + " to " + strconv.Itoa(most)
	}

	switch {
	case info.RetiringKeys > most:
		return []string{fmt.Sprintf("retiring_keys of %s differs (%s vs %d); likely: %s",
			b.label(name), expected, info.RetiringKeys, retiringSurplusCauses)}
	case info.RetiringKeys < least:
		return []string{fmt.Sprintf("retiring_keys of %s differs (%s vs %d); likely: %s",
			b.label(name), expected, info.RetiringKeys, b.fewerCauses())}
	default:
		return nil
	}
}

// checkUntil is check 3: retiring_until not before newUntil while the new block
// is usable just after the GET; absent or not before it once that block has
// expired.
func (b readBack) checkUntil(name string, info mtglib.SecretInfo, since config.RetiringReport,
	newUntil time.Time,
) []string {
	reported := info.RetiringUntil
	usable := slices.ContainsFunc(since.Usable, func(entry mtglib.RetiringSecret) bool {
		return entry.Name == name && entry.Until.Equal(newUntil)
	})

	if (reported != nil && !reported.Before(newUntil)) || (reported == nil && !usable) {
		return nil
	}

	shown := "none"
	if reported != nil {
		shown = reported.UTC().Format(time.RFC3339)
	}

	return []string{fmt.Sprintf("retiring_until of %s differs (%s or later vs %s); likely: %s",
		b.label(name), newUntil.UTC().Format(time.RFC3339), shown, b.fewerCauses())}
}

// usableOf is how many usable previous keys report holds for name.
func usableOf(report config.RetiringReport, name string) int {
	count := 0

	for _, entry := range report.Usable {
		if entry.Name == name {
			count++
		}
	}

	return count
}

// shape is a secret's mode and, for ee, its fronting host: what of it may be
// printed.
func shape(secret mtglib.Secret) string {
	if secret.Host == "" {
		return secret.Mode.String()
	}

	return secret.Mode.String() + " for " + secret.Host
}

// describeWritten is the written primary, as a mismatch prints it.
func describeWritten(secret mtglib.Secret) string { return "the written key, " + shape(secret) }

// describeServed is what the proxy serves as a mismatch prints it, and whether
// it is the written primary: the same key, mode and host.
func describeServed(written mtglib.Secret, value string) (string, bool) {
	served, err := mtglib.ParseSecret(value)
	if err != nil {
		return "a value that does not parse", false
	}

	switch {
	case served.Key != written.Key:
		return "another key, " + shape(served), false
	case served.Mode != written.Mode || served.Host != written.Host:
		return "the same key, " + shape(served), false
	default:
		return "", true
	}
}

// prunedNames are the names whose blocks the edit removed, as the written file
// shows (a block of before's that after no longer has, compared as the file
// spelled it), that after still configures, other than named: sorted, once
// each.
func prunedNames(before, after *config.Config, named string) []string {
	kept := make(map[config.ConfigRetiringSecret]int, len(after.RetiringSecrets))

	for _, entry := range after.RetiringSecrets {
		kept[entry]++
	}

	served := after.GetSecrets()

	var names []string

	for _, entry := range before.RetiringSecrets {
		if kept[entry] > 0 {
			kept[entry]--

			continue
		}

		if _, configured := served[entry.Name]; configured && entry.Name != named && !slices.Contains(names, entry.Name) {
			names = append(names, entry.Name)
		}
	}

	slices.Sort(names)

	return names
}
