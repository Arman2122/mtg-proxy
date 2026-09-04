package cli

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/Arman2122/mtg-proxy/internal/config"
	"github.com/Arman2122/mtg-proxy/internal/utils"
	"github.com/Arman2122/mtg-proxy/internal/webrelay"
	"github.com/stretchr/testify/require"
)

const oneSecret = `alice = "7oe1GqLy6TBc38CV3jx7q09nb29nbGUuY29t"`

// bob differs from alice in the KEY, not only in the fronting host. Two ee
// secrets that share a key are one WEB profile -- the capability is derived over
// the key alone -- so a fixture that varied the host would be testing a
// collision rather than a second client. See TestReloadRefusesCollidingSecrets.
const twoSecrets = oneSecret + "\n" + `bob = "7ni1GqLy6TBc38CV3jx7q09nb29nbGUuY29t"`

// collidingSecrets is that hazard written down: same key, different fronting
// host. The proxy serves them as two distinct FakeTLS profiles; the relay cannot
// tell them apart at all.
const collidingSecrets = oneSecret + "\n" + `carol = "7oe1GqLy6TBc38CV3jx7q09nb29nbGUuY29u"`

// reloadConfigTOML builds a config whose [web] table and secret set vary
// independently, which is the whole distinction a reload rests on.
//
// The table is assembled from a map rather than concatenated, because TOML
// refuses a duplicated key: an override has to replace the base line, not
// follow it.
func reloadConfigTOML(web map[string]string, listener, secrets string) string {
	table := map[string]string{
		"enabled":   "true",
		"host":      `"proxy.example.com"`,
		"bind-to":   `"127.0.0.1:8099"`,
		"backend":   `"127.0.0.1:2398"`,
		"token-key": `"/etc/mtg-proxy/web.key"`,
		"cover-dir": `"/var/www/site"`,
	}

	for key, value := range web {
		table[key] = value
	}

	keys := make([]string, 0, len(table))
	for key := range table {
		keys = append(keys, key)
	}

	sort.Strings(keys)

	lines := make([]string, 0, len(keys))
	for _, key := range keys {
		lines = append(lines, key+" = "+table[key])
	}

	return fmt.Sprintf(`
secret = "7oe1GqLy6TBc38CV3jx7q09nb29nbGUuY29t"
bind-to = "0.0.0.0:3128"

[[listener]]
bind-to = "127.0.0.1:2398"
accept = ["dd", "plain"]
%s

[web]
%s

[secrets]
%s
`, listener, strings.Join(lines, "\n"), secrets)
}

func reloadStructure(t *testing.T, web map[string]string, listener, secrets string) string {
	t.Helper()

	conf, err := config.Parse([]byte(reloadConfigTOML(web, listener, secrets)))
	require.NoError(t, err)
	require.NoError(t, conf.ValidateWeb())

	structure, err := webStructure(conf)
	require.NoError(t, err)

	return structure
}

// Adding or removing a client changes [secrets] and nothing else, so the
// structure the relay refuses to reload across must not move. If it did, every
// panel-side client change would be answered with "restart required" and the
// reload would exist for nothing.
func TestSecretChangesAreNotStructural(t *testing.T) {
	t.Parallel()

	before := reloadStructure(t, nil, "", oneSecret)
	after := reloadStructure(t, nil, "", twoSecrets)

	require.Equal(t, before, after)

	conf, err := config.Parse([]byte(reloadConfigTOML(nil, "", twoSecrets)))
	require.NoError(t, err)
	require.Len(t, orderedSecrets(conf), 2, "the second client did not reach the relay's profile list")
}

// Everything else does move it, and the relay refuses the reload rather than
// applying half a file. A capability is derived over the host, tokens are signed
// with the key, and the backend is the socket every stream lands on: a process
// that swapped one of them under its own live sessions would be in a state no
// configuration describes.
func TestStructuralChangesAreDetected(t *testing.T) {
	t.Parallel()

	base := reloadStructure(t, nil, "", oneSecret)

	for name, web := range map[string]map[string]string{
		"host":         {"host": `"other.example.com"`},
		"bind-to":      {"bind-to": `"127.0.0.1:9099"`},
		"token-key":    {"token-key": `"/etc/mtg-proxy/other.key"`},
		"cover":        {"cover-dir": `"/var/www/other"`},
		"client-ip":    {"client-ip": `"x-forwarded-for"`},
		"max-sessions": {"max-sessions": "64"},
		"max-streams":  {"max-streams": "64"},
		"payload":      {"max-frame-payload": `"256kb"`},
		"batch":        {"carrier-batch-bytes": `"1mb"`},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			require.NotEqual(t, base, reloadStructure(t, web, "", oneSecret))
		})
	}
}

// A cover site swapped from a directory to an upstream is structural too, and it
// is worth its own case: the two are alternatives, so a file that moved from one
// to the other leaves both fields different from the running set.
func TestSwappingTheCoverSiteIsStructural(t *testing.T) {
	t.Parallel()

	dir := reloadStructure(t, nil, "", oneSecret)
	upstream := reloadStructure(t, map[string]string{
		"cover-dir":      `""`,
		"cover-upstream": `"http://127.0.0.1:8080"`,
	}, "", oneSecret)

	require.NotEqual(t, dir, upstream)
}

// The listener's PROXY-protocol decision is not in [web] at all, and it is the
// one that fails silently: an unexpected header is consumed as the first bytes
// of the client's obfuscated handshake, so every stream dies with nothing to say
// why. A reload that let it change would break every new stream on a relay that
// looks healthy.
func TestTheBackendListenerIsStructuralToo(t *testing.T) {
	t.Parallel()

	plain := reloadStructure(t, nil, "", oneSecret)
	header := reloadStructure(t, nil, "proxy-protocol = true", oneSecret)

	require.NotEqual(t, plain, header)
}

// webStructure enumerates [web] by hand, and an enumeration rots the moment
// somebody adds a field. This is what stops that being silent: a new field
// arrives here as a failing test, and whoever added it has to say whether
// changing it is a reload or a restart. Every field of the table is structural
// today, which is why the list below is simply all of them.
func TestWebStructureCoversTheWholeTable(t *testing.T) {
	t.Parallel()

	covered := map[string]bool{
		"Optional":      true, // the enabled flag; ValidateWeb refuses a disabled table
		"Host":          true,
		"BindTo":        true,
		"Backend":       true,
		"TokenKey":      true,
		"CoverDir":      true,
		"CoverUpstream": true,
		"ClientIP":      true,
		"MaxSessions":   true,
		"MaxStreams":    true,
		"MaxPayload":    true,
		"BatchBytes":    true,
	}

	fields := reflect.TypeOf(config.ConfigWeb{})

	for i := range fields.NumField() {
		name := fields.Field(i).Name

		require.True(t, covered[name],
			"config.ConfigWeb.%s is not accounted for in webStructure: decide whether changing it "+
				"is a reload or a restart, then add it there and here", name)
	}

	require.Len(t, covered, fields.NumField(), "webStructure names a field config.ConfigWeb no longer has")
}

// writeReloadConfig puts a config on disk with a real signing key beside it, so
// the reload path can be driven exactly as the signal handler drives it.
func writeReloadConfig(t *testing.T, dir string, web map[string]string, listener, secrets string) string {
	t.Helper()

	key := filepath.Join(dir, "web.key")
	if _, err := os.Stat(key); os.IsNotExist(err) {
		require.NoError(t, webrelay.GenerateTokenKey(key))
	}

	if web == nil {
		web = map[string]string{}
	}

	// A forward-slashed path so the TOML string needs no escaping on Windows.
	web["token-key"] = `"` + filepath.ToSlash(key) + `"`
	web["cover-dir"] = `"` + filepath.ToSlash(dir) + `"`

	path := filepath.Join(dir, "config.toml")
	require.NoError(t, os.WriteFile(path, []byte(reloadConfigTOML(web, listener, secrets)), 0o600))

	return path
}

// The whole reload, driven the way SIGHUP drives it: a client is added to the
// file on disk, and the running relay starts serving them without restarting.
func TestReloadPicksUpANewClient(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := writeReloadConfig(t, dir, nil, "", oneSecret)

	conf, err := utils.ReadConfig(path)
	require.NoError(t, err)
	require.NoError(t, conf.ValidateWeb())

	log := newRecordingLogger()

	origin, _, err := buildOrigin(conf, log)
	require.NoError(t, err)

	structure, err := webStructure(conf)
	require.NoError(t, err)
	require.Equal(t, 1, origin.Profiles())

	// bob is not served before the reload, and is after it. The count alone
	// would be satisfied by a registry holding the right number of the wrong
	// capabilities -- which is exactly the bug an earlier version of this
	// fixture had.
	writeReloadConfig(t, dir, nil, "", twoSecrets)
	require.False(t, servesBridge(t, origin, path, "bob"), "an unconfigured client was already being served")

	reloadWebProfiles(path, origin, structure, log)

	require.Equal(t, 2, origin.Profiles(), "the added client never reached the running relay")
	require.True(t, servesBridge(t, origin, path, "bob"), "the added client is counted but not served")
	require.True(t, servesBridge(t, origin, path, "alice"), "the existing client stopped being served")
	require.Empty(t, log.recorded(), "a clean reload must report nothing")
}

// servesBridge asks the origin for one named client's bridge page, deriving the
// capability the way the client's own link carries it.
func servesBridge(t *testing.T, origin *webrelay.Origin, configPath, name string) bool {
	t.Helper()

	conf, err := utils.ReadConfig(configPath)
	require.NoError(t, err)

	secret, found := conf.GetSecrets()[name]
	require.True(t, found, "no secret named %s in the config", name)

	capability, err := webrelay.Derive(webrelay.WebSecret(secret), conf.Web.Host.Get(""))
	require.NoError(t, err)

	recorder := httptest.NewRecorder()
	origin.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/?bridge="+capability.String(), nil))

	return recorder.Code == http.StatusOK && strings.Contains(recorder.Body.String(), "TPROXY_BOOT")
}

// A file that changed more than its secrets is refused whole, loudly, and the
// relay keeps serving what it has. Half-applying it is how a process ends up in
// a state no configuration describes.
func TestReloadRefusesAStructuralChange(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := writeReloadConfig(t, dir, nil, "", oneSecret)

	conf, err := utils.ReadConfig(path)
	require.NoError(t, err)

	log := newRecordingLogger()

	origin, _, err := buildOrigin(conf, log)
	require.NoError(t, err)

	structure, err := webStructure(conf)
	require.NoError(t, err)

	// A new hostname AND a new client. Neither is applied: the capability every
	// live client holds was derived over the old host.
	writeReloadConfig(t, dir, map[string]string{"host": `"other.example.com"`}, "", twoSecrets)
	reloadWebProfiles(path, origin, structure, log)

	require.Equal(t, 1, origin.Profiles(), "a structural change was partly applied")
	require.Contains(t, strings.Join(log.recorded(), "\n"), "restart")
}

// An unreadable or invalid file must never take a working relay off the air.
func TestReloadKeepsTheRunningSetOnABadFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := writeReloadConfig(t, dir, nil, "", oneSecret)

	conf, err := utils.ReadConfig(path)
	require.NoError(t, err)

	log := newRecordingLogger()

	origin, _, err := buildOrigin(conf, log)
	require.NoError(t, err)

	structure, err := webStructure(conf)
	require.NoError(t, err)

	require.NoError(t, os.WriteFile(path, []byte("this is not toml at all ]["), 0o600))
	reloadWebProfiles(path, origin, structure, log)

	require.Equal(t, 1, origin.Profiles(), "a broken file emptied the registry")
	require.NotEmpty(t, log.recorded(), "a failed reload said nothing")
}

// A WEB capability is derived over the secret's key and the hostname, and
// nothing else -- so two ee secrets that share a key are indistinguishable here
// however different they look to the proxy, which also matches on the fronting
// host. The relay refuses the whole set rather than picking one: a request
// carrying that capability cannot name a single profile, and quietly resolving
// it to whichever came first would attribute one client's traffic to another.
func TestReloadRefusesCollidingSecrets(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := writeReloadConfig(t, dir, nil, "", oneSecret)

	conf, err := utils.ReadConfig(path)
	require.NoError(t, err)

	log := newRecordingLogger()

	origin, _, err := buildOrigin(conf, log)
	require.NoError(t, err)

	structure, err := webStructure(conf)
	require.NoError(t, err)

	writeReloadConfig(t, dir, nil, "", collidingSecrets)
	reloadWebProfiles(path, origin, structure, log)

	require.Equal(t, 1, origin.Profiles(), "a colliding set was accepted")
	require.Contains(t, strings.Join(log.recorded(), "\n"), "keeping the current one")
}
