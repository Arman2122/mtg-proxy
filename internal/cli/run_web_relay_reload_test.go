package cli

import (
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/Arman2122/mtg-proxy/internal/config"
	"github.com/stretchr/testify/require"
)

const oneSecret = `alice = "7oe1GqLy6TBc38CV3jx7q09nb29nbGUuY29t"`

const twoSecrets = oneSecret + "\n" + `bob = "7oe1GqLy6TBc38CV3jx7q09nb29nbGUuY29u"`

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
