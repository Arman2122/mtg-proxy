package config_test

import (
	"encoding/json"
	"sort"
	"testing"

	"github.com/Arman2122/mtg-proxy/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// handshakeBudgetMinimal is a config that never mentions the FakeTLS handshake
// budget: the one every deployment written before it existed is.
const handshakeBudgetMinimal = `secret = "7oe1GqLy6TBc38CV3jx7q09nb29nbGUuY29t"
bind-to = "0.0.0.0:3128"
`

func parseHandshakeBudget(t *testing.T, table string) *config.Config {
	t.Helper()

	conf, err := config.Parse([]byte(handshakeBudgetMinimal + table))
	require.NoError(t, err)

	return conf
}

// A config without the table keeps today's behaviour: every getter says "not
// set", which ProxyOpts reads as the defaults (enforce, 50 ms, 25%, hints
// following track-client-ips). Nothing about it is an unknown key either.
func TestHandshakeBudgetAbsentKeepsTodaysBehaviour(t *testing.T) {
	t.Parallel()

	conf := parseHandshakeBudget(t, "")

	assert.Empty(t, conf.GetHandshakeBudgetMode(), "no mode: ProxyOpts reads that as enforce")
	assert.Nil(t, conf.GetHandshakeBudgetPerIPMillis(), "unset is not 0: 0 turns the address bucket off")
	assert.Zero(t, conf.GetHandshakeBudgetCPUPercent(), "no percentage: ProxyOpts reads that as 25")
	assert.Nil(t, conf.GetHandshakeHints(), "unset follows track-client-ips")
	assert.Empty(t, conf.UnknownKeys)

	// An empty table is the same thing as no table.
	empty := parseHandshakeBudget(t, "\n[defense.handshake-budget]\n")

	assert.Empty(t, empty.GetHandshakeBudgetMode())
	assert.Nil(t, empty.GetHandshakeBudgetPerIPMillis())
	assert.Zero(t, empty.GetHandshakeBudgetCPUPercent())
	assert.Nil(t, empty.GetHandshakeHints())
	assert.Empty(t, empty.UnknownKeys)
}

// Config.String() is what a debug log prints, and several tests and an
// operator's grep depend on its shape: a config that does not use the table
// must render exactly the keys it rendered before the table existed.
func TestHandshakeBudgetLeavesConfigStringAloneUntilUsed(t *testing.T) {
	t.Parallel()

	defenseKeys := func(conf *config.Config) []string {
		var fields map[string]any

		require.NoError(t, json.Unmarshal([]byte(conf.String()), &fields))

		defense, ok := fields["defense"].(map[string]any)
		require.True(t, ok, "defense must still be rendered")

		keys := make([]string, 0, len(defense))
		for key := range defense {
			keys = append(keys, key)
		}

		sort.Strings(keys)

		return keys
	}

	assert.Equal(t, []string{"allowlist", "antiReplay", "blocklist", "doppelganger"},
		defenseKeys(parseHandshakeBudget(t, "")),
		"a config that never mentions the table renders no key for it")
	assert.Equal(t, []string{"allowlist", "antiReplay", "blocklist", "doppelganger"},
		defenseKeys(parseHandshakeBudget(t, "\n[defense.handshake-budget]\n")),
		"and neither does one with the table written empty")

	used := parseHandshakeBudget(t, "\n[defense.handshake-budget]\nmode = \"observe\"\n")

	assert.Contains(t, defenseKeys(used), "handshakeBudget", "a config that uses it shows it")
	assert.Contains(t, used.String(), `"mode":"observe"`)
}

func TestHandshakeBudgetModesParse(t *testing.T) {
	t.Parallel()

	for _, mode := range []string{
		config.TypeHandshakeBudgetModeEnforce,
		config.TypeHandshakeBudgetModeObserve,
		config.TypeHandshakeBudgetModeOff,
	} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()

			conf := parseHandshakeBudget(t, "\n[defense.handshake-budget]\nmode = \""+mode+"\"\n")

			assert.Equal(t, mode, conf.GetHandshakeBudgetMode())
			assert.Empty(t, conf.UnknownKeys, "mode is a known key")
		})
	}

	assert.Equal(t, "enforce", config.TypeHandshakeBudgetModeEnforce)
	assert.Equal(t, "observe", config.TypeHandshakeBudgetModeObserve)
	assert.Equal(t, "off", config.TypeHandshakeBudgetModeOff)
}

// The config layer takes exactly the three lower-case words. mtglib's own parser
// is case-insensitive, but only for an embedder: a file that says "OBSERVE" is a
// typo this binary reports rather than guesses at.
func TestHandshakeBudgetInvalidValuesAreRefusedByKey(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name  string
		table string
		key   string
	}{
		{"an unknown mode", "mode = \"audit\"", "mode"},
		{"an upper-case mode", "mode = \"ENFORCE\"", "mode"},
		{"a capitalised mode", "mode = \"Observe\"", "mode"},
		{"a mode with a space", "mode = \"off \"", "mode"},
		{"per-ip-ms past 1000", "per-ip-ms = 1001", "per-ip-ms"},
		{"per-ip-ms far past 1000", "per-ip-ms = 4000000", "per-ip-ms"},
		{"a negative per-ip-ms", "per-ip-ms = -5", "per-ip-ms"},
		{"a negative cpu-percent", "cpu-percent = -1", "cpu-percent"},
		{"an explicit cpu-percent of 0", "cpu-percent = 0", "cpu-percent"},
		{"cpu-percent past 100", "cpu-percent = 101", "cpu-percent"},
		{"cpu-percent far past 100", "cpu-percent = 4000000", "cpu-percent"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := config.Parse([]byte(handshakeBudgetMinimal + "\n[defense.handshake-budget]\n" + tc.table + "\n"))

			require.Error(t, err)
			assert.ErrorContains(t, err, tc.key, "the error must name the key that is wrong")
		})
	}

	_, err := config.Parse([]byte(handshakeBudgetMinimal + "\n[defense.handshake-budget]\nmode = \"audit\"\n"))
	for _, word := range []string{`"enforce"`, `"observe"`, `"off"`} {
		assert.ErrorContains(t, err, word, "the error must name the values that work")
	}
}

// An empty mode is not a fifth word: it is read as unset, like an absent key, and
// enforce is what that means. Today that holds because the TOML mirror drops an
// empty string (omitempty) before the mode type ever sees it; this pins the
// behaviour the documentation states, so a change to the mirror cannot turn
// `mode = ""` into a startup error without a test saying so.
func TestAnEmptyModeIsUnset(t *testing.T) {
	t.Parallel()

	conf := parseHandshakeBudget(t, "\n[defense.handshake-budget]\nmode = \"\"\n")

	assert.Empty(t, conf.GetHandshakeBudgetMode(), "an empty mode is unset, which mtglib reads as enforce")
	assert.Empty(t, conf.UnknownKeys, "mode is still a known key")
	assert.NoError(t, conf.Validate())
}

// The edges of the ranges are valid. An explicit per-ip-ms of 0 is the way to
// switch the per-address bucket off; cpu-percent has no such spelling.
func TestHandshakeBudgetBoundariesAreValid(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		table string
		check func(t *testing.T, conf *config.Config)
	}{
		{"per-ip-ms = 0", func(t *testing.T, conf *config.Config) {
			require.NotNil(t, conf.GetHandshakeBudgetPerIPMillis())
			assert.Zero(t, *conf.GetHandshakeBudgetPerIPMillis())
		}},
		{"per-ip-ms = 1", func(t *testing.T, conf *config.Config) {
			require.NotNil(t, conf.GetHandshakeBudgetPerIPMillis())
			assert.EqualValues(t, 1, *conf.GetHandshakeBudgetPerIPMillis())
		}},
		{"per-ip-ms = 1000", func(t *testing.T, conf *config.Config) {
			require.NotNil(t, conf.GetHandshakeBudgetPerIPMillis())
			assert.EqualValues(t, 1000, *conf.GetHandshakeBudgetPerIPMillis())
		}},
		{"cpu-percent = 1", func(t *testing.T, conf *config.Config) {
			assert.EqualValues(t, 1, conf.GetHandshakeBudgetCPUPercent())
		}},
		{"cpu-percent = 100", func(t *testing.T, conf *config.Config) {
			assert.EqualValues(t, 100, conf.GetHandshakeBudgetCPUPercent())
		}},
	} {
		t.Run(tc.table, func(t *testing.T) {
			t.Parallel()

			tc.check(t, parseHandshakeBudget(t, "\n[defense.handshake-budget]\n"+tc.table+"\n"))
		})
	}
}

// The two keys whose zero or false means something. A pointer in the TOML mirror
// and in Config is what lets an explicit value survive instead of reading as
// "not set": per-ip-ms = 0 turns the address bucket off (unset is 50), and
// hints = false turns the cache off even under track-client-ips (unset follows
// it).
func TestHandshakeBudgetExplicitZeroAndFalseSurvive(t *testing.T) {
	t.Parallel()

	zero := parseHandshakeBudget(t, "\n[defense.handshake-budget]\nper-ip-ms = 0\n")

	require.NotNil(t, zero.GetHandshakeBudgetPerIPMillis(), "an explicit 0 must not read as unset")
	assert.Zero(t, *zero.GetHandshakeBudgetPerIPMillis())

	assert.Nil(t, parseHandshakeBudget(t, "\n[defense.handshake-budget]\nmode = \"off\"\n").GetHandshakeBudgetPerIPMillis(),
		"a table that leaves it out is unset")

	off := parseHandshakeBudget(t, "\n[defense.handshake-budget]\nhints = false\n")

	require.NotNil(t, off.GetHandshakeHints(), "an explicit false must not read as unset")
	assert.False(t, *off.GetHandshakeHints())

	on := parseHandshakeBudget(t, "\n[defense.handshake-budget]\nhints = true\n")

	require.NotNil(t, on.GetHandshakeHints())
	assert.True(t, *on.GetHandshakeHints())

	// Whatever track-client-ips says, the hints key is the authority when present
	// and absent otherwise: Parse never folds one into the other.
	tracked, err := config.Parse([]byte(handshakeBudgetMinimal + "track-client-ips = true\n"))

	require.NoError(t, err)
	assert.True(t, tracked.TrackClientIPs.Get(false))
	assert.Nil(t, tracked.GetHandshakeHints(), "unset stays unset under track-client-ips; ProxyOpts follows it")
}

// A config key here is carried by two structs joined by nothing but a matching
// json tag, and a typo in either is silent. Every key set to a value that is not
// its default proves each one arrives.
func TestHandshakeBudgetRoundTrips(t *testing.T) {
	t.Parallel()

	conf := parseHandshakeBudget(t, `
[defense.handshake-budget]
mode = "observe"
per-ip-ms = 200
cpu-percent = 60
hints = true
`)

	assert.Equal(t, "observe", conf.GetHandshakeBudgetMode())

	require.NotNil(t, conf.GetHandshakeBudgetPerIPMillis())
	assert.EqualValues(t, 200, *conf.GetHandshakeBudgetPerIPMillis())

	assert.EqualValues(t, 60, conf.GetHandshakeBudgetCPUPercent())

	require.NotNil(t, conf.GetHandshakeHints())
	assert.True(t, *conf.GetHandshakeHints())

	assert.Empty(t, conf.UnknownKeys, "none of the four is an unknown key")
	assert.NoError(t, conf.Validate())
}

// The lenient parser still names what it does not know: a typo inside the new
// table is reported, not swallowed.
func TestHandshakeBudgetTypoIsAnUnknownKey(t *testing.T) {
	t.Parallel()

	conf := parseHandshakeBudget(t, "\n[defense.handshake-budget]\nmodes = \"observe\"\nper-ip = 5\n")

	assert.Equal(t,
		[]string{"defense.handshake-budget.modes", "defense.handshake-budget.per-ip"},
		conf.UnknownKeys)
}
