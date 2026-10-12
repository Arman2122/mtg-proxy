package config_test

import (
	"encoding/hex"
	"fmt"
	"math/rand/v2"
	"strings"
	"testing"
	"time"

	"github.com/Arman2122/mtg-proxy/internal/config"
	"github.com/stretchr/testify/require"
)

// The two properties in time of §1.3, over a seeded generator of small files:
// a few names (two configured, one never configured, and "default"), a few
// keys (the primaries' among them), a few untils (ties, expiries around the
// judged instants, and untils on both sides of now + 720h), every mode and
// spelling, and some entries that fail rule 1. Each file is judged at every
// instant of rotGenTimes, and every pair t < t' is checked.

// rotGenFiles is how many files each property judges.
const rotGenFiles = 3000

// rotGenUntils are the untils a generated entry picks from, after rotNow.
var rotGenUntils = []time.Duration{
	-2 * time.Hour, -time.Hour, 0, time.Hour, 2 * time.Hour, 3 * time.Hour, 4 * time.Hour,
	719 * time.Hour, 720 * time.Hour, 721 * time.Hour, 722 * time.Hour, 723 * time.Hour,
}

// rotGenCrowdUntils are the untils of a crowded file's crowd: few, so they tie.
var rotGenCrowdUntils = []time.Duration{time.Hour, 3 * time.Hour, 721 * time.Hour}

// rotGenTimes are the instants every file is judged at, after rotNow,
// ascending: the readings of a high-water clock never go back.
var rotGenTimes = []time.Duration{
	-3 * time.Hour, -time.Hour, 0, 30 * time.Minute, time.Hour, 90 * time.Minute,
	2 * time.Hour, 150 * time.Minute, 3 * time.Hour, 4 * time.Hour, 5 * time.Hour,
}

// rotGenEntry is what the generator wrote for one block.
type rotGenEntry struct {
	name  string
	key   string // the 16-byte key, in hex
	until time.Time
	valid bool // passes rule 1
}

type rotGenFile struct {
	text       string
	entries    []rotGenEntry
	configured map[string]bool
}

// rotGenKeys is the pool of retiring keys: six, so one name can hold more
// than the cap of distinct keys.
func rotGenKeys(rng *rand.Rand) []string {
	keys := make([]string, 6)

	for i := range keys {
		keys[i] = fmt.Sprintf("%016x%016x", rng.Uint64()|1, rng.Uint64())
	}

	return keys
}

// rotGenValue spells key in a random mode and a random spelling.
func rotGenValue(rng *rand.Rand, key string) string {
	var value string

	switch rng.IntN(3) {
	case 0:
		value = rotEE(key)
	case 1:
		value = rotDD(key)
	default:
		value = key
	}

	if rng.IntN(2) == 0 {
		return rotB64(value)
	}

	return value
}

// rotGenUntil spells until as a quoted instant in UTC, a quoted instant with
// an offset, or a TOML offset date-time.
func rotGenUntil(rng *rand.Rand, until time.Time) string {
	switch rng.IntN(3) {
	case 0:
		return fmt.Sprintf("until = %q", until.Format(time.RFC3339))
	case 1:
		return fmt.Sprintf("until = %q", until.In(time.FixedZone("", 3*3600+1800)).Format(time.RFC3339))
	default:
		return "until = " + until.Format(time.RFC3339)
	}
}

func rotGenerate(rng *rand.Rand, keys []string) rotGenFile {
	single := rng.IntN(6) == 0
	names := []string{"alice", "bob", "carol", "default"}
	file := rotGenFile{configured: map[string]bool{"alice": !single, "bob": !single, "default": single}}

	crowd := "alice"
	if single {
		crowd = "default"
	}

	count := rng.IntN(7)

	crowded := rng.IntN(3) == 0
	if crowded {
		count = 5 + rng.IntN(5)
	}

	var blocks strings.Builder

	for range count {
		entry := rotGenEntry{name: names[rng.IntN(len(names))], valid: true}

		switch rng.IntN(10) {
		case 0:
			entry.key = rotKeyAlice
		case 1:
			entry.key = rotKeyBob
		default:
			entry.key = keys[rng.IntN(len(keys))]
		}

		entry.until = rotNow.Add(rotGenUntils[rng.IntN(len(rotGenUntils))])

		// A crowded file piles entries onto one name, from the key pool and
		// from three untils, so rule 8's cut often falls inside a tie.
		if crowded && rng.IntN(4) != 0 {
			entry.name = crowd
			entry.key = keys[rng.IntN(len(keys))]
			entry.until = rotNow.Add(rotGenCrowdUntils[rng.IntN(len(rotGenCrowdUntils))])
		}

		lines := []string{rotName(entry.name), rotSecret(rotGenValue(rng, entry.key)), rotGenUntil(rng, entry.until)}

		switch rng.IntN(16) {
		case 0:
			lines = lines[:2]
			entry.valid = false
		case 1:
			lines[1] = rotSecret(rotEE(rotKeyZero))
			entry.valid = false
		case 2:
			lines[0] = rotName("")
			entry.valid = false
		case 3:
			lines[2] = "until = " + entry.until.Format("2006-01-02T15:04:05")
			entry.valid = false
		}

		blocks.WriteString(rotBlock(lines...))
		file.entries = append(file.entries, entry)
	}

	if single {
		file.text = rotSingleFile(blocks.String())
	} else {
		file.text = rotFile(blocks.String())
	}

	return file
}

// rotJudgeAll parses the file and judges it at every instant of rotGenTimes.
func rotJudgeAll(t *testing.T, file rotGenFile) (*config.Config, []time.Time, []config.RetiringReport) {
	t.Helper()

	conf, err := config.Parse([]byte(file.text))
	require.NoError(t, err, file.text)

	times := make([]time.Time, len(rotGenTimes))
	reports := make([]config.RetiringReport, len(rotGenTimes))

	for i, d := range rotGenTimes {
		times[i] = rotNow.Add(d)
		reports[i] = conf.GetRetiringSecrets(times[i])
	}

	return conf, times, reports
}

// rotPairs is the set of (name, key) pairs report accepts.
func rotPairs(report config.RetiringReport) map[string]bool {
	out := make(map[string]bool, len(report.Usable))

	for _, entry := range report.Usable {
		out[entry.Name+"/"+hex.EncodeToString(entry.Secret.Key[:])] = true
	}

	return out
}

// C9, P1: a file run --check accepts at t -- no problem or warning line, and
// no unknown key -- it accepts at every t' > t. Rules 1 and 5 do not depend on
// time, rules 3 and 8 look only at unexpired entries, rule 4 compares with a
// now that only grows, and entries only ever move into rule 2.
func TestCheckAcceptanceIsMonotoneInTime(t *testing.T) {
	t.Parallel()

	rng := rand.New(rand.NewPCG(0x8a2026, 0x1008))
	keys := rotGenKeys(rng)

	// Floors, so the property cannot pass on files that say nothing.
	var acceptedNonEmpty, acceptedThenExpiring, becameAccepted int

	for f := range rotGenFiles {
		file := rotGenerate(rng, keys)
		conf, times, reports := rotJudgeAll(t, file)

		accepted := func(r config.RetiringReport) bool { return len(r.Lines) == 0 && len(conf.UnknownKeys) == 0 }

		for i := range reports {
			for j := i + 1; j < len(reports); j++ {
				if !accepted(reports[i]) {
					if accepted(reports[j]) {
						becameAccepted++
					}

					continue
				}

				require.True(t, accepted(reports[j]),
					"file %d: accepted at %s, refused at %s with %q\n%s", f, times[i], times[j], reports[j].Lines, file.text)

				if len(reports[i].Usable) > 0 {
					acceptedNonEmpty++
				}

				for _, entry := range reports[i].Usable {
					if !entry.Until.After(times[j]) {
						acceptedThenExpiring++

						break
					}
				}
			}
		}
	}

	t.Logf("accepted with usable entries: %d; accepted, then an entry expired: %d; refused, then accepted: %d",
		acceptedNonEmpty, acceptedThenExpiring, becameAccepted)

	require.GreaterOrEqual(t, acceptedNonEmpty, 1000, "accepted files with usable entries")
	require.GreaterOrEqual(t, acceptedThenExpiring, 200, "accepted files whose entries then expire")
	require.GreaterOrEqual(t, becameAccepted, 200, "refused files that are accepted later")
}

// C12, P2 (R0): a (name, key) pair run does not accept at t -- absent from
// Usable -- it does not accept at any t' > t, whatever the rule that dropped
// it. The instants are what a high-water clock reads: they never go back.
func TestRunNeverAcceptsAKeyItDropped(t *testing.T) {
	t.Parallel()

	rng := rand.New(rand.NewPCG(0x8a2026, 0x1008))
	keys := rotGenKeys(rng)

	// Floors: each counts the cases one way of breaking P2 needs, so none of
	// them passes for want of a case.
	var droppedLive, capTies, collisionsCrossing, overLongCrossing int

	for f := range rotGenFiles {
		file := rotGenerate(rng, keys)
		_, times, reports := rotJudgeAll(t, file)

		pairs := make([]map[string]bool, len(reports))
		for i := range reports {
			pairs[i] = rotPairs(reports[i])
			capTies += rotCapTies(file, reports[i])
		}

		for i := range reports {
			for j := i + 1; j < len(reports); j++ {
				for _, entry := range file.entries {
					if !entry.valid {
						continue
					}

					pair := entry.name + "/" + entry.key

					if !pairs[i][pair] {
						require.False(t, pairs[j][pair],
							"file %d: %s/key %s dropped at %s, accepted at %s\n%s",
							f, entry.name, rotGenLabel(keys, entry.key), times[i], times[j], file.text)

						if entry.until.After(times[j]) {
							droppedLive++
						}
					}

					if entry.until.After(times[i].Add(720*time.Hour)) && !entry.until.After(times[j].Add(720*time.Hour)) &&
						pairs[j][pair] {
						overLongCrossing++
					}
				}

				collisionsCrossing += rotCollisionsCrossing(file, times[i], times[j])
			}
		}
	}

	t.Logf("dropped and still unexpired later: %d; rule-8 ties at the cut: %d; "+
		"collisions whose one side expires between: %d; over-long entries that stop being over-long: %d",
		droppedLive, capTies, collisionsCrossing, overLongCrossing)

	require.GreaterOrEqual(t, droppedLive, 1000, "dropped pairs still unexpired later")
	require.GreaterOrEqual(t, capTies, 50, "rule-8 cuts between entries with the same until")
	require.GreaterOrEqual(t, collisionsCrossing, 50, "cross-name collisions where one side expires in between")
	require.GreaterOrEqual(t, overLongCrossing, 50, "usable entries that cross now + 720h")
}

// rotGenLabel names a key by its place in the pool, never by its bytes.
func rotGenLabel(keys []string, key string) string {
	for i, k := range keys {
		if k == key {
			return fmt.Sprintf("pool #%d", i)
		}
	}

	if label, known := rotLabels[key]; known {
		return label
	}

	return "unknown"
}

// rotCapTies counts the per-name rule-8 drops in report whose entry has the
// same until as an entry of its name that was kept: the cut fell inside a
// tie, which only key bytes break.
func rotCapTies(file rotGenFile, report config.RetiringReport) int {
	ties := 0

	for _, line := range report.Lines {
		if !strings.Contains(line, whyOverCapName) {
			continue
		}

		var n int
		if _, err := fmt.Sscanf(line, "retiring-secret #%d", &n); err != nil || n < 1 || n > len(file.entries) {
			continue
		}

		dropped := file.entries[n-1]

		for _, kept := range report.Usable {
			if kept.Name == dropped.name && kept.Until.Equal(dropped.until) {
				ties++

				break
			}
		}
	}

	return ties
}

// rotCollisionsCrossing counts the pairs of valid entries of two configured
// names with one key where one expires in (from, to] and the other is still
// unexpired at to.
func rotCollisionsCrossing(file rotGenFile, from, to time.Time) int {
	count := 0

	for a, first := range file.entries {
		for _, second := range file.entries[a+1:] {
			if !first.valid || !second.valid || first.key != second.key || first.name == second.name ||
				!file.configured[first.name] || !file.configured[second.name] {
				continue
			}

			for _, pair := range [][2]rotGenEntry{{first, second}, {second, first}} {
				expiring, staying := pair[0], pair[1]
				if expiring.until.After(from) && !expiring.until.After(to) && staying.until.After(to) {
					count++
				}
			}
		}
	}

	return count
}
