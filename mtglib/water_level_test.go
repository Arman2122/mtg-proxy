package mtglib

import (
	"math"
	"math/big"
	"math/rand/v2"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	// waterLevelInputs is how many seeded random inputs the property tests draw.
	waterLevelInputs = 10_000

	// waterLevelMinTotal is the smallest speed limit the config accepts, and
	// waterLevelMaxParticipants the most participants one secret has: the
	// per-secret entry cap plus the rest entry.
	waterLevelMinTotal        = 8_000
	waterLevelMaxParticipants = 4_097
)

// referenceWaterLevel solves the same problem as waterLevel the way the
// definition reads, and shares nothing with it: no sort, no running pair of
// remaining and k. Every round it gives each unsettled participant an equal
// share of what is left, settles every one whose demand fits in that share all
// at once, and goes round again until nobody fits. What is left over, divided
// among the unsettled, is the level, floored the same way and raised to 1.
func referenceWaterLevel(total int64, demands []int64) int64 {
	if len(demands) == 0 {
		return total
	}

	settled := make([]bool, len(demands))
	remaining, open := total, int64(len(demands))

	for open > 0 {
		share := remaining / open

		var taken, fit int64

		for i, d := range demands {
			d = max(d, 0)
			if !settled[i] && d <= share {
				settled[i] = true
				taken += d
				fit++
			}
		}

		if fit == 0 {
			return max(share, 1)
		}

		remaining -= taken
		open -= fit
	}

	return max(total, 1)
}

// allocations is what each participant gets at a level: its demand, or the
// level if the demand is more.
func allocations(demands []int64, level int64) []int64 {
	out := make([]int64, len(demands))

	for i, d := range demands {
		out[i] = min(max(d, 0), level)
	}

	return out
}

// allocationSum adds the allocations in arbitrary precision, so that a wrong
// level near MaxInt64 fails an assertion instead of wrapping the sum around.
func allocationSum(demands []int64, level int64) *big.Int {
	sum := new(big.Int)

	for _, a := range allocations(demands, level) {
		sum.Add(sum, big.NewInt(a))
	}

	return sum
}

// anyExceeds reports whether some participant wants more than the level.
func anyExceeds(demands []int64, level int64) bool {
	return slices.ContainsFunc(demands, func(d int64) bool { return d > level })
}

// randomWaterLevelInput draws one input. The totals run from 1 to millions and
// the participants from 1 to 50. A profile decides how the demands are spread,
// so that the draw keeps hitting the shapes that matter: mostly throttled
// participants, none throttled with everything fitting, a mix. Inside a profile
// the demands include infinity, zero, a negative, duplicates from a small pool
// and values at the equal share, which is the boundary the loop compares to.
func randomWaterLevelInput(r *rand.Rand) (int64, []int64) {
	total := 1 + r.Int64N([]int64{12, 2_000, 5_000_000}[r.IntN(3)])
	n := 1 + r.IntN(50)
	equal := total / int64(n)

	infinite, span := 5, 2*total+1

	switch r.IntN(4) {
	case 0:
		infinite = 12
	case 1:
		infinite, span = 0, 2*equal+2
	case 2:
		infinite = 2
	}

	pool := [3]int64{r.Int64N(span), r.Int64N(span), r.Int64N(equal + 2)}
	demands := make([]int64, n)

	for i := range demands {
		roll := r.IntN(20)

		switch {
		case roll < infinite:
			demands[i] = demandInfinite
		case roll < infinite+2:
			demands[i] = 0
		case roll == infinite+2 && infinite > 0:
			demands[i] = -1 - r.Int64N(100)
		case roll < infinite+6:
			demands[i] = pool[r.IntN(len(pool))]
		case roll < infinite+8:
			demands[i] = max(0, equal+r.Int64N(5)-2)
		default:
			demands[i] = r.Int64N(span)
		}
	}

	return total, demands
}

func TestWaterLevelCases(t *testing.T) {
	t.Parallel()

	manyInfinite := func(n int) []int64 {
		out := make([]int64, n)
		for i := range out {
			out[i] = demandInfinite
		}

		return out
	}

	cases := []struct {
		name    string
		total   int64
		demands []int64
		want    int64
	}{
		{"no participants returns the total", 100, nil, 100},
		{"an empty slice returns the total", 100, []int64{}, 100},
		{"one participant below the total", 100, []int64{30}, 100},
		{"one participant above the total", 100, []int64{500}, 100},
		{"one participant at infinity", 100, []int64{demandInfinite}, 100},
		{"one participant at zero", 100, []int64{0}, 100},
		{"all infinite share the total equally", 100, manyInfinite(2), 50},
		{"all infinite floor the share", 100, manyInfinite(3), 33},
		{"a floor is a floor, not a rounding", 10, manyInfinite(3), 3},
		{"every demand zero gives the whole total, not the share", 100, []int64{0, 0, 0, 0}, 100},
		{"every demand fits: k reaches zero and the level is the total", 100, []int64{10, 20, 30}, 100},
		{"every demand fits exactly", 60, []int64{10, 20, 30}, 60},
		{"a quiet address leaves its slack to the throttled one, above total/n", 100, []int64{10, demandInfinite}, 90},
		{"two quiet addresses leave theirs to the third", 100, []int64{10, 10, demandInfinite}, 80},
		{"the order of the demands does not matter", 100, []int64{demandInfinite, 10, demandInfinite, 10}, 40},
		{"a demand equal to the share is settled", 11, []int64{5, demandInfinite}, 6},
		{"a demand one above the share is not settled", 10, []int64{6, demandInfinite}, 5},
		{"ties at the infinite end share what is left", 100, []int64{20, 20, demandInfinite, demandInfinite}, 30},
		{"ties at the share settle together", 9, []int64{3, 3, demandInfinite}, 3},
		{"ties above the share stay unsettled together", 10, []int64{5, 5, 5}, 3},
		{"the rise of the share settles a later demand", 100, []int64{10, 40, demandInfinite}, 50},
		{"a chain of settlements, each enabled by the one before", 100, []int64{20, 26, 27, 28}, 27},
		{"a negative demand counts as zero", 10, []int64{-5, demandInfinite}, 10},
		{"the most negative demand counts as zero", 10, []int64{math.MinInt64, demandInfinite}, 10},
		{"a level that would be zero is raised to one", 5, append([]int64{0, 0}, manyInfinite(6)...), 1},
		{"fewer bytes than participants: the floor, never zero", 3, manyInfinite(5), 1},
		{"the smallest limit and one participant", waterLevelMinTotal, manyInfinite(1), waterLevelMinTotal},
		{"the smallest limit and two participants", waterLevelMinTotal, manyInfinite(2), 4_000},
		{"the smallest limit and 4,000 participants", waterLevelMinTotal, manyInfinite(4_000), 2},
		{"the smallest limit and 4,096 participants", waterLevelMinTotal, manyInfinite(4_096), 1},
		{
			"the smallest limit and 4,097 participants: never zero, no larger clamp",
			waterLevelMinTotal, manyInfinite(waterLevelMaxParticipants), 1,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			before := slices.Clone(tc.demands)

			assert.Equal(t, tc.want, waterLevel(tc.total, tc.demands))
			assert.Equal(t, tc.want, referenceWaterLevel(tc.total, tc.demands), "the reference disagrees with the case")
			assert.Equal(t, before, tc.demands, "the demands were changed")
		})
	}
}

func TestWaterLevelMatchesBruteForce(t *testing.T) {
	t.Parallel()

	r := rand.New(rand.NewPCG(4, 2026))

	var exceeding, fitting, floored int

	for range waterLevelInputs {
		total, demands := randomWaterLevelInput(r)
		before := slices.Clone(demands)

		got := waterLevel(total, demands)
		want := referenceWaterLevel(total, before)

		require.Equal(t, want, got, "total=%d demands=%v", total, before)
		require.Equal(t, before, demands, "the demands were changed: total=%d", total)

		switch {
		case anyExceeds(demands, got):
			exceeding++
		default:
			fitting++
		}

		if total < int64(len(demands)) {
			floored++
		}
	}

	// The draw must keep both shapes in play, or the agreement above is about
	// one half of the algorithm.
	assert.Greater(t, exceeding, waterLevelInputs/4, "inputs where some demand exceeds the level")
	assert.Greater(t, fitting, waterLevelInputs/20, "inputs where every demand fits")
	assert.Greater(t, floored, waterLevelInputs/50, "inputs with fewer bytes than participants")
}

func TestWaterLevelProperties(t *testing.T) {
	t.Parallel()

	r := rand.New(rand.NewPCG(8, 2026))

	for range waterLevelInputs {
		total, demands := randomWaterLevelInput(r)
		n := int64(len(demands))
		level := waterLevel(total, demands)

		// The level is a rate: never zero, which would read as unlimited, and
		// never more than there is to give. Asserted first, so that a wild level
		// stops the test before it is summed.
		require.GreaterOrEqual(t, level, int64(1), "total=%d demands=%v", total, demands)
		require.LessOrEqual(t, level, total, "total=%d demands=%v", total, demands)

		// Nobody gets less than an equal share, and the level is above it
		// whenever somebody wants less than that.
		require.GreaterOrEqual(t, level, total/n, "total=%d demands=%v", total, demands)

		if total >= n {
			// With a byte for each participant the floor of 1 never fires, so the
			// allocations add up: never over the total, and short of it by less
			// than a byte per participant when somebody is held at the level.
			sum := allocationSum(demands, level)
			require.LessOrEqual(t, sum.Cmp(big.NewInt(total)), 0, "total=%d demands=%v level=%d", total, demands, level)

			if anyExceeds(demands, level) {
				shortfall := new(big.Int).Sub(big.NewInt(total), sum)
				require.Less(t, shortfall.Cmp(big.NewInt(n)), 0, "total=%d demands=%v level=%d", total, demands, level)
			}
		}

		// The order the demands come in is the caller's accident.
		shuffled := slices.Clone(demands)
		r.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })
		require.Equal(t, level, waterLevel(total, shuffled), "total=%d demands=%v", total, demands)

		// Raising one participant's demand never lowers its own allocation and
		// never raises anyone else's.
		at := r.IntN(len(demands))
		old := max(demands[at], 0)

		if old == demandInfinite {
			continue
		}

		raised := slices.Clone(demands)
		if r.IntN(4) == 0 {
			raised[at] = demandInfinite
		} else {
			raised[at] = old + r.Int64N(2*total+2)
		}

		raisedLevel := waterLevel(total, raised)
		before, after := allocations(demands, level), allocations(raised, raisedLevel)

		require.GreaterOrEqual(t, after[at], before[at], "raising %d of total=%d demands=%v to %d lowered its own allocation", at, total, demands, raised[at])

		for i := range demands {
			if i != at {
				require.LessOrEqual(t, after[i], before[i], "raising %d of total=%d demands=%v to %d raised the allocation of %d", at, total, demands, raised[at], i)
			}
		}
	}
}

// TestWaterLevelRaisingADemandIsMonotonic runs the max-min property over every
// small input rather than a sample: floors can break a property that holds for
// real numbers by one byte, and a small domain is where one byte shows.
func TestWaterLevelRaisingADemandIsMonotonic(t *testing.T) {
	t.Parallel()

	values := []int64{0, 1, 2, 3, 4, 5, demandInfinite}

	var inputs int

	for total := int64(1); total <= 8; total++ {
		for n := 1; n <= 4; n++ {
			demands := make([]int64, n)

			for code := range pow(len(values), n) {
				rest := code
				for i := range demands {
					demands[i] = values[rest%len(values)]
					rest /= len(values)
				}

				inputs++

				level := waterLevel(total, demands)
				require.Equal(t, referenceWaterLevel(total, demands), level, "total=%d demands=%v", total, demands)

				before := allocations(demands, level)

				for at := range demands {
					for _, newValue := range values {
						if newValue <= demands[at] {
							continue
						}

						raised := slices.Clone(demands)
						raised[at] = newValue

						after := allocations(raised, waterLevel(total, raised))

						require.GreaterOrEqual(t, after[at], before[at], "total=%d demands=%v raising %d to %d lowered its own allocation", total, demands, at, newValue)

						for i := range demands {
							if i != at {
								require.LessOrEqual(t, after[i], before[i], "total=%d demands=%v raising %d to %d raised the allocation of %d", total, demands, at, newValue, i)
							}
						}
					}
				}
			}
		}
	}

	assert.Equal(t, 8*(7+49+343+2401), inputs)
}

func pow(base, exp int) int {
	out := 1
	for range exp {
		out *= base
	}

	return out
}

func TestWaterLevelDoesNotChangeTheCallersDemands(t *testing.T) {
	t.Parallel()

	// Not sorted, with a zero, a negative and an infinity: an in-place sort and
	// an in-place clamp of the negative would each show.
	demands := []int64{9, -4, 0, demandInfinite, 3, 7, math.MinInt64, 3}
	before := slices.Clone(demands)

	level := waterLevel(100, demands)

	assert.Equal(t, before, demands)
	assert.Equal(t, waterLevel(100, []int64{0, 0, 3, 3, 7, 9, demandInfinite, 0}), level, "a negative demand counts as zero")
}

func TestWaterLevelNearTheLimitsOfInt64(t *testing.T) {
	t.Parallel()

	const top = int64(math.MaxInt64)

	check := func(t *testing.T, total int64, demands []int64) {
		t.Helper()

		before := slices.Clone(demands)
		level := waterLevel(total, demands)

		require.Equal(t, referenceWaterLevel(total, before), level, "total=%d demands=%v", total, before)
		require.GreaterOrEqual(t, level, int64(1))
		require.LessOrEqual(t, level, total)
		require.LessOrEqual(t, allocationSum(demands, level).Cmp(big.NewInt(total)), 0, "total=%d demands=%v level=%d", total, before, level)

		if anyExceeds(demands, level) {
			shortfall := new(big.Int).Sub(big.NewInt(total), allocationSum(demands, level))
			require.Less(t, shortfall.Cmp(big.NewInt(int64(len(demands)))), 0, "total=%d demands=%v level=%d", total, before, level)
		}
	}

	t.Run("hand cases", func(t *testing.T) {
		t.Parallel()

		assert.Equal(t, top/3, waterLevel(top, []int64{top - 1, top - 2, top - 3}))
		assert.Equal(t, top/2, waterLevel(top, []int64{top, top}))
		assert.Equal(t, (top-1)/2, waterLevel(top, []int64{1, top, top}))
		assert.Equal(t, top, waterLevel(top, []int64{top - 1}))
		assert.Equal(t, top, waterLevel(top, []int64{demandInfinite}))
		assert.Equal(t, top, waterLevel(top, []int64{0, demandInfinite}))
		assert.Equal(t, top/3, waterLevel(top, []int64{top / 2, top / 2, demandInfinite}))
		assert.Equal(t, top-2*(top/3), waterLevel(top, []int64{top / 3, top / 3, demandInfinite}))
		assert.Equal(t, top/2, waterLevel(top, []int64{demandInfinite, demandInfinite}))

		for _, total := range []int64{top, top - 1, top / 2, 1 << 62} {
			check(t, total, []int64{top - 1, top - 2, top - 3})
			check(t, total, []int64{top, top, top, top})
			check(t, total, []int64{1, top, top})
			check(t, total, []int64{total, total, total})
			check(t, total, []int64{total - 1, total / 2, 1, demandInfinite})
		}
	})

	t.Run("random", func(t *testing.T) {
		t.Parallel()

		r := rand.New(rand.NewPCG(16, 2026))

		for range 2_000 {
			total := top - r.Int64N(1<<40)
			demands := make([]int64, 1+r.IntN(8))

			for i := range demands {
				switch r.IntN(4) {
				case 0:
					demands[i] = demandInfinite
				case 1:
					demands[i] = top - r.Int64N(1<<40)
				case 2:
					demands[i] = total/int64(len(demands)) + r.Int64N(5) - 2
				default:
					demands[i] = r.Int64N(total)
				}
			}

			check(t, total, demands)
		}
	})
}

func TestWaterLevelNeverPanics(t *testing.T) {
	t.Parallel()

	totals := []int64{math.MinInt64, -1, 0, 1, 8_000, math.MaxInt64}
	inputs := [][]int64{
		nil,
		{},
		{0},
		{math.MinInt64},
		{demandInfinite},
		{math.MinInt64, math.MaxInt64 - 1, demandInfinite},
		{demandInfinite, demandInfinite, demandInfinite, demandInfinite, demandInfinite},
		{0, 0, 0, 0, 0, 0},
	}

	for _, total := range totals {
		for _, demands := range inputs {
			var level int64

			require.NotPanics(t, func() { level = waterLevel(total, demands) }, "total=%d demands=%v", total, demands)

			if len(demands) > 0 {
				assert.GreaterOrEqual(t, level, int64(1), "the level is never zero: total=%d demands=%v", total, demands)
			}
		}
	}
}
