package mtglib

import (
	"math"
	"slices"
)

// demandInfinite is the demand of a participant that the fair limiter is
// holding back: it has no measured rate to report, because all it moved is what
// it was let move, and it would take whatever it is given. waterLevel never
// settles one while there is still a share to compute.
const demandInfinite = int64(math.MaxInt64)

// waterLevel splits one secret's speed limit total among its participants, whose
// measured demands in bytes per second are demands, and returns the level L: the
// largest at which the sum of min(d, L) over every participant is at most the
// total (exactly the total, short of a floor remainder, when someone is held at
// L). A participant that wants less than L gets what it wants and the rest get
// L, so what the quiet ones leave unused goes to the ones that want more.
//
// The demands are sorted ascending and settled one at a time: while a demand is
// at most remaining/k (remaining starts at the total, k at the number of
// participants) it is subtracted and k drops by one. The first demand that is
// more, or is demandInfinite, ends the loop, and L is remaining/k, or the total
// if nobody is left. Division floors, a demand of zero or less counts as zero,
// and L is at least total/n, floored. The result is raised to 1, because a zero
// would read as unlimited; spec §3 says why nothing larger clamps it. The total
// must be positive. The function is pure and sorts a copy of demands.
func waterLevel(total int64, demands []int64) int64 {
	n := int64(len(demands))
	if n == 0 {
		return total
	}

	sorted := make([]int64, len(demands))
	for i, d := range demands {
		sorted[i] = max(d, 0)
	}

	slices.Sort(sorted)

	remaining, k := total, n

	for _, d := range sorted {
		if d == demandInfinite || d > remaining/k {
			break
		}

		remaining -= d
		k--
	}

	level := total
	if k > 0 {
		level = remaining / k
	}

	return max(level, 1)
}
