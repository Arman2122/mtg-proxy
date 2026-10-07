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

// waterLevel is the fair-share ticker's split of one secret's speed limit total
// among its participants, whose measured demands in bytes per second are
// demands. It returns the level L at which the sum of min(d, L) over every
// participant is the total: a participant that wants less than L gets what it
// wants, and everyone else gets L. That is a max-min split, and it is
// work-conserving, because what the quiet participants leave unused goes to the
// ones that want more.
//
// The demands are sorted, smallest first, and settled one at a time. With
// remaining starting at the total and k at the number of participants, a demand
// that is no more than an equal share of what remains, remaining/k, is
// subtracted and k drops by one; the first demand that is more, or one that is
// demandInfinite, ends the loop, and the level is an equal share of what is
// left, remaining/k. If every demand was settled there is nobody to hold at a
// level, and the level is the total, which is at least what any of them asked
// for. A settlement can only raise the equal share of what remains, so the
// level is never below total/n, and it rises above it by the slack that the
// quiet participants leave.
//
// All division floors, and a demand of zero or less counts as zero. The result
// is at least 1: a level of zero would read as unlimited. The floor only raises
// a computed 0 to 1, and it can only fire when there are fewer bytes than
// participants, which a speed limit of at least 8,000 bytes a second and the
// at most 4,097 participants of a secret never reach. There is deliberately no
// larger clamp, because a level lifted above what the algorithm computed would
// put the sum of the rates over the total. The total must be positive; with no
// participants it is returned as it is.
//
// The function is pure. It works on a sorted copy, so the caller can go on
// using demands, and no step can divide by zero or overflow: remaining and a
// demand are only subtracted when the demand is at most remaining/k.
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
