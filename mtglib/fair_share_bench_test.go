package mtglib

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// What fair share costs and how fast it takes hold, measured locally: the
// ticker's work per tick of one fair secret, and the ticks a share takes to
// reach the max-min level when thousands of addresses use one secret.

// fairBenchTotal is the secret's speed-down in these benchmarks, 100 MB/s:
// fast enough that the fair limiters' burst is at its 4 MiB cap.
const fairBenchTotal = 100_000_000

// BenchmarkFairTick is one tick of one fair secret with n live entries, up to
// the per-secret cap: what the ticker does once a second per fair secret. Each
// second every entry moved a relay buffer and half of them spent most of it
// waiting, so every one takes part and half are throttled; what the entries do
// between ticks is not timed.
func BenchmarkFairTick(b *testing.B) {
	for _, n := range []int{16, 512, maxClientsPerSecret} {
		b.Run(fmt.Sprintf("entries=%d", n), func(b *testing.B) {
			clock := newFakeAddrClock()
			table := newClientTable(clock.clock())
			secret := fairSecret{name: "alice", totals: fairTotals{Down: fairBenchTotal}}
			entries := make([]*clientEntry, n)

			for i := range entries {
				entries[i] = table.acquire("alice", syntheticClientKey(i), true, entryInit{FairTotals: secret.totals})
			}

			table.tick(clock.read(), secret)

			b.ReportAllocs()

			for b.Loop() {
				b.StopTimer()

				start := clock.read()

				for i, entry := range entries {
					entry.bytesOut.Add(DefaultBufferSize)

					if i%2 == 0 {
						entry.blockedDown.enter(start)
						entry.blockedDown.leave(start.Add(600 * time.Millisecond))
					}
				}

				clock.advance(fairTestTick)

				b.StartTimer()

				table.tick(clock.read(), secret)
			}
		})
	}
}

// BenchmarkFairShareSettling is how many ticks a share takes to settle with n
// live addresses, on the whole-path model of fair_share_sim_test.go: a quarter
// of them greedy, one connection each, the rest asking for 1-10 KB/s, 100 MB/s
// of speed-down among them, fair share on from the start -- the 12a review's
// case -- and, for comparison, the same with fair share off.
//
// A new fair limiter starts with its full fixed burst, 4 MiB at this total,
// and a share only binds once that has drained (the spec's Risks: about n/60
// seconds at the cap). Until then the user's bucket splits by connection, and
// its queue of greedy pieces is what every quiet piece waits behind. Three
// metrics: the tick from which the level stays within 1% of the max-min level
// (-1 for never), the tick from which the quiet addresses together get at
// least 95% of what they ask for (-1 for never), and the share of it they got
// over the last 50 ticks. The quiet clients here ask again only once a piece
// has arrived, so a wait in that queue costs them rate, not only latency.
//
// Run it on its own, once: -run '^$' -bench FairShareSettling -benchtime 1x.
func BenchmarkFairShareSettling(b *testing.B) {
	for _, n := range []int{1024, 2048, maxClientsPerSecret} {
		for _, on := range []bool{true, false} {
			b.Run(fmt.Sprintf("entries=%d/fair=%v", n, on), func(b *testing.B) {
				var settled fairSettling

				for b.Loop() {
					settled = fairSettlingRun(b, n, on)
				}

				b.ReportMetric(float64(settled.level), "ticks-to-level")
				b.ReportMetric(float64(settled.quiet), "ticks-to-quiet-met")
				b.ReportMetric(settled.quietShare*100, "quiet-%-met")
			})
		}
	}
}

// fairSettling is what fairSettlingRun found: the tick from which the level
// stays within 1% of the max-min level, the tick from which the quiet
// addresses' demand stays 95% met, each -1 for never, and the share of that
// demand they got over the run's last 50 ticks.
type fairSettling struct {
	level, quiet int
	quietShare   float64
}

// fairSettlingRun runs BenchmarkFairShareSettling's model with n addresses for
// 200 ticks.
func fairSettlingRun(tb testing.TB, n int, fairOn bool) fairSettling {
	tb.Helper()

	const (
		ticks = 200
		tail  = 50
	)

	s := newPathSim(tb, fairDownBucket, fairBenchTotal)
	s.fairOn = fairOn

	demands := make([]int64, 0, n)

	var asked int64

	for i := range n {
		if i%4 == 0 {
			s.join(syntheticClientKey(i), true, 0, pathGreedy(1, false)...)
			demands = append(demands, demandInfinite)

			continue
		}

		demand := int64(1_000 * (1 + i%10))
		s.join(syntheticClientKey(i), true, 0, pathAsking(float64(demand))...)
		demands = append(demands, demand)
		asked += demand
	}

	want := waterLevel(fairBenchTotal, demands)

	s.run(ticks)

	quietMoved := func(row pathRow) int64 {
		var moved int64

		for i, d := range demands {
			if d != demandInfinite {
				moved += row.moved[i]
			}
		}

		return moved
	}

	// settledFrom is the first tick from which ok holds to the end of the run.
	settledFrom := func(ok func(row pathRow) bool) int {
		settled := -1

		for tick := ticks - 1; tick > 0 && ok(s.rows[tick]); tick-- {
			settled = tick
		}

		return settled
	}

	var lately int64
	for tick := ticks - tail; tick < ticks; tick++ {
		lately += quietMoved(s.rows[tick])
	}

	settled := fairSettling{
		level: settledFrom(func(row pathRow) bool { return row.level >= want*99/100 && row.level <= want*101/100 }),
		quiet: settledFrom(func(row pathRow) bool { return quietMoved(row) >= asked*95/100 }),

		quietShare: float64(lately) / float64(asked*tail),
	}

	require.Positive(tb, settled.quietShare, "the quiet addresses moved")

	return settled
}
