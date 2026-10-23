package mtglib

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// BenchmarkScanBudgetReserve is the budget's own cost per scan: the reserve a
// FakeTLS scan makes before it starts and the settle it makes once the handshake
// has succeeded, and nothing else -- no hello, no verification, no socket. It is
// what a scan pays on top of its SHA-256 blocks, a mutex, an address-map lookup
// and one reservation allocation.
//
// The costs are 12 blocks (a real client's 517-byte hello) over 1,000
// candidates, on a real clock. The budget is built so that every reserve is
// granted at once, and settle(true) refunds it in full, so no iteration waits
// for refill or is refused whatever the machine does: the loop times the
// bookkeeping and never the throttle.
//
// keyed is one public address, which has an address bucket as well as the
// process-wide one; unkeyed is nil, which has the process-wide bucket only.
func BenchmarkScanBudgetReserve(b *testing.B) {
	const (
		blocks     = 12
		candidates = 1000
	)

	for _, tc := range []struct {
		name string
		ip   net.IP
		// charges is what a reserve for ip must have charged: the process-wide
		// bucket, and the address's if it is keyed.
		charges int
	}{
		{name: "keyed", ip: net.ParseIP("203.0.113.7"), charges: 2},
		{name: "unkeyed", ip: nil, charges: 1},
	} {
		b.Run(tc.name, func(b *testing.B) {
			budget := newScanBudget(scanBudgetConfig{
				Mode:        budgetEnforce,
				NsPerBlock:  340,
				PerIPMillis: 1000,
				CPUPercent:  100,
				Procs:       1_000_000,
			}, time.Now)

			// Once before the loop, and settled. A budget that is off, a refusal, a
			// wait, or a scan charged to the wrong buckets (an address that is
			// not keyed when it should be, or the reverse) would still run the
			// loop and time something else. It also makes the address's bucket
			// here, so the loop times a reserve that finds it and not the one
			// that creates it.
			res, wait, verdict := budget.reserve(tc.ip, blocks, candidates)
			require.Equal(b, budgetGranted, verdict, "the budget must grant the scan")
			require.Zero(b, wait, "the budget must grant it without a wait")
			require.NotNil(b, res, "the budget must be charging")
			require.Equal(b, tc.charges, res.n, "the scan must be charged to the buckets %s has", tc.name)
			res.settle(true)

			b.ReportAllocs()

			for b.Loop() {
				res, _, verdict := budget.reserve(tc.ip, blocks, candidates)
				if verdict != budgetGranted {
					b.Fatalf("the budget refused a scan it must grant: verdict %d", verdict)
				}

				res.settle(true)
			}
		})
	}
}
