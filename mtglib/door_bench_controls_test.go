package mtglib

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/time/rate"
)

// The per-address controls, end to end through ServeConn: BenchmarkDoorBulk's
// download rows with a control on the secret. This file is not in the old
// binary of an A/B -- there is no control to time there -- so BenchmarkDoorBulk
// itself, which both binaries run, stays in door_bench_test.go, untouched.

// benchDoorRate is the rate of every limit the controls rows set: the
// client-speed of a ceiling row, and the speed and the fair share's total of a
// fair row. Far above anything a socket carries -- a loopback door moves a few
// gigabytes a second -- so that no wait has to sleep, and not so large that it
// stops being a rate the code can read back: at benchCeiling the float a bucket
// holds is 2^63, which an int64 does not, and assertFairInvariant converts the
// limit it reads back. 2^62 is exact in both, and a bucket short of tokens by
// 4 GB is due less than a nanosecond.
const benchDoorRate = 1 << 62

// doorControl is a control for a row's secret, and the name of the row.
type doorControl struct {
	name   string
	limits SecretLimits
}

var (
	// ceilingControl is client-speed far above anything a socket carries: every
	// keyed stream pays its address's bucket on every write, and the bucket never
	// holds it back.
	ceilingControl = doorControl{
		name:   "ceiling",
		limits: SecretLimits{ClientSpeedBytesPerSecond: benchDoorRate},
	}

	// fairControl is client-fair on a combined speed far above link speed: every
	// keyed stream pays its address's fair share and the user's bucket the share
	// divides, bracketing each wait with the share's tracker, and the proxy's
	// ticker re-rates the shares every second. The speed never binds, so the
	// shares stay at the total.
	fairControl = doorControl{
		name:   "fair",
		limits: SecretLimits{SpeedBytesPerSecond: benchDoorRate, ClientFair: true},
	}
)

// controlShape is where a row's connections come from: the shapes of
// BenchmarkDoorBulk.
type controlShape struct {
	conns  int
	addr   string
	addrOf func(i int) net.Addr
	places int
}

var controlShapes = []controlShape{
	{conns: 1, addr: "stamped", addrOf: distinctAddr, places: 1},
	{conns: 16, addr: "stamped", addrOf: distinctAddr, places: 16},
	{conns: 16, addr: "shared", addrOf: sharedAddr, places: 1},
}

// governed is dc with its door built for alice under the control, with the
// proxy's fair-share ticker running when the control is a fair share, as
// NewProxy runs it: the harness is a Proxy literal, and nothing starts it
// otherwise. It hands what it built to built. This is how a limit reaches
// stampedDoor and benchDoorBulkStamped, which build the door from the limits
// the door case passes, and pass none.
func (c doorControl) governed(dc doorCase, built func(h *entryHarness)) doorCase {
	build := dc.build

	dc.build = func(tb testing.TB, secrets map[string]Secret, _ map[string]SecretLimits) *entryHarness {
		tb.Helper()

		h := build(tb, secrets, map[string]SecretLimits{"alice": c.limits})

		if c.limits.ClientFair {
			h.proxy.startFairShare(h.proxy.ctx, fairTickInterval)
		}

		built(h)

		return h
	}

	return dc
}

// BenchmarkDoorBulkControls is BenchmarkDoorBulk's tracked download -- clients
// that are not on loopback, each stamped with a documentation address, on a
// proxy that keeps client addresses -- from a secret with a per-address
// control that never holds anything back. Its rows are the tracked rows of
// BenchmarkDoorBulk with a ceiling or a fair share added, so in one binary a
// row over its twin there is what the control costs a stream that it does not
// slow.
//
// <door>/conns=<n>/addr=<stamped|shared>/ceiling is client-speed far above any
// socket's rate: every write pays its address's bucket first. .../fair is
// client-fair on a combined speed far above link speed: every write pays the
// address's fair share and the user's bucket, each bracketed by the share's
// tracker, and the proxy's one-second ticker runs, so its work is in the figure.
//
// Each row proves what it timed (see requireControlOnPath): the proxy saw the
// stamped places, the bytes were counted once on the user and on the places'
// entries, the entries carry the control and only that, and nothing was held
// at an address's limiter. A fair row also proves that the ticker ticked and
// decided: a row shorter than two ticks waits out the rest after its loop,
// untimed.
func BenchmarkDoorBulkControls(b *testing.B) {
	for _, name := range []string{"ee-unpaced", "dd", "plain"} {
		dc := doorNamed(name)

		for _, shape := range controlShapes {
			for _, control := range []doorControl{ceilingControl, fairControl} {
				row := fmt.Sprintf("%s/conns=%d/addr=%s/%s", name, shape.conns, shape.addr, control.name)

				b.Run(row, func(b *testing.B) { benchDoorBulkControl(b, dc, control, shape) })
			}
		}
	}
}

// benchDoorBulkControl is benchDoorBulkStamped, tracked, for a door whose secret
// carries the control, and then the check of what the entries carry and what the
// control did.
func benchDoorBulkControl(b *testing.B, dc doorCase, control doorControl, shape controlShape) {
	b.Helper()

	var door *entryHarness

	governed := control.governed(dc, func(built *entryHarness) { door = built })

	benchDoorBulkStamped(b, governed, shape.conns, shape.addrOf, shape.places, true)

	requireControlOnPath(b, door.proxy, control, shape.places)
}

// requireControlOnPath reads back, from the proxy's own table and counters after
// a row's loop, that the row timed the control it is named for. A stream that
// reached no limiter, a limiter on some of the places only, a limiter that held
// the stream back, or a ticker that never ran would all pass the byte counts of
// benchDoorBulkStamped, which are the user's.
//
//   - Every place the streams are at has its own entry, no rest entry exists,
//     and every live stream holds one of them: the entry is what a stream pays.
//   - Every entry carries the control the row is named for, and only that: the
//     ceiling at the rate and burst of client-speed, or none; and the fair
//     limiters by assertFairInvariant, the check fair share's duty rests on, with
//     the secret's totals, or with none for a ceiling row, which then also
//     proves no fair limiter is anywhere.
//   - The user carries the combined speed a fair share divides, or none.
//   - The bytes are counted once on the entries as on the user: every place moved
//     its share of what the user's counter says, and nothing came in.
//   - Nothing was held at an address's limiter, on the entry or on the user's
//     tally of it. The user's own bucket is not read: its throttled time counts
//     every call, sleeping or not. At benchDoorRate it cannot sleep.
//   - A fair row's ticker ticked, and decided: the table holds the secret's level.
func requireControlOnPath(b *testing.B, p *Proxy, control doorControl, places int) {
	b.Helper()

	st := p.stats.getOrCreate("alice")

	// benchDoorBulkStamped has made the user's counter byte-exact against the
	// iterations, so it is what the entries are held to.
	total := st.bytesOut.Load()
	require.Positive(b, total, "the loop moved nothing")
	require.Zero(b, total%int64(places), "the places must have moved the same")

	entries := controlEntries(b, p, "alice", places)
	perPlace := total / int64(places)

	// The wrapper counts a byte on the entry after the user's, so the last
	// chunk's count may still be arriving, as the user's is in benchDoorBulkStamped.
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(time.Millisecond) {
		if entriesHold(entries, perPlace) {
			break
		}
	}

	for _, entry := range entries {
		require.Equal(b, perPlace, entry.bytesOut.Load(), "every byte sent down must be counted on its place's entry, once")
		require.Zero(b, entry.bytesIn.Load(), "a download reads nothing from the client")
		require.Zero(b, entry.throttledNanos.Load(), "the entry's limiter held the stream back: it timed a sleep")

		ceiling := entry.ceiling.limiter.Load()

		if rateOf := control.limits.ClientSpeedBytesPerSecond; rateOf > 0 {
			require.NotNil(b, ceiling, "entry %q must carry the ceiling", entry.key)
			require.Equal(b, rate.Limit(rateOf), ceiling.Limit(), "entry %q: the ceiling's rate", entry.key)
			require.Equal(b, ceilingBurst(rateOf), ceiling.Burst(), "entry %q: the ceiling's burst", entry.key)
		} else {
			require.Nil(b, ceiling, "entry %q must carry no ceiling: it would time the ceiling's wait under fair share's name", entry.key)
		}
	}

	require.True(b, assertFairInvariant(b, p.clients, "alice", control.limits.fairTotals()),
		"the entries must carry the fair share the secret has, or none")
	require.Zero(b, st.clientThrottledNanos.Load(), "an address's limiter held the user's streams back: it timed a sleep")

	if speed := control.limits.SpeedBytesPerSecond; speed > 0 {
		require.EqualValues(b, speed, st.speed.bytesPerSecond(), "the user must carry the speed the fair share divides")
	} else {
		require.Nil(b, st.speed.limiter.Load(), "the user must carry no speed of its own")
	}

	if control.limits.ClientFair {
		requireFairTicked(b, p.clients, "alice")
	}
}

// controlEntries are the entries of name's secret in the proxy's table, read
// back: one per place, none of them the rest entry, and each held by the live
// streams, which together hold all of them.
func controlEntries(tb testing.TB, p *Proxy, name string, places int) []*clientEntry {
	tb.Helper()

	entries := p.clients.snapshot(name)
	require.Len(tb, entries, places, "the table must hold an entry for every place the streams are at, and no more")

	table := make(map[*clientEntry]struct{}, len(entries))

	for _, entry := range entries {
		require.False(tb, entry.rest, "a stamped stream must have an address's own entry, not the rest entry")

		table[entry] = struct{}{}
	}

	p.liveMu.Lock()
	defer p.liveMu.Unlock()

	held := make(map[*clientEntry]struct{}, len(entries))

	for stream := range p.liveConns[name] {
		entry := stream.addrEntry.Load()
		require.NotNil(tb, entry, "every stream must hold an entry")

		_, inTable := table[entry]
		require.True(tb, inTable, "a stream's entry must be one the table holds")

		held[entry] = struct{}{}
	}

	require.Len(tb, held, places, "the streams must hold every entry of the table")

	return entries
}

// entriesHold says whether every entry has counted perPlace bytes sent down.
func entriesHold(entries []*clientEntry, perPlace int64) bool {
	for _, entry := range entries {
		if entry.bytesOut.Load() != perPlace {
			return false
		}
	}

	return true
}

// requireFairTicked requires that the proxy's ticker has ticked name's secret
// and decided: the table holds the secret's level for the combined bucket, which
// takes a baseline tick and a deciding one. It waits for the second tick if the
// row ended before it -- after the timed loop, so the wait is not in the figure.
func requireFairTicked(tb testing.TB, table *clientTable, name string) {
	tb.Helper()

	level := func() int64 { return fairLevelOf(table, name, fairSpeedBucket) }

	for deadline := time.Now().Add(10 * time.Second); level() == 0 && time.Now().Before(deadline); {
		time.Sleep(10 * time.Millisecond)
	}

	require.Positive(tb, level(), "the proxy's fair-share ticker must have ticked and decided")
}
