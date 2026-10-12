package mtglib

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// Benchmarks of the two paths secret rotation added outside the doors (the
// doors' own rows are BenchmarkDoorHandshakeRetiring, in door_bench_test.go).
// Neither opens a socket: they time the engine's functions on sets and streams
// built up front, and each proves, before and after its loop, that it timed the
// path it names. No key is ever formatted: an assertion says counts and labels.
//
// BenchmarkBuildSecretSetAt/secrets=5000/retiring=<R> times buildSecretSetAt, the
// builder every swap, reload and expiry sweep runs, over 5,000 ee secrets and R
// retiring entries handed in: 0 (the set a proxy without a [[retiring-secret]]
// table builds, nil retiring list), 100, and 4096, the most a set keeps
// (MaxRetiringSecrets). The entries are old keys of R distinct names, one each,
// all valid under the rules the file enforces (distinct keys, none a primary's,
// not expired, names configured), so none is dropped: the row counts them kept,
// and the candidates they add (every key is ee), in every iteration.
//
// BenchmarkCloseStaleConns/<rotation|unrelated> times closeStaleConns, the walk
// a swap makes over the live registry under liveMu (so the time every admission
// waits for it), with 10,000 live streams: 1,000 names of 10 streams each. It is
// the function itself, called with the old set, the new set and the swap's
// instant, on streams registered the way a door registers them.
//
//   - rotation: the swap is a rotation. Every name gets a new primary and its old
//     key becomes a retiring entry; the streams hold the old keys. The held keys
//     of every name changed, so the fast path cannot apply and every one of the
//     10,000 streams is judged by its own key (the new set accepts it as a
//     retiring key); none is closed, which is what a rotation does (L1), so each
//     iteration does identical work. Before the loop an extra name, "canary",
//     is re-keyed with no overlap in the same swap: its streams must be the only
//     ones the call closes, which shows that the judgment is by key and live. The
//     canary's streams are unregistered afterwards, so the timed registry is the
//     10,000 alone.
//   - unrelated: the swap changes nothing about the keys of the streams (an
//     ad tag, here, for every name), on a set that already holds a retiring
//     entry for every name, half the streams on the old key and half on the new.
//     The held keys of every name are the same, so the fast path applies to every
//     name: closeStaleConns compares the keys the two sets hold and judges no
//     stream. Before the loop the call is made with staleSkipHook on, which must
//     hear of every name once and close nothing; the hook is off in the loop,
//     where its mutex or closure would be timed inside the fast path.

// benchRotationBuildSecrets is how many primaries the build rows host.
const benchRotationBuildSecrets = 5000

// benchRotationOverlap is how long after the swap's instant the retiring entries
// of these rows stop being accepted.
const benchRotationOverlap = 24 * time.Hour

// rotationBenchName is the name of user i in these rows; zero-padded so that
// names sort in the order of i.
func rotationBenchName(i int) string {
	return fmt.Sprintf("u%05d", i)
}

// rotationBenchSecret is an ee secret on a key of its own: numberedKey makes the
// key from marker and i, so no two secrets of different markers or numbers share
// one, and none is all-zero.
func rotationBenchSecret(marker byte, i int) Secret {
	return eeSecretOf(numberedKey(marker, i), govCoverHost)
}

func BenchmarkBuildSecretSetAt(b *testing.B) {
	for _, retiring := range []int{0, 100, 4096} {
		b.Run(fmt.Sprintf("secrets=%d/retiring=%d", benchRotationBuildSecrets, retiring), func(b *testing.B) {
			benchBuildSecretSetAt(b, benchRotationBuildSecrets, retiring)
		})
	}
}

func benchBuildSecretSetAt(b *testing.B, primaries, retiring int) {
	b.Helper()

	now := rotationNow
	secrets := make(map[string]Secret, primaries)

	for i := range primaries {
		secrets[rotationBenchName(i)] = rotationBenchSecret(0x11, i)
	}

	// nil, not empty, when there is nothing to hand: the list a swap of a file
	// without the table passes.
	var handed []RetiringSecret

	if retiring > 0 {
		handed = make([]RetiringSecret, 0, retiring)
	}

	for i := range retiring {
		handed = append(handed, RetiringSecret{
			Name: rotationBenchName(i), Secret: rotationBenchSecret(0x22, i), Until: now.Add(benchRotationOverlap),
		})
	}

	b.ReportAllocs()

	var (
		set   *secretSet
		drops []retiringDrop
	)

	for b.Loop() {
		set, drops = buildSecretSetAt(secrets, nil, nil, nil, handed, now)

		// Counts only, every iteration: a build that dropped an entry, or kept
		// fewer than the row's label, is timing a different set.
		if len(drops) != 0 || len(set.retiring) != retiring {
			b.Fatalf("the build kept %d of %d retiring entries and dropped %d", len(set.retiring), retiring, len(drops))
		}
	}

	requireBuiltSet(b, set, drops, primaries, retiring, now)
}

// requireBuiltSet reads a built set back: primaries names, retiring entries
// kept and none dropped, every key a candidate (ee), the retiring candidates
// after the primaries, and every retiring field nil or zero when none was
// handed in. It formats counts and booleans only.
func requireBuiltSet(b *testing.B, set *secretSet, drops []retiringDrop, primaries, retiring int, now time.Time) {
	b.Helper()

	require.Zero(b, len(drops), "no entry may be dropped")
	require.Equal(b, primaries, len(set.names))
	require.Equal(b, primaries, len(set.secrets))
	require.Equal(b, retiring, len(set.retiring), "every retiring entry must be kept")
	require.Equal(b, primaries+retiring, len(set.cands), "every key is ee, so every key is a candidate")
	require.Equal(b, primaries, set.primaryEnd(), "the retiring candidates come after every primary")
	require.Equal(b, retiring, len(set.candRetiring))
	require.Equal(b, retiring, len(set.retiringOf), "one entry for each of retiring names")

	positions := 0
	for _, at := range set.retiringCands {
		positions += len(at)
	}

	require.Equal(b, retiring, positions)

	if retiring == 0 {
		require.True(b, set.retiring == nil, "a set without a retiring entry has no retiring list")
		require.True(b, set.retiringOf == nil)
		require.True(b, set.candRetiring == nil)
		require.True(b, set.retiringCands == nil)
		require.Zero(b, set.primaryCands)
		require.True(b, set.retiringNext.IsZero())

		return
	}

	require.True(b, set.retiringNext.Equal(now.Add(benchRotationOverlap)), "retiringNext is the earliest until")
}

// staleWorld is a proxy with live streams and the two sets one closeStaleConns
// call judges them between.
type staleWorld struct {
	p      *Proxy
	oldSet *secretSet
	newSet *secretSet
	now    time.Time

	// streams are the live streams, in name order.
	streams []*streamContext
}

const (
	benchStaleNames   = 1000
	benchStalePerName = 10
	benchStaleStreams = benchStaleNames * benchStalePerName
)

// liveStreamCount is how many streams the registry holds, and in how many
// names, counted under the lock it is written under.
func liveStreamCount(p *Proxy) (streams, names int) {
	p.liveMu.Lock()
	defer p.liveMu.Unlock()

	for _, conns := range p.liveConns {
		streams += len(conns)
	}

	return streams, len(p.liveConns)
}

// requireStaleWorldOpen requires that the registry holds exactly the world's
// streams and that none of them has been closed.
func requireStaleWorldOpen(b *testing.B, w *staleWorld) {
	b.Helper()

	streams, names := liveStreamCount(w.p)

	require.Equal(b, benchStaleStreams, streams, "the registry must hold the 10,000 live streams")
	require.Equal(b, benchStaleNames, names)

	for i, sc := range w.streams {
		require.NoError(b, sc.Err(), "stream %d must be open", i)
	}
}

func BenchmarkCloseStaleConns(b *testing.B) {
	b.Run("rotation", benchCloseStaleRotation)
	b.Run("unrelated", benchCloseStaleUnrelated)
}

// benchCloseStaleRotation: see the file header.
func benchCloseStaleRotation(b *testing.B) {
	const canary = "canary"

	now := time.Now()
	until := now.Add(benchRotationOverlap)

	before := make(map[string]Secret, benchStaleNames+1)
	after := make(map[string]Secret, benchStaleNames+1)
	retiring := make([]RetiringSecret, 0, benchStaleNames)

	for i := range benchStaleNames {
		name := rotationBenchName(i)
		before[name], after[name] = rotationBenchSecret(0x31, i), rotationBenchSecret(0x32, i)
		retiring = append(retiring, RetiringSecret{Name: name, Secret: before[name], Until: until})
	}

	// Re-keyed in the same swap with no overlap: its streams are the ones the
	// swap must close.
	before[canary], after[canary] = rotationBenchSecret(0x33, 0), rotationBenchSecret(0x34, 0)

	p := newReloadTestProxy(before)
	w := &staleWorld{p: p, oldSet: p.secrets.Load(), now: now}

	var drops []retiringDrop

	w.newSet, drops = buildSecretSetAt(after, nil, nil, nil, retiring, now)

	require.Zero(b, len(drops), "no entry may be dropped")
	require.Equal(b, benchStaleNames, len(w.newSet.retiring), "every name keeps its old key as a retiring entry")

	// The streams, on the old keys, registered while the old set is in force.
	w.streams = make([]*streamContext, 0, benchStaleStreams)

	for i := range benchStaleNames {
		name := rotationBenchName(i)

		for range benchStalePerName {
			w.streams = append(w.streams, registerOnKey(b, p, name, before[name].Key))
		}
	}

	var canaries []*streamContext

	for range 8 {
		canaries = append(canaries, registerOnKey(b, p, canary, before[canary].Key))
	}

	// Why every one of the 10,000 is judged by its own key, and kept: the held
	// keys of each name differ between the sets (so no fast path), and the new
	// set accepts the old key as a retiring one.
	for i := range benchStaleNames {
		name := rotationBenchName(i)
		oldKey := before[name].Key

		require.False(b, sameHeldKeys(w.oldSet, w.newSet, name), "the held keys of %s changed: no fast path", name)
		require.True(b, w.newSet.accepts(name, oldKey[:], now), "the new set must accept %s's old key", name)
		require.False(b, w.newSet.accepts(name, oldKey[:], until), "and only until the entry's until")
	}

	canaryKey := before[canary].Key

	require.False(b, w.newSet.accepts(canary, canaryKey[:], now), "the canary's old key is not accepted")

	// One untimed call of the real function, with the fast path's hook on.
	skipped := 0
	p.staleSkipHook = func(string) { skipped++ }
	closed := p.closeStaleConns(w.oldSet, w.newSet, now)
	p.staleSkipHook = nil

	require.Zero(b, skipped, "no name may take the fast path")
	require.Equal(b, map[string]int{canary: len(canaries)}, closed, "exactly the canary's streams are closed, judged by key")

	for i, sc := range canaries {
		require.ErrorIs(b, sc.Err(), context.Canceled, "canary stream %d must be closed", i)
		p.unregisterConn(sc)
	}

	requireStaleWorldOpen(b, w)
	b.ReportAllocs()

	for b.Loop() {
		if closed := p.closeStaleConns(w.oldSet, w.newSet, now); closed != nil {
			b.Fatalf("a rotation must close no stream, closed %d names", len(closed))
		}
	}

	requireStaleWorldOpen(b, w)
}

// benchCloseStaleUnrelated: see the file header.
func benchCloseStaleUnrelated(b *testing.B) {
	now := time.Now()
	until := now.Add(benchRotationOverlap)

	primaries := make(map[string]Secret, benchStaleNames)
	olds := make(map[string]Secret, benchStaleNames)
	tags := make(map[string][AdTagLength]byte, benchStaleNames)
	retiring := make([]RetiringSecret, 0, benchStaleNames)

	for i := range benchStaleNames {
		name := rotationBenchName(i)
		primaries[name], olds[name] = rotationBenchSecret(0x32, i), rotationBenchSecret(0x31, i)
		tags[name] = adTagFilled(7)
		retiring = append(retiring, RetiringSecret{Name: name, Secret: olds[name], Until: until})
	}

	// A rotated set is in force, as it is during an overlap.
	p := newReloadTestProxy(primaries)
	p.rotation = NewRotationClock(nil, nil)

	rotated, drops := buildSecretSetAt(primaries, nil, nil, nil, retiring, now)

	require.Zero(b, len(drops), "no entry may be dropped")
	require.Equal(b, benchStaleNames, len(rotated.retiring))

	p.secrets.Store(rotated)

	w := &staleWorld{p: p, oldSet: rotated, now: now}

	// Half the streams of every name on the old key (a retiring match), half on
	// the new one.
	w.streams = make([]*streamContext, 0, benchStaleStreams)

	for i := range benchStaleNames {
		name := rotationBenchName(i)

		for k := range benchStalePerName {
			key := primaries[name].Key
			if k%2 == 0 {
				key = olds[name].Key
			}

			w.streams = append(w.streams, registerOnKey(b, p, name, key))
		}
	}

	// The swap: every name gets an ad tag, and nothing else changes.
	w.newSet, drops = buildSecretSetAt(primaries, tags, nil, nil, retiring, now)

	require.Zero(b, len(drops))
	require.Equal(b, benchStaleNames, len(w.newSet.retiring))
	require.True(b, w.oldSet.adTags[0] == nil && w.newSet.adTags[0] != nil, "the sets do differ, in the ad tags")

	for i := range benchStaleNames {
		name := rotationBenchName(i)

		require.True(b, sameHeldKeys(w.oldSet, w.newSet, name), "the held keys of %s are the same: the fast path", name)
	}

	requireStaleWorldOpen(b, w)

	// One untimed call of the real function, with the fast path's hook on: it
	// must hear of every name that has streams, once, and close nothing.
	skipped := make(map[string]int, benchStaleNames)
	p.staleSkipHook = func(name string) { skipped[name]++ }
	closed := p.closeStaleConns(w.oldSet, w.newSet, now)
	p.staleSkipHook = nil

	require.Nil(b, closed, "an unrelated swap closes no stream")
	require.Equal(b, benchStaleNames, len(skipped), "the fast path must apply to every name with streams")

	for name, times := range skipped {
		require.Equal(b, 1, times, "%s must be skipped once", name)
	}

	requireStaleWorldOpen(b, w)
	b.ReportAllocs()

	for b.Loop() {
		if closed := p.closeStaleConns(w.oldSet, w.newSet, now); closed != nil {
			b.Fatalf("an unrelated swap must close no stream, closed %d names", len(closed))
		}
	}

	requireStaleWorldOpen(b, w)
}
