package mtglib

import (
	"bytes"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestTheFakeTLSDoorAllocatesAsBefore: on a set with no retiring entry the three
// door functions allocate exactly what they allocated before rotation existed.
// The counts are the ones measured on the unmodified door (commit 9634101, with
// and without -race, AllocsPerRun of 1,000 runs) over this very fixture: a
// hinted hello's positions cost two allocations (the names the cache recalls,
// and the positions), and nothing else allocates. Each call is handed the
// address of a helloNow on its caller's stack, as doFakeTLSHandshake hands it,
// so an escaping helloNow would show here.
//
// Not parallel: AllocsPerRun counts every allocation in the process.
func TestTheFakeTLSDoorAllocatesAsBefore(t *testing.T) { //nolint: paralleltest // see above
	set := buildSecretSet(map[string]Secret{
		"a": eeSecretOf(keyFilledFrom(10), candidatesCover),
		"b": eeSecretOf(keyFilledFrom(40), candidatesCover),
		"c": eeSecretOf(keyFilledFrom(70), candidatesCover),
		"d": eeSecretOf(keyFilledFrom(100), candidatesCover),
		"e": ddSecretOf(keyFilledFrom(130)),
	}, nil, nil, nil)

	require.Empty(t, set.retiring, "a set with no retiring entry")

	p := &Proxy{
		tolerateTimeSkewness: time.Hour,
		hints:                &matchHints{current: make(map[netip.Addr]*hintEntry)},
		rotation:             NewRotationClock(time.Now, nil),
	}

	hintedIP, unhintedIP := "203.0.113.7", "203.0.113.8"
	for _, name := range []string{"a", "e", "c"} {
		p.hints.remember(net.ParseIP(hintedIP), name)
	}

	ctxAt := func(ip string) *streamContext {
		return &streamContext{clientSocket: remoteAddrConn{addr: tcpFrom(ip, 41000)}}
	}

	hinted, unhinted := ctxAt(hintedIP), ctxAt(unhintedIP)

	match := parsedHello(t, fakeTLSClientHello(t, keyFilledFrom(70), candidatesCover, bytes.Repeat([]byte{0x31}, 32)), candidatesCover)
	miss := parsedHello(t, fakeTLSClientHello(t, keyFilledFrom(200), candidatesCover, bytes.Repeat([]byte{0x32}, 32)), candidatesCover)

	positions := p.hintedPositions(hinted, match, set)
	require.Equal(t, []int{2, 0}, positions, "c, then a; e is dd and no candidate")

	const runs = 1000

	for _, tc := range []struct {
		name string
		want float64
		call func()
	}{
		{"hintedPositions, a hinted hello", 2, func() { p.hintedPositions(hinted, match, set) }},
		{"hintedPositions, an unhinted hello", 0, func() { p.hintedPositions(unhinted, match, set) }},
		{"verifyHinted, a match", 0, func() {
			now := helloNow{clock: p.rotation}
			p.verifyHinted(match, set, positions, &now)
		}},
		{"verifyHinted, a miss", 0, func() {
			now := helloNow{clock: p.rotation}
			p.verifyHinted(miss, set, positions, &now)
		}},
		{"verifyHinted, no hints", 0, func() {
			now := helloNow{clock: p.rotation}
			p.verifyHinted(match, set, nil, &now)
		}},
		{"scanCandidates, a match", 0, func() {
			now := helloNow{clock: p.rotation}
			p.scanCandidates(match, set, nil, &now)
		}},
		{"scanCandidates, a miss", 0, func() {
			now := helloNow{clock: p.rotation}
			p.scanCandidates(miss, set, nil, &now)
		}},
		{"scanCandidates, a hinted hello's match", 0, func() {
			now := helloNow{clock: p.rotation}
			p.scanCandidates(match, set, skipPositions([]int{0}), &now)
		}},
		{"scanCandidates, a hinted hello's miss", 0, func() {
			now := helloNow{clock: p.rotation}
			p.scanCandidates(miss, set, skipPositions(positions), &now)
		}},
	} {
		assert.InDelta(t, tc.want, testing.AllocsPerRun(runs, tc.call), 0, tc.name)
	}
}
