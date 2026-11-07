package mtglib

import (
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Fair share end to end, through the real door and against the wall clock: a
// fake Telegram pushes down each stream, the client counts what arrives, and
// the proxy's own ticker divides the secret's speed-down once a second. The
// rules are tested synthetically (fair_share_test.go, fair_share_sim_test.go);
// this is the wiring -- the ticker, the reload that puts the shares on streams
// already open, the brackets countingConn puts around the waits -- so it holds
// wide bands only, each far from what it tells apart: a split within a factor
// of two against a 4:1 one, nine tenths of the total against half of it. The
// waits are long enough for a loaded machine: shares settle within five ticks
// of a reload, and every window is seconds long.
//
// One door, dd: its client receives exactly the bytes Telegram sent.

const (
	// fairDoorTotal is the secret's speed-down, a megabyte a second. Its fair
	// limiters have the 64 KiB floor of a burst, the user's bucket a second of
	// the total.
	fairDoorTotal = 1_000_000

	// fairDoorSlack is what a window can carry past its share of the total:
	// the user's bucket full at its start, and what the sockets hold.
	fairDoorSlack = fairDoorTotal + 256<<10

	// fairDoorPiece is what Telegram writes at a time to a greedy stream: a
	// relay buffer.
	fairDoorPiece = 16 << 10
)

// fairDownload is one of alice's streams through the door, what Telegram has
// written down it, and what its client has received.
type fairDownload struct {
	*ceilingStream

	sent, received atomic.Int64
}

// openFairDownload connects one of alice's clients from where and counts what
// reaches it until the stream is closed. Nothing is sent until push.
func openFairDownload(
	t *testing.T, ec govEntryCase, h *entryHarness, key [SecretKeyLength]byte, where *net.TCPAddr,
) *fairDownload {
	t.Helper()

	d := &fairDownload{ceilingStream: openCeilingStream(t, ec, h, key, where)}
	require.NoError(t, d.client.SetReadDeadline(time.Time{}))

	go func() {
		buf := make([]byte, 64<<10)

		for {
			n, err := d.client.Read(buf)
			d.received.Add(int64(n))

			if err != nil {
				return
			}
		}
	}()

	return d
}

// push has Telegram write down the stream until it is closed, piece bytes at a
// time: as fast as the proxy takes them, or one piece every `every`.
func (d *fairDownload) push(piece int, every time.Duration) {
	go func() {
		buf := make([]byte, piece)

		var tick <-chan time.Time

		if every > 0 {
			ticker := time.NewTicker(every)
			defer ticker.Stop()

			tick = ticker.C
		}

		for {
			if tick != nil {
				<-tick
			}

			n, err := d.upstream.Write(buf)
			d.sent.Add(int64(n))

			if err != nil {
				return
			}
		}
	}()
}

// fairAddress is the downloads of one address, counted together.
type fairAddress []*fairDownload

func (a fairAddress) received() int64 {
	var sum int64

	for _, d := range a {
		sum += d.received.Load()
	}

	return sum
}

// fairWindow is what each address received over the next w.
func fairWindow(w time.Duration, addresses ...fairAddress) []int64 {
	before := make([]int64, len(addresses))
	for i, a := range addresses {
		before[i] = a.received()
	}

	time.Sleep(w)

	moved := make([]int64, len(addresses))
	for i, a := range addresses {
		moved[i] = a.received() - before[i]
	}

	return moved
}

// fairOfTotal is the fraction of the total over w that n bytes are.
func fairOfTotal(n int64, w time.Duration) float64 {
	return float64(n) / (fairDoorTotal * w.Seconds())
}

// assertWithinTheTotal requires what the addresses moved over w, together, to
// be no more than the total over w plus a burst.
func assertWithinTheTotal(t *testing.T, moved []int64, w time.Duration, what string) {
	t.Helper()

	var sum int64
	for _, n := range moved {
		sum += n
	}

	assert.LessOrEqual(t, sum, int64(fairDoorTotal*w.Seconds())+fairDoorSlack,
		"%s: together %d over %s, past the secret's limit and a burst", what, sum, w)
}

// assertWithinTwo requires two addresses' bytes to be within a factor of two of
// each other.
func assertWithinTwo(t *testing.T, a, b int64, what string) {
	t.Helper()

	if !assert.Positive(t, b, what) {
		return
	}

	ratio := float64(a) / float64(b)
	assert.True(t, ratio >= 0.5 && ratio <= 2, "%s: %d against %d is a ratio of %.2f, outside 0.5-2", what, a, b, ratio)
}

// fairDoor is the dd door with alice at lim and the proxy's fair-share ticker
// running, as NewProxy runs it, until the test ends.
func fairDoor(t *testing.T, lim SecretLimits) (govEntryCase, *entryHarness, Secret) {
	t.Helper()

	ec := govEntryCases()[1]
	secret := ec.secret(t)
	h := ec.harness(t, map[string]Secret{"alice": secret}, map[string]SecretLimits{"alice": lim})

	require.False(t, h.proxy.trackClientIPs)

	h.proxy.startFairShare(h.proxy.ctx, fairTickInterval)

	return ec, h, secret
}

// Review Focus 7 at the door: four connections from one address and one from
// another, both downloading as fast as they can, and already running when fair
// share is turned on -- the user's bucket long drained and splitting 4:1 by
// connection, each new fair limiter at the total, above what its address gets,
// so neither is ever held at its own. The phase before shows the 4:1 is there.
// Once the reload has put the shares on the open streams and the ticks have
// seen the waits at the user's bucket, the two are within a factor of two of
// each other, both moving, and together within the total and a burst.
func TestFairShareThroughTheDoorFourConnectionsAgainstOne(t *testing.T) {
	t.Parallel()

	ec, h, secret := fairDoor(t, SecretLimits{SpeedDownBytesPerSecond: fairDoorTotal})

	var four, one fairAddress

	for i := range 4 {
		four = append(four, openFairDownload(t, ec, h, secret.Key, tcpFrom("203.0.113.71", 50001+i)))
	}

	one = append(one, openFairDownload(t, ec, h, secret.Key, tcpFrom("198.51.100.72", 50010)))

	for _, d := range append(append(fairAddress{}, four...), one...) {
		d.push(fairDoorPiece, 0)
	}

	// The user's bucket starts with a second of the total in it; past that,
	// it splits by connection.
	time.Sleep(2 * time.Second)

	const offWindow = 2 * time.Second

	off := fairWindow(offWindow, four, one)
	t.Logf("fair share off: four connections %d, one %d over %s", off[0], off[1], offWindow)
	require.Greater(t, off[0], 2*off[1], "without fair share the user's bucket splits by connection")

	require.NoError(t, h.proxy.ReplaceSecrets(SecretConfig{
		Secrets: map[string]Secret{"alice": secret},
		Limits:  map[string]SecretLimits{"alice": {SpeedDownBytesPerSecond: fairDoorTotal, ClientFair: true}},
	}))

	// A baseline tick, a tick that sees both addresses held, and the shares
	// taking hold.
	time.Sleep(5 * time.Second)

	const onWindow = 4 * time.Second

	on := fairWindow(onWindow, four, one)
	t.Logf("fair share on: four connections %d (%.2f of the total), one %d (%.2f) over %s",
		on[0], fairOfTotal(on[0], onWindow), on[1], fairOfTotal(on[1], onWindow), onWindow)

	assertWithinTwo(t, on[0], on[1], "four connections against one")
	assert.Greater(t, fairOfTotal(on[0], onWindow), 0.1, "the four-connection address moves")
	assert.Greater(t, fairOfTotal(on[1], onWindow), 0.1, "the one-connection address moves")
	assertWithinTheTotal(t, on, onWindow, "fair share on")
}

// An idle address beside a busy one holds it back by nothing: connected but
// moving nothing, it is no participant, so the busy one has the whole total,
// not half of it. When the idle one starts downloading too, the two share.
func TestFairShareThroughTheDoorAnIdleAddressStallsNobody(t *testing.T) {
	t.Parallel()

	ec, h, secret := fairDoor(t, SecretLimits{SpeedDownBytesPerSecond: fairDoorTotal, ClientFair: true})

	busy := openFairDownload(t, ec, h, secret.Key, tcpFrom("203.0.113.81", 50001))
	idle := openFairDownload(t, ec, h, secret.Key, tcpFrom("198.51.100.82", 50002))

	// Alone, the busy address runs at the whole total from its first byte:
	// there is nothing to converge, only the first ticks to pass.
	busy.push(fairDoorPiece, 0)
	time.Sleep(2 * time.Second)

	const window = 4 * time.Second

	alone := fairWindow(window, fairAddress{busy}, fairAddress{idle})
	t.Logf("one idle: busy %d (%.2f of the total), idle %d over %s",
		alone[0], fairOfTotal(alone[0], window), alone[1], window)

	assert.Greater(t, fairOfTotal(alone[0], window), 0.7, "the busy address has the total, not a share of it")
	assert.Zero(t, alone[1])
	assertWithinTheTotal(t, alone, window, "one idle")

	idle.push(fairDoorPiece, 0)
	time.Sleep(5 * time.Second)

	both := fairWindow(window, fairAddress{busy}, fairAddress{idle})
	t.Logf("both busy: %d (%.2f of the total) and %d (%.2f) over %s",
		both[0], fairOfTotal(both[0], window), both[1], fairOfTotal(both[1], window), window)

	assertWithinTwo(t, both[0], both[1], "the two busy addresses")
	assert.Greater(t, fairOfTotal(both[1], window), 0.25, "the address that woke up moves")
	assertWithinTheTotal(t, both, window, "both busy")
}

// Max-min, not the total over the number of addresses: a quiet address asking
// for a tenth of the total keeps all of it, and a greedy one beside it has the
// rest, nine tenths -- not the half an even split would hold it to.
//
// What the quiet address asks for is what Telegram actually wrote down its
// stream in the window, not the schedule the writer aims at: a writer the
// machine descheduled asks for less, and the proxy is not to blame for that.
func TestFairShareThroughTheDoorAQuietAddressKeepsItsDemand(t *testing.T) {
	t.Parallel()

	const (
		quietPiece = 10_000
		quietEvery = 100 * time.Millisecond // a tenth of the total
		window     = 5 * time.Second
	)

	ec, h, secret := fairDoor(t, SecretLimits{SpeedDownBytesPerSecond: fairDoorTotal, ClientFair: true})

	greedy := openFairDownload(t, ec, h, secret.Key, tcpFrom("203.0.113.91", 50001))
	quiet := openFairDownload(t, ec, h, secret.Key, tcpFrom("198.51.100.92", 50002))

	greedy.push(fairDoorPiece, 0)
	quiet.push(quietPiece, quietEvery)

	// The first tick is a baseline, and a throttle the start-up set holds
	// three more.
	time.Sleep(5 * time.Second)

	sentBefore := quiet.sent.Load()
	got := fairWindow(window, fairAddress{greedy}, fairAddress{quiet})
	asked := quiet.sent.Load() - sentBefore

	t.Logf("greedy %d (%.2f of the total), quiet %d of the %d Telegram wrote for it, over %s",
		got[0], fairOfTotal(got[0], window), got[1], asked, window)

	// A piece written as the window closes may still be on its way.
	assert.GreaterOrEqual(t, got[1], (asked-quietPiece)*3/4, "the quiet address keeps what it asks for")
	assert.Greater(t, fairOfTotal(got[0], window), 0.7, "the greedy one has the rest, not half")
	assertWithinTheTotal(t, got, window, "greedy and quiet")
}
