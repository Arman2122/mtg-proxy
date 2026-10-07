package webrelay

import (
	"flag"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

// Every test in this package runs with released read buffers poisoned: a
// buffer used after its release corrupts what the client receives, and the
// byte-exact tests fail instead of passing by luck. Benchmarks run without it:
// the poison is a 64 KiB fill and scan on every release -- 12% of the WEB
// download benchmark's CPU -- and would be measured as the relay's own cost.
func TestMain(m *testing.M) {
	flag.Parse()

	poisonReleased = flag.Lookup("test.bench").Value.String() == ""

	os.Exit(m.Run())
}

// A stream reads small until a read fills its buffer, then large; a large read
// that comes back under the small size returns it to small. An idle stream,
// blocked in a read, so holds the small buffer.
func TestTheReadSizeFollowsTheStream(t *testing.T) {
	t.Parallel()

	assert.True(t, nextReadLarge(false, smallRead), "a small read that filled its buffer goes large")
	assert.False(t, nextReadLarge(false, smallRead-1), "a small read with room left stays small")
	assert.False(t, nextReadLarge(true, smallRead-1), "a large read under the small size goes small")
	assert.True(t, nextReadLarge(true, largeRead), "a full large read stays large")
}

// What a taken buffer holds is the backend's, and a backend may send any byte,
// the poison's among them. A buffer that holds nothing else is still released
// for the first time: told by its content, one 0xA5 read into a buffer back
// from the pool -- poisoned whole on its last release -- passed for a buffer
// released twice, about once in every 256 such reads.
func TestABufferHoldingOnlyThePoisonIsReleasedOnce(t *testing.T) {
	t.Parallel()

	pools := newReadBufferPools()

	b := pools.get(false)
	for i := range b {
		b[i] = poison
	}

	assert.NotPanics(t, func() { pools.release(b[:1]) }, "a first release, whatever the buffer holds")
	assert.Panics(t, func() { pools.release(b) }, "a second release is still a bug the tests must see")
}
