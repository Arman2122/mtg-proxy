package webrelay

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Every test in this package runs with released read buffers poisoned: a
// buffer used after its release corrupts what the client receives, and the
// byte-exact tests fail instead of passing by luck.
func init() { poisonReleased = true } //nolint: gochecknoinits // the package's tests, all of them

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

// Buffers are handed out at the two sizes, and a released one is poisoned in
// place and returned to the pool its capacity names; a buffer of any other
// capacity is not the pools' and is left alone.
func TestReleasedBuffersGoBackByCapacity(t *testing.T) {
	t.Parallel()

	small, large := getReadBuffer(false), getReadBuffer(true)
	require.Len(t, small, smallRead)
	require.Len(t, large, largeRead)

	releaseReadBuffer(small[:10])
	releaseReadBuffer(large[:100])

	assert.Equal(t, bytes.Repeat([]byte{poison}, smallRead), small, "released whole, by capacity, and poisoned")
	assert.Equal(t, bytes.Repeat([]byte{poison}, largeRead), large)

	stranger := bytes.Repeat([]byte{1}, 1000)
	releaseReadBuffer(stranger)
	assert.Equal(t, bytes.Repeat([]byte{1}, 1000), stranger, "not a pool's buffer: untouched")

	again := getReadBuffer(false)
	releaseReadBuffer(again)
	assert.Panics(t, func() { releaseReadBuffer(again) }, "a second release is a bug the tests must see")
}
