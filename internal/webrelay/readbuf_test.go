package webrelay

import (
	"testing"

	"github.com/stretchr/testify/assert"
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
