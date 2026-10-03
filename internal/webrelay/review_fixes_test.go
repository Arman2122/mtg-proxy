package webrelay

import (
	"bytes"
	"testing"

	"github.com/Arman2122/mtg-proxy/internal/webrelay/frame"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A queued DATA frame is charged for the memory it holds: its whole read
// buffer, not the bytes it carries. The proxy hands the relay 16 KiB at a
// time, so charging the bytes let the queue hold four times its budget in
// 64 KiB buffers -- the budget is the process's memory guard against slow
// clients, and a guard four times loose is no guard.
func TestQueuedDataIsChargedForTheBufferItHolds(t *testing.T) {
	t.Parallel()

	session, global := newBudget(1<<30, 1<<20), newBudget(1<<30, 1<<20)
	o := newOutbox(session, global, frame.Limits{})

	buffer := make([]byte, largeRead) // a pooled read buffer, a quarter full
	require.NoError(t, o.PushData(frame.NewData(1, buffer[:16<<10])))

	held, items := session.pending()
	assert.Equal(t, int64(frame.HeaderSize+largeRead+QueueItemCharge), held, "charged for the buffer, not the bytes")
	assert.Equal(t, int64(1), items)

	globalHeld, _ := global.pending()
	assert.Equal(t, held, globalHeld)

	require.Len(t, o.Take(), 1)

	held, items = session.pending()
	assert.Zero(t, held, "released exactly what was charged")
	assert.Zero(t, items)

	globalHeld, _ = global.pending()
	assert.Zero(t, globalHeld)
}

// A DATA payload sliced from a client message keeps the whole message alive
// until it is written. A small one is copied out instead, so a byte of credit
// cannot pin a message of megabytes; a large one stays a slice, the zero-copy
// case the bulk path is built on.
func TestASmallPayloadDoesNotPinItsMessage(t *testing.T) {
	t.Parallel()

	small := []byte{42}
	large := bytes.Repeat([]byte{7}, 64<<10)

	var message []byte
	for _, f := range []frame.Frame{frame.NewData(1, small), frame.NewData(3, large)} {
		var err error

		message, err = f.AppendTo(message, frame.ClientToRelay)
		require.NoError(t, err)
	}

	frames, err := frame.Limits{}.DecodeBatchAliased(message, frame.ClientToRelay)
	require.NoError(t, err)

	unpinSmallPayloads(frames, message)

	for i := range message {
		message[i] = 0xFF
	}

	assert.Equal(t, small, frames[0].Payload, "the small payload is a copy of its own")
	assert.Equal(t, bytes.Repeat([]byte{0xFF}, 64<<10), frames[1].Payload, "the large one is still the message's")
}

// The pools' poison and double-release checks, on pools of the test's own: a
// buffer touched after its release to the package's pools could be one a
// stream in a parallel test has already taken.
func TestReleasedBuffersArePoisonedAndReleasedOnce(t *testing.T) {
	t.Parallel()

	pools := newReadBufferPools()

	small, large := pools.get(false), pools.get(true)
	require.Len(t, small, smallRead)
	require.Len(t, large, largeRead)

	pools.release(small[:10])
	pools.release(large[:100])

	assert.Equal(t, bytes.Repeat([]byte{poison}, smallRead), small, "released whole, by capacity, and poisoned")
	assert.Equal(t, bytes.Repeat([]byte{poison}, largeRead), large)

	stranger := bytes.Repeat([]byte{1}, 1000)
	pools.release(stranger)
	assert.Equal(t, bytes.Repeat([]byte{1}, 1000), stranger, "not a pool's buffer: untouched")

	again := pools.get(false)
	pools.release(again)
	assert.Panics(t, func() { pools.release(again) }, "a second release is a bug the tests must see")
}
