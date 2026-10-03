package frame_test

import (
	"bytes"
	"testing"

	"github.com/Arman2122/mtg-proxy/internal/webrelay/frame"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The relay decodes a message it never reuses, so its DATA payloads are
// slices of that message: the bytes the frames carry are the message's own.
func TestTheAliasedDecoderSlicesTheMessage(t *testing.T) {
	t.Parallel()

	big := bytes.Repeat([]byte{0x5a}, 64<<10)

	var message []byte
	for _, f := range []frame.Frame{
		frame.NewOpen(1), frame.NewData(1, []byte{7}), frame.NewData(3, big), frame.NewWindow(1, 4096), frame.NewClose(3),
	} {
		var err error

		message, err = f.AppendTo(message, frame.ClientToRelay)
		require.NoError(t, err)
	}

	copied, err := frame.Limits{}.DecodeBatch(message, frame.ClientToRelay)
	require.NoError(t, err)

	aliased, err := frame.Limits{}.DecodeBatchAliased(message, frame.ClientToRelay)
	require.NoError(t, err)
	require.Equal(t, copied, aliased)

	one := frame.HeaderSize + frame.HeaderSize // after OPEN and DATA's header
	two := one + 1 + frame.HeaderSize          // after DATA(1 byte) and the next header
	assert.Same(t, &message[one], &aliased[1].Payload[0], "a 1-byte DATA payload is a slice of the message")
	assert.Same(t, &message[two], &aliased[2].Payload[0], "a 64 KiB DATA payload is a slice of the message")
}

// The aliasing decoder refuses exactly what the copying one refuses. Every
// decode test goes through decodeBoth, which holds it to that on every
// malformed batch in this package; these are the batches whose length checks
// guard against reading past the message, named on their own.
func TestTheAliasedDecoderRefusesWhatTheCopyingOneRefuses(t *testing.T) {
	t.Parallel()

	for name, input := range map[string][]byte{
		"a torn header":                   wellFormed(frame.TypeData, 1, []byte("x"))[:5],
		"a payload shorter than declared": raw(frame.TypeData, 1, 10, []byte("short")),
		"a payload over the maximum":      raw(frame.TypeData, 1, frame.MaxPayloadSize+1, nil),
	} {
		_, want := frame.Limits{}.DecodeBatch(input, frame.ClientToRelay)
		require.Error(t, want, name)

		frames, err := frame.Limits{}.DecodeBatchAliased(input, frame.ClientToRelay)
		require.EqualError(t, err, want.Error(), name)
		assert.Nil(t, frames, name)
	}
}

func mixedBatch(n int, dir frame.Direction) []frame.Frame {
	frames := make([]frame.Frame, 0, n)

	for i := range n {
		id := uint32(i%7 + 1) //nolint: gosec // a small test id

		switch i % 4 {
		case 0:
			frames = append(frames, frame.NewData(id, bytes.Repeat([]byte{byte(i)}, i%300+1)))
		case 1:
			frames = append(frames, frame.NewWindow(id, uint32(i+1))) //nolint: gosec // a small delta
		case 2:
			frames = append(frames, frame.NewClose(id))
		default:
			if dir == frame.ClientToRelay {
				frames = append(frames, frame.NewOpen(id))
			} else {
				frames = append(frames, frame.NewData(id, []byte{0xee}))
			}
		}
	}

	return frames
}

// A batch as write vectors is, byte for byte, the batch EncodeBatch builds:
// the relay writes the first where it used to write the second.
func TestBatchVectorsAreTheEncodedBatch(t *testing.T) {
	t.Parallel()

	var (
		vecs    [][]byte
		headers []byte
	)

	for _, dir := range []frame.Direction{frame.RelayToClient, frame.ClientToRelay} {
		for _, n := range []int{1, 2, 17, frame.MaxFramesPerBatch} {
			frames := mixedBatch(n, dir)

			want, err := frame.Limits{}.EncodeBatch(nil, frames, dir)
			require.NoError(t, err)

			// The same slices, reused across batches, as the write loop reuses them.
			vecs, headers, err = frame.Limits{}.BatchVectors(vecs[:0], headers, frames, dir)
			require.NoError(t, err)
			assert.Equal(t, want, bytes.Join(vecs, nil), "%d frames", n)

			for _, v := range vecs {
				assert.NotEmpty(t, v, "an empty payload is no vector at all")
			}
		}
	}
}

// What EncodeBatch refuses, BatchVectors refuses, with the same error.
func TestBatchVectorsRefuseWhatEncodeBatchRefuses(t *testing.T) {
	t.Parallel()

	tooMany := make([]frame.Frame, frame.MaxFramesPerBatch+1)
	for i := range tooMany {
		tooMany[i] = frame.NewClose(1)
	}

	overBudget := make([]frame.Frame, 64)
	for i := range overBudget {
		overBudget[i] = frame.NewData(1, bytes.Repeat([]byte{1}, frame.MaxPayloadSize))
	}

	for name, frames := range map[string][]frame.Frame{
		"too many frames":               tooMany,
		"over the byte budget":          overBudget,
		"an OPEN from the relay's side": {frame.NewData(1, []byte{1}), frame.NewOpen(2)},
	} {
		_, want := frame.Limits{}.EncodeBatch(nil, frames, frame.RelayToClient)
		require.Error(t, want, name)

		vecs, _, err := frame.Limits{}.BatchVectors(nil, nil, frames, frame.RelayToClient)
		require.EqualError(t, err, want.Error(), name)
		assert.Empty(t, vecs, name)
	}
}
