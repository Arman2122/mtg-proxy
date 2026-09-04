package frame_test

import (
	"bytes"
	"testing"

	"github.com/Arman2122/mtg-proxy/internal/webrelay/frame"
	"github.com/stretchr/testify/require"
)

// FuzzDecodeBatch drives the only code in this package that reads
// attacker-controlled bytes off a public path.
//
// It checks three properties rather than one. No input may panic, because a
// panic in a carrier goroutine ends the whole proxy. The two decoders must
// agree, because they are two hand-written parsers of one grammar and a
// disagreement is a bug in whichever one is more permissive. And an accepted
// batch must re-encode to exactly the bytes it came from, which rules out a
// decoder that silently ignores a field, tolerates a non-canonical encoding, or
// loses a frame.
func FuzzDecodeBatch(f *testing.F) {
	for _, seed := range [][]byte{
		nil,
		helloBytes,
		welcomeBytes,
		openBytes,
		wellFormed(frame.TypeData, 1, []byte("payload")),
		wellFormed(frame.TypeWindow, 1, []byte{0, 0x40, 0, 0}),
		wellFormed(frame.TypeClose, 1, nil),
		wellFormed(frame.TypePong, 0, []byte("token")),
		append(append([]byte(nil), openBytes...), wellFormed(frame.TypeData, 17, []byte("hi"))...),
		// Malformed shapes worth starting the mutator from.
		raw(frame.TypeData, 1, 0xffffffff, nil),
		raw(frame.TypeData, 1, 8, []byte("short")),
		wellFormed(frame.TypeWindow, 1, []byte{0, 0, 0, 0}),
		wellFormed(frame.TypeData, 1, nil),
		openBytes[:7],
		// Multi-frame batches that fail on the second frame's payload: the only
		// shape in which a decoder has already accumulated something to leak,
		// and CI runs the seed corpus rather than a fuzzing campaign.
		append(append([]byte(nil), openBytes...), wellFormed(frame.TypeWindow, 17, []byte{0, 0, 0, 0})...),
		append(append([]byte(nil), openBytes...), wellFormed(frame.TypeHello, 0, []byte{0x02})...),
	} {
		f.Add(seed, true)
		f.Add(seed, false)
	}

	f.Fuzz(func(t *testing.T, b []byte, fromClient bool) {
		dir := frame.RelayToClient
		if fromClient {
			dir = frame.ClientToRelay
		}

		frames, err := frame.Limits{}.DecodeBatch(b, dir)
		streamed, streamErr := frame.Limits{}.DecodeBatchFrom(bytes.NewReader(b), dir)

		if err != nil {
			require.Error(t, streamErr, "DecodeBatch rejected this input and DecodeBatchFrom accepted it")
			require.Nil(t, frames)
			require.Nil(t, streamed)

			return
		}

		require.NoError(t, streamErr, "DecodeBatch accepted this input and DecodeBatchFrom rejected it")
		require.Equal(t, frames, streamed)
		require.LessOrEqual(t, len(frames), frame.MaxFramesPerBatch)

		reencoded, err := frame.Limits{}.EncodeBatch(nil, frames, dir)
		require.NoError(t, err, "a batch that decoded must encode again")
		// bytes.Equal, not require.Equal: an empty input re-encodes to a nil
		// slice, and those are the same batch even though they are not the same
		// value.
		require.True(t, bytes.Equal(b, reencoded), "re-encoding an accepted batch changed its bytes")
	})
}
