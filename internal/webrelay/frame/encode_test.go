package frame_test

import (
	"bytes"
	"testing"

	"github.com/Arman2122/mtg-proxy/internal/webrelay/frame"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The encoder runs the same rules as the decoder, so a relay bug cannot put a
// frame on the wire that this package would refuse to read back.
func TestTheEncoderRefusesWhatTheDecoderWouldReject(t *testing.T) {
	for _, tc := range []struct {
		name  string
		frame frame.Frame
		dir   frame.Direction
		want  error
	}{
		{
			"a stream id past the 24-bit field",
			frame.NewOpen(frame.MaxStreamID + 1), frame.ClientToRelay, frame.ErrStreamIDRange,
		},
		{
			"a DATA frame with no payload",
			frame.NewData(1, nil), frame.RelayToClient, frame.ErrEmptyData,
		},
		{
			"a WINDOW granting zero credit",
			frame.NewWindow(1, 0), frame.RelayToClient, frame.ErrZeroWindow,
		},
		{
			"a payload one byte past the maximum",
			frame.NewData(1, bytes.Repeat([]byte{1}, frame.MaxPayloadSize+1)), frame.RelayToClient,
			frame.ErrPayloadTooLarge,
		},
		{
			"the relay emitting an OPEN",
			frame.NewOpen(17), frame.RelayToClient, frame.ErrWrongDirection,
		},
		{
			"the relay emitting a HELLO",
			frame.NewHello(), frame.RelayToClient, frame.ErrWrongDirection,
		},
		{
			"a CLOSE on stream zero",
			frame.NewClose(0), frame.RelayToClient, frame.ErrStreamFrameOnZero,
		},
		{
			"a PING on a nonzero stream",
			frame.Frame{Type: frame.TypePing, StreamID: 3},
			frame.RelayToClient,
			frame.ErrSessionFrameOnStream,
		},
		{
			"an unassigned type",
			frame.Frame{Type: frame.Type(0x42), StreamID: 1},
			frame.RelayToClient, frame.ErrUnknownType,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.ErrorIs(t, tc.frame.Validate(tc.dir), tc.want)

			// A rejected frame must not leave a stub behind in the caller's
			// buffer for the next AppendTo to build on.
			dst := []byte("already here")
			out, err := tc.frame.AppendTo(dst, tc.dir)
			require.ErrorIs(t, err, tc.want)
			assert.Equal(t, dst, out)
		})
	}
}

func TestTheLargestStreamIDEncodes(t *testing.T) {
	encoded, err := frame.NewOpen(frame.MaxStreamID).AppendTo(nil, frame.ClientToRelay)
	require.NoError(t, err)
	assert.Equal(t, []byte{0x01, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00}, encoded)
}

func TestEncodeForClientEncodesARelayFrame(t *testing.T) {
	encoded, err := frame.NewWelcome().EncodeForClient()
	require.NoError(t, err)
	assert.Equal(t, welcomeBytes, encoded)
}

func TestEncodeBatchRefusesMoreFramesThanThePeerWillRead(t *testing.T) {
	tooMany := make([]frame.Frame, frame.MaxFramesPerBatch+1)
	for i := range tooMany {
		tooMany[i] = frame.NewClose(1)
	}

	encoded, err := frame.Limits{}.EncodeBatch(nil, tooMany[:frame.MaxFramesPerBatch], frame.RelayToClient)
	require.NoError(t, err)
	assert.Len(t, encoded, frame.MaxFramesPerBatch*frame.HeaderSize)

	_, err = frame.Limits{}.EncodeBatch(nil, tooMany, frame.RelayToClient)
	require.ErrorIs(t, err, frame.ErrTooManyFrames)
}

func TestEncodeBatchRefusesABatchThePeerWouldDropWhole(t *testing.T) {
	// Every frame here is legal on its own and the count is exactly at the
	// frame cap, so only the byte budget can refuse it: 4096 relay DATA chunks
	// are 256 MiB, and the client discards an oversized message whole rather
	// than truncating it, which kills the session with nothing to see here.
	chunk := bytes.Repeat([]byte{0x5a}, frame.MaxRelayDataChunk)
	atFrameCap := make([]frame.Frame, frame.MaxFramesPerBatch)

	for i := range atFrameCap {
		atFrameCap[i] = frame.NewData(1, chunk)
	}

	dst := []byte("already here")
	out, err := frame.Limits{}.EncodeBatch(dst, atFrameCap, frame.RelayToClient)
	require.ErrorIs(t, err, frame.ErrBatchTooLarge)
	assert.Equal(t, dst, out)

	// 64 frames of the maximum payload are 64 MiB with a count nowhere near the
	// cap: the frame bound does not imply the byte bound in either direction.
	biggest := bytes.Repeat([]byte{0x5a}, frame.MaxPayloadSize)
	fewButHuge := make([]frame.Frame, 64)

	for i := range fewButHuge {
		fewButHuge[i] = frame.NewData(1, biggest)
	}

	_, err = frame.Limits{}.EncodeBatch(nil, fewButHuge, frame.RelayToClient)
	require.ErrorIs(t, err, frame.ErrBatchTooLarge)
}

func TestEncodeBatchStopsExactlyAtItsByteBudget(t *testing.T) {
	three := []frame.Frame{frame.NewClose(1), frame.NewClose(2), frame.NewClose(3)}
	four := []frame.Frame{frame.NewClose(1), frame.NewClose(2), frame.NewClose(3), frame.NewClose(4)}
	exact := frame.Limits{BatchBytes: 3 * frame.HeaderSize}

	out, err := exact.EncodeBatch(nil, three, frame.RelayToClient)
	require.NoError(t, err)
	assert.Len(t, out, 3*frame.HeaderSize)

	_, err = exact.EncodeBatch(nil, four, frame.RelayToClient)
	require.ErrorIs(t, err, frame.ErrBatchTooLarge)
}

func TestEncodeBatchAppendsToWhateverIsAlreadyInTheBuffer(t *testing.T) {
	// A carrier assembles one message out of several EncodeBatch calls, so the
	// bytes already in dst must survive verbatim and the new ones must follow
	// exactly once.
	prefix := []byte("already here")

	out, err := frame.Limits{}.EncodeBatch(prefix, []frame.Frame{frame.NewWelcome()}, frame.RelayToClient)
	require.NoError(t, err)
	assert.Equal(t, append(append([]byte(nil), prefix...), welcomeBytes...), out)
}

func TestAFailedEncodeBatchLeavesTheDestinationAlone(t *testing.T) {
	// Half a batch on the wire is worse than none: the peer would read the good
	// frames and then fail on a torn one.
	dst := []byte("already here")

	out, err := frame.Limits{}.EncodeBatch(dst, []frame.Frame{
		frame.NewClose(1),
		frame.NewWindow(2, 0),
	}, frame.RelayToClient)

	require.ErrorIs(t, err, frame.ErrZeroWindow)
	assert.Equal(t, dst, out)
}

func TestWindowDeltaOnlyAnswersForWindowFrames(t *testing.T) {
	delta, ok := frame.NewWindow(1, 7).WindowDelta()
	require.True(t, ok)
	assert.EqualValues(t, 7, delta)

	_, ok = frame.NewData(1, []byte{0, 0, 0, 7}).WindowDelta()
	assert.False(t, ok)
}
