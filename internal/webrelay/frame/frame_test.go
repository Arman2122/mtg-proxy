package frame_test

import (
	"bytes"
	"testing"

	"github.com/Arman2122/mtg-proxy/internal/webrelay/frame"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// decodeBoth runs the []byte decoder and the io.Reader decoder over the same
// input and asserts they agree, then returns the result. Every decode in this
// file goes through it, so the two implementations of one grammar are checked
// against each other by every test rather than only by the fuzz target.
func decodeBoth(t *testing.T, b []byte, dir frame.Direction) ([]frame.Frame, error) {
	t.Helper()

	return decodeBothWith(t, frame.Limits{}, b, dir)
}

// decodeBothWith is decodeBoth under a deployment's own bounds, so a lowered
// limit is checked on both decoders rather than only on whichever one a test
// happened to call.
func decodeBothWith(t *testing.T, lim frame.Limits, b []byte, dir frame.Direction) ([]frame.Frame, error) {
	t.Helper()

	fromBytes, errBytes := lim.DecodeBatch(b, dir)
	fromReader, errReader := lim.DecodeBatchFrom(bytes.NewReader(b), dir)

	if errBytes != nil {
		require.Error(t, errReader, "DecodeBatch rejected this input, DecodeBatchFrom accepted it")
		require.Nil(t, fromBytes, "a failed decode must hand back no frames at all")
		require.Nil(t, fromReader, "a failed decode must hand back no frames at all")

		return nil, errBytes
	}

	require.NoError(t, errReader, "DecodeBatch accepted this input, DecodeBatchFrom rejected it")
	require.Equal(t, fromBytes, fromReader, "the two decoders disagree on the frames")

	return fromBytes, nil
}

// The two byte sequences published as interoperability vectors. They are the
// only frames whose exact bytes are fixed by something other than this
// package's own encoder, so they are asserted literally.
var (
	helloBytes   = []byte{0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01}
	welcomeBytes = []byte{0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	openBytes    = []byte{0x01, 0x00, 0x00, 0x11, 0x00, 0x00, 0x00, 0x00}
)

func TestPublishedWireVectors(t *testing.T) {
	for _, tc := range []struct {
		name  string
		frame frame.Frame
		dir   frame.Direction
		want  []byte
	}{
		{"HELLO", frame.NewHello(), frame.ClientToRelay, helloBytes},
		{"WELCOME", frame.NewWelcome(), frame.RelayToClient, welcomeBytes},
		{"OPEN on stream 17", frame.NewOpen(17), frame.ClientToRelay, openBytes},
	} {
		t.Run(tc.name, func(t *testing.T) {
			encoded, err := tc.frame.AppendTo(nil, tc.dir)
			require.NoError(t, err)
			assert.Equal(t, tc.want, encoded)

			decoded, err := decodeBoth(t, tc.want, tc.dir)
			require.NoError(t, err)
			require.Len(t, decoded, 1)
			assert.Equal(t, tc.frame, decoded[0])
		})
	}
}

func TestAWindowFrameIsAlwaysTwelveBytes(t *testing.T) {
	for _, delta := range []uint32{1, 0xff, 0x10000, 4 << 20, 0xffffffff} {
		encoded, err := frame.NewWindow(1, delta).AppendTo(nil, frame.RelayToClient)
		require.NoError(t, err)
		assert.Len(t, encoded, 12)

		decoded, err := decodeBoth(t, encoded, frame.RelayToClient)
		require.NoError(t, err)
		require.Len(t, decoded, 1)

		got, ok := decoded[0].WindowDelta()
		require.True(t, ok)
		assert.Equal(t, delta, got)
	}
}

// allNineTypes is one legal frame of every v1 type, with the direction it is
// allowed to travel in.
func allNineTypes() []struct {
	name  string
	frame frame.Frame
	dir   frame.Direction
} {
	return []struct {
		name  string
		frame frame.Frame
		dir   frame.Direction
	}{
		{"OPEN", frame.NewOpen(17), frame.ClientToRelay},
		{"DATA client", frame.NewData(1, []byte("payload")), frame.ClientToRelay},
		{"DATA relay", frame.NewData(frame.MaxStreamID, bytes.Repeat([]byte{0xab}, 4096)), frame.RelayToClient},
		{"CLOSE", frame.NewClose(9), frame.RelayToClient},
		{"WINDOW", frame.NewWindow(3, 4<<20), frame.ClientToRelay},
		{"PING", frame.NewPing([]byte("token")), frame.RelayToClient},
		{"PONG", frame.NewPong([]byte("token")), frame.ClientToRelay},
		{"HELLO", frame.NewHello(), frame.ClientToRelay},
		{"WELCOME", frame.NewWelcome(), frame.RelayToClient},
		{"BYE", frame.NewBye([]byte("draining")), frame.RelayToClient},
	}
}

func TestEveryFrameTypeSurvivesARoundTrip(t *testing.T) {
	for _, tc := range allNineTypes() {
		t.Run(tc.name, func(t *testing.T) {
			encoded, err := frame.Limits{}.EncodeBatch(nil, []frame.Frame{tc.frame}, tc.dir)
			require.NoError(t, err)
			assert.Len(t, encoded, tc.frame.EncodedLen())

			decoded, err := decodeBoth(t, encoded, tc.dir)
			require.NoError(t, err)
			require.Len(t, decoded, 1)
			assert.Equal(t, tc.frame, decoded[0])
		})
	}
}

func TestABatchOfEveryTypeRoundTripsInOnePiece(t *testing.T) {
	// Batches are per-direction on the wire, so this splits by direction and
	// checks that concatenation with no separator is all the framing there is.
	for _, dir := range []frame.Direction{frame.ClientToRelay, frame.RelayToClient} {
		var want []frame.Frame

		for _, tc := range allNineTypes() {
			if tc.dir == dir {
				want = append(want, tc.frame)
			}
		}

		encoded, err := frame.Limits{}.EncodeBatch(nil, want, dir)
		require.NoError(t, err)

		decoded, err := decodeBoth(t, encoded, dir)
		require.NoError(t, err)
		assert.Equal(t, want, decoded)
	}
}

func TestAnEmptyBatchIsNotAnError(t *testing.T) {
	// The spec never says whether a zero-frame body is malformed, so the codec
	// reports it as what it is -- no frames -- and leaves the judgement to the
	// session layer, which knows what it was expecting.
	decoded, err := decodeBoth(t, nil, frame.ClientToRelay)
	require.NoError(t, err)
	assert.Empty(t, decoded)
}

func TestAnUnknownTypePrintsItsByte(t *testing.T) {
	assert.Equal(t, "HELLO", frame.TypeHello.String())
	assert.Equal(t, "unknown(0x7f)", frame.Type(0x7f).String())
}
