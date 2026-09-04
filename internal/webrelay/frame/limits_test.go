package frame_test

import (
	"bytes"
	"testing"

	"github.com/Arman2122/mtg-proxy/internal/webrelay/frame"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The one lowered bound the deployment documentation actually calls for: Linux
// Desktop builds from before the 2 MiB message cap reject anything past their
// own 1 MiB native-helper limit, so those deployments must cap frames at
// 512 KiB. Nothing on the wire reports that rejection, so an unenforced bound
// is invisible until the session dies.
const oldDesktopPayload = 512 << 10

func TestALoweredPayloadCapIsEnforcedOnDecode(t *testing.T) {
	lim := frame.Limits{MaxPayload: oldDesktopPayload}

	decoded, err := decodeBothWith(t, lim,
		wellFormed(frame.TypeData, 1, bytes.Repeat([]byte{0x5a}, oldDesktopPayload)),
		frame.ClientToRelay)
	require.NoError(t, err)
	require.Len(t, decoded, 1)
	assert.Len(t, decoded[0].Payload, oldDesktopPayload)

	// Declared but not sent: a lowered bound has to refuse from the header
	// alone, for the same reason the ceiling does.
	_, err = decodeBothWith(t, lim,
		raw(frame.TypeData, 1, oldDesktopPayload+1, nil), frame.ClientToRelay)
	require.ErrorIs(t, err, frame.ErrPayloadTooLarge)

	// The same frame is legal at the default, so the rejection is the
	// configured bound and not some other rule.
	_, err = decodeBoth(t,
		wellFormed(frame.TypeData, 1, bytes.Repeat([]byte{0x5a}, oldDesktopPayload+1)),
		frame.ClientToRelay)
	require.NoError(t, err)
}

func TestALoweredPayloadCapIsEnforcedOnEncode(t *testing.T) {
	// A bound the decoder enforces and the encoder ignores is the same defect
	// pointing the other way: the relay would emit what its own peer drops.
	over := frame.NewData(1, bytes.Repeat([]byte{0x5a}, oldDesktopPayload+1))

	dst := []byte("already here")
	out, err := frame.Limits{MaxPayload: oldDesktopPayload}.
		EncodeBatch(dst, []frame.Frame{over}, frame.RelayToClient)
	require.ErrorIs(t, err, frame.ErrPayloadTooLarge)
	assert.Equal(t, dst, out)

	_, err = frame.Limits{}.EncodeBatch(nil, []frame.Frame{over}, frame.RelayToClient)
	require.NoError(t, err)
}

func TestABoundAboveItsCeilingIsClampedRatherThanHonoured(t *testing.T) {
	// Every bound here is compiled into the client, so a configuration may only
	// lower one. Raising one must not take effect anywhere.
	raised := frame.Limits{MaxPayload: frame.MaxPayloadSize + 1, BatchBytes: frame.MaxBatchBytes + 1}

	require.ErrorIs(t, raised.Validate(), frame.ErrLimitOutOfRange)

	_, err := decodeBothWith(t, raised,
		raw(frame.TypeData, 1, frame.MaxPayloadSize+1, nil), frame.ClientToRelay)
	require.ErrorIs(t, err, frame.ErrPayloadTooLarge)

	// Exactly one byte past the batch ceiling, which is the only size that can
	// tell a clamped budget from an honoured one: a raised budget covers it.
	over := dataPairTotalling(frame.MaxBatchBytes + 1)

	_, err = raised.EncodeBatch(nil, over, frame.RelayToClient)
	require.ErrorIs(t, err, frame.ErrBatchTooLarge)

	_, err = decodeBothWith(t, raised, wireBytes(over), frame.RelayToClient)
	require.ErrorIs(t, err, frame.ErrBatchTooLarge)
}

// dataPairTotalling is two DATA frames encoding to exactly total bytes. It
// takes two because MaxPayloadSize is half of MaxBatchBytes, so no single frame
// can reach the batch ceiling.
func dataPairTotalling(total int) []frame.Frame {
	second := total - 2*frame.HeaderSize - frame.MaxPayloadSize

	return []frame.Frame{
		frame.NewData(1, bytes.Repeat([]byte{0x5a}, frame.MaxPayloadSize)),
		frame.NewData(2, bytes.Repeat([]byte{0x5a}, second)),
	}
}

// wireBytes lays frames out by hand, for batches the encoder is expected to
// refuse and which therefore cannot be built with it.
func wireBytes(frames []frame.Frame) []byte {
	var out []byte
	for _, f := range frames {
		out = append(out, wellFormed(f.Type, f.StreamID, f.Payload)...)
	}

	return out
}

func TestTheBatchCeilingIsAcceptedAndOneMoreByteIsNot(t *testing.T) {
	// The bound the relay breaks by accident: every frame legal, the count far
	// under the frame cap, and the total one byte too big for the client.
	atCeiling := dataPairTotalling(frame.MaxBatchBytes)

	encoded, err := frame.Limits{}.EncodeBatch(nil, atCeiling, frame.RelayToClient)
	require.NoError(t, err)
	require.Len(t, encoded, frame.MaxBatchBytes)

	decoded, err := decodeBoth(t, encoded, frame.RelayToClient)
	require.NoError(t, err)
	assert.Len(t, decoded, 2)

	over := dataPairTotalling(frame.MaxBatchBytes + 1)

	_, err = frame.Limits{}.EncodeBatch(nil, over, frame.RelayToClient)
	require.ErrorIs(t, err, frame.ErrBatchTooLarge)

	// The decoder refuses the same bytes, so neither end of this codec is the
	// one that lets an oversized message through.
	_, err = decodeBoth(t, wireBytes(over), frame.RelayToClient)
	require.ErrorIs(t, err, frame.ErrBatchTooLarge)
}

func TestLimitsValidate(t *testing.T) {
	for _, lim := range []frame.Limits{
		{},
		{MaxPayload: oldDesktopPayload, BatchBytes: 1 << 20},
		{MaxPayload: frame.MaxPayloadSize, BatchBytes: frame.MaxBatchBytes},
	} {
		require.NoError(t, lim.Validate())
	}

	for _, tc := range []struct {
		name string
		lim  frame.Limits
	}{
		{"a frame payload above the ceiling", frame.Limits{MaxPayload: frame.MaxPayloadSize + 1}},
		{"a batch budget above the ceiling", frame.Limits{BatchBytes: frame.MaxBatchBytes + 1}},
		{"a negative frame payload", frame.Limits{MaxPayload: -1}},
		{"a negative batch budget", frame.Limits{BatchBytes: -1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.ErrorIs(t, tc.lim.Validate(), frame.ErrLimitOutOfRange)
		})
	}
}
