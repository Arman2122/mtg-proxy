package frame_test

import (
	"bytes"
	"io"
	"testing"

	"github.com/Arman2122/mtg-proxy/internal/webrelay/frame"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Atomicity and bounds probes the package suite left unpinned: a rejected
// batch must hand back NO frames from EVERY rejection site, not only the
// header-level one, and a lowered deployment limit must actually bite.
//
// From an adversarial audit, which found four decode sites whose atomicity
// nothing asserted -- breaking any of them left the whole suite green.

// ---------- whole-batch byte bound on the encode path ----------

// Three individually legal 1 MiB DATA frames: three frames, far under the 4096
// frame cap, 3 MiB + 24 on the wire, which the client drops whole.
func TestBatchByteBoundRefusesIndividuallyLegalFrames(t *testing.T) {
	mib := bytes.Repeat([]byte{0x5a}, frame.MaxPayloadSize)
	batch := []frame.Frame{
		frame.NewData(1, mib), frame.NewData(2, mib), frame.NewData(3, mib),
	}

	dst := []byte("carrier prefix")
	out, err := frame.Limits{}.EncodeBatch(dst, batch, frame.RelayToClient)
	require.ErrorIs(t, err, frame.ErrBatchTooLarge)
	assert.Equal(t, dst, out, "a refused batch must leave dst alone")
}

// ---------- atomicity, my own shapes ----------

func TestNothingLeaksWhenALaterFrameFails(t *testing.T) {
	for _, tc := range []struct {
		name  string
		batch []byte
		dir   frame.Direction
		want  error
	}{
		{
			"DATA then a zero WINDOW",
			append(wellFormed(frame.TypeData, 5, []byte("x")),
				wellFormed(frame.TypeWindow, 5, []byte{0, 0, 0, 0})...),
			frame.ClientToRelay, frame.ErrZeroWindow,
		},
		{
			"CLOSE then a HELLO announcing v0",
			append(wellFormed(frame.TypeClose, 1, nil),
				wellFormed(frame.TypeHello, 0, []byte{0x00})...),
			frame.ClientToRelay, frame.ErrUnsupportedVersion,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			frames, err := frame.Limits{}.DecodeBatch(tc.batch, tc.dir)
			require.ErrorIs(t, err, tc.want)
			assert.Nil(t, frames, "DecodeBatch leaked the frames before the bad one")

			frames, err = frame.Limits{}.DecodeBatchFrom(bytes.NewReader(tc.batch), tc.dir)
			require.ErrorIs(t, err, tc.want)
			assert.Nil(t, frames, "DecodeBatchFrom leaked the frames before the bad one")
		})
	}
}

// ---------- D2 extension: every other way a batch can fail after frame 0 ----------

// halfReader hands out b and then fails, so a transport error lands after a
// whole good frame rather than on the first read.
type halfReader struct {
	b   []byte
	off int
}

func (r *halfReader) Read(p []byte) (int, error) {
	if r.off >= len(r.b) {
		return 0, io.ErrClosedPipe
	}

	n := copy(p, r.b[r.off:])
	r.off += n

	return n, nil
}

func TestEveryRejectionSiteLeaksNothingAfterAGoodFrame(t *testing.T) {
	good := wellFormed(frame.TypeOpen, 17, nil)

	for _, tc := range []struct {
		name  string
		batch []byte
		lim   frame.Limits
		want  error
	}{
		{
			"a bad header after a good frame",
			append(append([]byte(nil), good...), wellFormed(frame.TypeOpen, 0, nil)...),
			frame.Limits{},
			frame.ErrStreamFrameOnZero,
		},
		{
			"an oversized declared length after a good frame",
			append(append([]byte(nil), good...), raw(frame.TypeData, 1, frame.MaxPayloadSize+1, nil)...),
			frame.Limits{},
			frame.ErrPayloadTooLarge,
		},
		{
			"a truncated header after a good frame",
			append(append([]byte(nil), good...), 0x01, 0x00),
			frame.Limits{},
			frame.ErrPartialFrame,
		},
		{
			"a truncated payload after a good frame",
			append(append([]byte(nil), good...), wellFormed(frame.TypeData, 1, []byte("twelve bytes"))[:14]...),
			frame.Limits{},
			frame.ErrPartialFrame,
		},
		{
			"a budget overrun after a good frame",
			append(append([]byte(nil), good...), wellFormed(frame.TypeData, 1, bytes.Repeat([]byte{1}, 64))...),
			frame.Limits{BatchBytes: 32},
			frame.ErrBatchTooLarge,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			frames, err := tc.lim.DecodeBatch(tc.batch, frame.ClientToRelay)
			require.ErrorIs(t, err, tc.want)
			assert.Nil(t, frames, "DecodeBatch leaked the frames before the bad one")

			frames, err = tc.lim.DecodeBatchFrom(bytes.NewReader(tc.batch), frame.ClientToRelay)
			require.ErrorIs(t, err, tc.want)
			assert.Nil(t, frames, "DecodeBatchFrom leaked the frames before the bad one")
		})
	}
}

func TestATransportErrorAfterAGoodFrameLeaksNothing(t *testing.T) {
	// The reader dies mid-batch rather than on its first read, which is the
	// only shape in which the two io error sites hold accumulated frames.
	good := wellFormed(frame.TypeOpen, 17, nil)

	frames, err := frame.Limits{}.DecodeBatchFrom(&halfReader{b: good}, frame.ClientToRelay)
	require.ErrorIs(t, err, io.ErrClosedPipe)
	assert.Nil(t, frames, "a dead carrier handed back the frames read before it died")

	// The same, with the failure inside a payload rather than a header.
	partial := append(append([]byte(nil), good...), wellFormed(frame.TypeData, 1, []byte("abcd"))[:10]...)

	frames, err = frame.Limits{}.DecodeBatchFrom(&halfReader{b: partial}, frame.ClientToRelay)
	require.Error(t, err)
	assert.Nil(t, frames, "a dead carrier handed back the frames read before it died")
}

func TestTheFrameCapRejectionLeaksNothing(t *testing.T) {
	// 4097 empty CLOSE frames: the cap trips with 4096 good frames already in
	// the accumulator, the largest leak this decoder can produce.
	batch := bytes.Repeat(wellFormed(frame.TypeClose, 1, nil), frame.MaxFramesPerBatch+1)

	frames, err := frame.Limits{}.DecodeBatch(batch, frame.ClientToRelay)
	require.ErrorIs(t, err, frame.ErrTooManyFrames)
	assert.Nil(t, frames, "the frame cap handed back 4096 frames")

	frames, err = frame.Limits{}.DecodeBatchFrom(bytes.NewReader(batch), frame.ClientToRelay)
	require.ErrorIs(t, err, frame.ErrTooManyFrames)
	assert.Nil(t, frames, "the frame cap handed back 4096 frames")
}

// ---------- a lowered payload bound is expressible and enforced ----------

func TestASharplyLoweredPayloadCapBites(t *testing.T) {
	lim := frame.Limits{MaxPayload: 16}

	_, err := decodeBothWith(t, lim, wellFormed(frame.TypeData, 1, bytes.Repeat([]byte{7}, 17)), frame.ClientToRelay)
	require.ErrorIs(t, err, frame.ErrPayloadTooLarge)

	decoded, err := decodeBothWith(t, lim, wellFormed(frame.TypeData, 1, bytes.Repeat([]byte{7}, 16)), frame.ClientToRelay)
	require.NoError(t, err)
	require.Len(t, decoded, 1)

	_, err = lim.EncodeBatch(nil,
		[]frame.Frame{frame.NewData(1, bytes.Repeat([]byte{7}, 17))}, frame.RelayToClient)
	require.ErrorIs(t, err, frame.ErrPayloadTooLarge)
}
