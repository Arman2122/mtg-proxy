package frame_test

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"

	"github.com/Arman2122/mtg-proxy/internal/webrelay/frame"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// raw builds wire bytes with a declared length that need not match the payload
// actually appended, which is the whole point: a hostile peer controls the
// length field independently of what it sends.
func raw(t frame.Type, streamID, declaredLen uint32, payload []byte) []byte {
	header := []byte{
		byte(t),
		byte(streamID >> 16),
		byte(streamID >> 8),
		byte(streamID),
		0, 0, 0, 0,
	}
	binary.BigEndian.PutUint32(header[4:], declaredLen)

	return append(header, payload...)
}

// wellFormed builds a frame whose declared length matches its payload.
func wellFormed(t frame.Type, streamID uint32, payload []byte) []byte {
	// Safe: every payload in this file is a test literal well under 4 GiB.
	return raw(t, streamID, uint32(len(payload)), payload)
}

// Each entry is one of the fatal protocol errors the spec enumerates, exercised
// on its own so that a decoder which stopped checking one of them fails exactly
// one test.
func TestEveryFatalProtocolErrorIsRejected(t *testing.T) {
	for _, tc := range []struct {
		name  string
		input []byte
		dir   frame.Direction
		want  error
	}{
		{
			"type byte 0x00 is unassigned",
			wellFormed(frame.Type(0x00), 1, nil), frame.ClientToRelay, frame.ErrUnknownType,
		},
		{
			"type byte 0x07 falls in the gap below HELLO",
			wellFormed(frame.Type(0x07), 1, nil), frame.ClientToRelay, frame.ErrUnknownType,
		},
		{
			"type byte 0x12 falls in the gap above WELCOME",
			wellFormed(frame.Type(0x12), 1, nil), frame.ClientToRelay, frame.ErrUnknownType,
		},
		{
			"type byte 0xff is unassigned",
			wellFormed(frame.Type(0xff), 1, nil), frame.ClientToRelay, frame.ErrUnknownType,
		},
		{
			"HELLO on a nonzero stream",
			wellFormed(frame.TypeHello, 1, []byte{frame.Version}), frame.ClientToRelay,
			frame.ErrSessionFrameOnStream,
		},
		{
			"PONG on a nonzero stream",
			wellFormed(frame.TypePong, 4, []byte("token")), frame.ClientToRelay,
			frame.ErrSessionFrameOnStream,
		},
		{
			"WELCOME on a nonzero stream",
			wellFormed(frame.TypeWelcome, 1, nil), frame.RelayToClient,
			frame.ErrSessionFrameOnStream,
		},
		{
			"OPEN on stream zero",
			wellFormed(frame.TypeOpen, 0, nil), frame.ClientToRelay, frame.ErrStreamFrameOnZero,
		},
		{
			"DATA on stream zero",
			wellFormed(frame.TypeData, 0, []byte("x")), frame.ClientToRelay, frame.ErrStreamFrameOnZero,
		},
		{
			"CLOSE on stream zero",
			wellFormed(frame.TypeClose, 0, nil), frame.ClientToRelay, frame.ErrStreamFrameOnZero,
		},
		{
			"WINDOW on stream zero",
			wellFormed(frame.TypeWindow, 0, []byte{0, 0, 0, 1}), frame.ClientToRelay,
			frame.ErrStreamFrameOnZero,
		},
		{
			"OPEN arriving from the relay",
			wellFormed(frame.TypeOpen, 17, nil), frame.RelayToClient, frame.ErrWrongDirection,
		},
		{
			"HELLO arriving from the relay",
			helloBytes, frame.RelayToClient, frame.ErrWrongDirection,
		},
		{
			"WELCOME arriving from the client",
			welcomeBytes, frame.ClientToRelay, frame.ErrWrongDirection,
		},
		{
			"PING arriving from the client",
			wellFormed(frame.TypePing, 0, []byte("token")), frame.ClientToRelay, frame.ErrWrongDirection,
		},
		{
			"PONG arriving from the relay",
			wellFormed(frame.TypePong, 0, []byte("token")), frame.RelayToClient, frame.ErrWrongDirection,
		},
		{
			"BYE arriving from the client",
			wellFormed(frame.TypeBye, 0, nil), frame.ClientToRelay, frame.ErrWrongDirection,
		},
		{
			"the zero value of Direction is not a direction",
			helloBytes, frame.Direction(0), frame.ErrWrongDirection,
		},
		{
			"a header cut short",
			openBytes[:7], frame.ClientToRelay, frame.ErrPartialFrame,
		},
		{
			"a whole frame followed by a stray byte",
			append(append([]byte(nil), openBytes...), 0x02), frame.ClientToRelay, frame.ErrPartialFrame,
		},
		{
			"a payload shorter than its declared length",
			raw(frame.TypeData, 1, 8, []byte("short")), frame.ClientToRelay, frame.ErrPartialFrame,
		},
		{
			"a length field of 0xffffffff, which overflows a naive offset+length",
			raw(frame.TypeData, 1, 0xffffffff, nil), frame.ClientToRelay, frame.ErrPayloadTooLarge,
		},
		{
			"a length one byte past the maximum payload",
			raw(frame.TypeData, 1, frame.MaxPayloadSize+1, nil), frame.ClientToRelay,
			frame.ErrPayloadTooLarge,
		},
		{
			"a WINDOW granting zero credit",
			wellFormed(frame.TypeWindow, 1, []byte{0, 0, 0, 0}), frame.ClientToRelay, frame.ErrZeroWindow,
		},
		{
			"a DATA frame with an empty payload",
			wellFormed(frame.TypeData, 1, nil), frame.ClientToRelay, frame.ErrEmptyData,
		},
		{
			"an OPEN carrying a payload",
			wellFormed(frame.TypeOpen, 17, []byte("x")), frame.ClientToRelay, frame.ErrPayloadLength,
		},
		{
			"a CLOSE carrying a payload",
			wellFormed(frame.TypeClose, 17, []byte("why")), frame.ClientToRelay, frame.ErrPayloadLength,
		},
		{
			"a WELCOME carrying a payload",
			wellFormed(frame.TypeWelcome, 0, []byte("x")), frame.RelayToClient, frame.ErrPayloadLength,
		},
		{
			"a WINDOW of three bytes",
			wellFormed(frame.TypeWindow, 1, []byte{0, 0, 1}), frame.ClientToRelay, frame.ErrPayloadLength,
		},
		{
			"a WINDOW of five bytes",
			wellFormed(frame.TypeWindow, 1, []byte{0, 0, 0, 0, 1}), frame.ClientToRelay,
			frame.ErrPayloadLength,
		},
		{
			"a HELLO with no version byte",
			wellFormed(frame.TypeHello, 0, nil), frame.ClientToRelay, frame.ErrPayloadLength,
		},
		{
			"a HELLO with two version bytes",
			wellFormed(frame.TypeHello, 0, []byte{1, 1}), frame.ClientToRelay, frame.ErrPayloadLength,
		},
		{
			"a HELLO announcing v2",
			wellFormed(frame.TypeHello, 0, []byte{0x02}), frame.ClientToRelay,
			frame.ErrUnsupportedVersion,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := decodeBoth(t, tc.input, tc.dir)
			require.ErrorIs(t, err, tc.want)
		})
	}
}

func TestTheMaximumPayloadIsAcceptedAndOneMoreByteIsNot(t *testing.T) {
	payload := bytes.Repeat([]byte{0x5a}, frame.MaxPayloadSize)

	decoded, err := decodeBoth(t, wellFormed(frame.TypeData, 1, payload), frame.ClientToRelay)
	require.NoError(t, err)
	require.Len(t, decoded, 1)
	assert.Len(t, decoded[0].Payload, frame.MaxPayloadSize)

	// One byte more, declared but not sent: the length alone must be refused,
	// because the point of the bound is to refuse before allocating.
	_, err = decodeBoth(t, raw(frame.TypeData, 1, frame.MaxPayloadSize+1, nil), frame.ClientToRelay)
	require.ErrorIs(t, err, frame.ErrPayloadTooLarge)
}

func TestTheFrameCapIsAcceptedAndOneMoreFrameIsNot(t *testing.T) {
	full := bytes.Repeat(openBytes, frame.MaxFramesPerBatch)

	decoded, err := decodeBoth(t, full, frame.ClientToRelay)
	require.NoError(t, err)
	assert.Len(t, decoded, frame.MaxFramesPerBatch)

	_, err = decodeBoth(t, append(full, openBytes...), frame.ClientToRelay)
	require.ErrorIs(t, err, frame.ErrTooManyFrames)
}

func TestNoFrameOfARejectedBatchIsHandedBack(t *testing.T) {
	// The spec requires a batch to be validated in full before any of it is
	// applied. The codec enforces that by refusing to return a partial result,
	// so the caller has nothing to apply early even if it wanted to.
	batch := append(append([]byte(nil), openBytes...), wellFormed(frame.TypeData, 1, nil)...)

	frames, err := frame.Limits{}.DecodeBatch(batch, frame.ClientToRelay)
	require.ErrorIs(t, err, frame.ErrEmptyData)
	assert.Nil(t, frames)

	frames, err = frame.Limits{}.DecodeBatchFrom(bytes.NewReader(batch), frame.ClientToRelay)
	require.ErrorIs(t, err, frame.ErrEmptyData)
	assert.Nil(t, frames)
}

// A batch that fails on its first frame proves nothing about atomicity: the
// accumulator is still empty, so a decoder that returned what it had would
// return nothing anyway. These batches carry one good frame and then a frame
// that is well-formed enough to reach checkPayload, which is the only shape
// where a decoder has something to leak.
func TestNoFrameOfARejectedBatchIsHandedBackWhenALaterFrameFails(t *testing.T) {
	for _, tc := range []struct {
		name   string
		second []byte
		want   error
	}{
		{
			"a WINDOW granting zero credit",
			wellFormed(frame.TypeWindow, 17, []byte{0, 0, 0, 0}), frame.ErrZeroWindow,
		},
		{
			"a HELLO announcing v2",
			wellFormed(frame.TypeHello, 0, []byte{0x02}), frame.ErrUnsupportedVersion,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			batch := append(append([]byte(nil), openBytes...), tc.second...)

			frames, err := frame.Limits{}.DecodeBatch(batch, frame.ClientToRelay)
			require.ErrorIs(t, err, tc.want)
			assert.Nil(t, frames, "a rejected batch handed back the frames before the bad one")

			frames, err = frame.Limits{}.DecodeBatchFrom(bytes.NewReader(batch), frame.ClientToRelay)
			require.ErrorIs(t, err, tc.want)
			assert.Nil(t, frames, "a rejected batch handed back the frames before the bad one")
		})
	}
}

func TestDecodedPayloadsDoNotAliasTheCarrierBuffer(t *testing.T) {
	// A carrier reuses its read buffer for the next message while the session
	// layer still holds this DATA frame queued for a backend write. Aliasing it
	// would corrupt the stream silently rather than fail loudly.
	buf := wellFormed(frame.TypeData, 1, []byte("original"))

	decoded, err := frame.Limits{}.DecodeBatch(buf, frame.ClientToRelay)
	require.NoError(t, err)
	require.Len(t, decoded, 1)

	for i := range buf {
		buf[i] = 0xff
	}

	assert.Equal(t, []byte("original"), decoded[0].Payload)
}

func TestTheReaderDecoderStopsAtItsByteBudget(t *testing.T) {
	batch := bytes.Repeat(openBytes, 4)

	exact := frame.Limits{BatchBytes: int64(len(batch))}

	frames, err := exact.DecodeBatchFrom(bytes.NewReader(batch), frame.ClientToRelay)
	require.NoError(t, err)
	assert.Len(t, frames, 4)

	// One byte short of the batch. This is a budget overrun, not a truncated
	// frame: the bytes are all there, the caller just refused to read them.
	tight := frame.Limits{BatchBytes: int64(len(batch)) - 1}
	_, err = tight.DecodeBatchFrom(bytes.NewReader(batch), frame.ClientToRelay)
	require.ErrorIs(t, err, frame.ErrBatchTooLarge)

	// The []byte decoder enforces the same budget, so a body one decoder would
	// refuse cannot be smuggled past the other.
	_, err = tight.DecodeBatch(batch, frame.ClientToRelay)
	require.ErrorIs(t, err, frame.ErrBatchTooLarge)

	// A payload the budget cannot cover is refused from the header alone,
	// before the payload is read or allocated.
	big := wellFormed(frame.TypeData, 1, bytes.Repeat([]byte{1}, 4096))
	_, err = frame.Limits{BatchBytes: 64}.DecodeBatchFrom(bytes.NewReader(big), frame.ClientToRelay)
	require.ErrorIs(t, err, frame.ErrBatchTooLarge)
}

func TestTheReaderDecoderReportsATornPayloadAsAPartialFrame(t *testing.T) {
	// io.ErrUnexpectedEOF inside a payload is a protocol error, not a transport
	// hiccup to be retried, so it must surface as ErrPartialFrame.
	torn := wellFormed(frame.TypeData, 1, []byte("twelve bytes"))[:14]

	_, err := frame.Limits{BatchBytes: 1024}.DecodeBatchFrom(bytes.NewReader(torn), frame.ClientToRelay)
	require.ErrorIs(t, err, frame.ErrPartialFrame)
}

type failingReader struct{ err error }

func (r failingReader) Read([]byte) (int, error) { return 0, r.err }

func TestTheReaderDecoderPropagatesATransportError(t *testing.T) {
	// A dead carrier is not a protocol violation, so the underlying error must
	// stay reachable instead of being flattened into ErrPartialFrame.
	_, err := frame.Limits{BatchBytes: 1024}.DecodeBatchFrom(failingReader{io.ErrClosedPipe}, frame.ClientToRelay)
	require.ErrorIs(t, err, io.ErrClosedPipe)
	assert.NotErrorIs(t, err, frame.ErrPartialFrame)
}

func TestDecodeHello(t *testing.T) {
	require.NoError(t, frame.DecodeHello(helloBytes))

	for _, tc := range []struct {
		name string
		body []byte
		want error
	}{
		{
			"a body over the 64-byte cap",
			bytes.Repeat([]byte{0x00}, frame.MaxSessionCreateBody+1),
			frame.ErrBatchTooLarge,
		},
		{
			"two HELLOs",
			append(append([]byte(nil), helloBytes...), helloBytes...),
			frame.ErrNotHello,
		},
		{
			"an empty body",
			nil,
			frame.ErrNotHello,
		},
		{
			"an OPEN instead of a HELLO",
			openBytes,
			frame.ErrNotHello,
		},
		{
			"a HELLO with a trailing frame",
			append(append([]byte(nil), helloBytes...), openBytes...),
			frame.ErrNotHello,
		},
		{
			"a HELLO with trailing bytes that do not form a frame",
			append(append([]byte(nil), helloBytes...), 0x01, 0x02),
			frame.ErrPartialFrame,
		},
		{
			"a HELLO announcing v2",
			wellFormed(frame.TypeHello, 0, []byte{0x02}),
			frame.ErrUnsupportedVersion,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.ErrorIs(t, frame.DecodeHello(tc.body), tc.want)
		})
	}
}
