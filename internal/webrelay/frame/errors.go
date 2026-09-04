package frame

import "errors"

// Every error below is a fatal protocol error: the session that produced it is
// finished, and no frame from the offending batch may be applied. They are
// separate sentinels so the session layer can count them by class in metrics
// without ever logging the bytes that caused them.
var (
	// ErrUnknownType is an unassigned type byte. v1 assigns nine of 256.
	ErrUnknownType = errors.New("unknown frame type")

	// ErrWrongDirection is a frame only the other peer is allowed to send, or a
	// caller that passed no Direction at all.
	ErrWrongDirection = errors.New("frame sent in the wrong direction")

	// ErrSessionFrameOnStream is a session frame carrying a nonzero stream id.
	ErrSessionFrameOnStream = errors.New("session frame on a nonzero stream")

	// ErrStreamFrameOnZero is a stream frame carrying stream id zero.
	ErrStreamFrameOnZero = errors.New("stream frame on stream zero")

	// ErrPayloadTooLarge is a declared payload length above MaxPayloadSize. It
	// is checked against the header alone, before anything is allocated.
	ErrPayloadTooLarge = errors.New("payload longer than the maximum frame payload")

	// ErrPayloadLength is a payload whose length is wrong for its type: a
	// nonempty OPEN, CLOSE or WELCOME, a WINDOW that is not four bytes, a HELLO
	// that is not one.
	ErrPayloadLength = errors.New("payload length invalid for this frame type")

	// ErrEmptyData is a DATA frame with no payload. DATA is defined as opaque
	// and nonempty, so a zero-length one is a way to spend a batch slot for
	// free.
	ErrEmptyData = errors.New("DATA frame with an empty payload")

	// ErrZeroWindow is a WINDOW frame granting zero credit, which can never
	// unblock a stalled stream and so is never legitimate.
	ErrZeroWindow = errors.New("WINDOW frame with a zero delta")

	// ErrUnsupportedVersion is a HELLO whose single byte is not Version.
	ErrUnsupportedVersion = errors.New("HELLO announcing an unsupported protocol version")

	// ErrPartialFrame is a batch that ends inside a frame -- a truncated header
	// or a payload shorter than its declared length.
	ErrPartialFrame = errors.New("trailing partial frame")

	// ErrTooManyFrames is a batch holding more than MaxFramesPerBatch frames.
	ErrTooManyFrames = errors.New("too many frames in one batch")

	// ErrBatchTooLarge is a batch whose total encoded size exceeds the byte
	// budget, on either the decode or the encode path.
	ErrBatchTooLarge = errors.New("batch longer than the byte budget")

	// ErrLimitOutOfRange is a configured bound outside the range a deployment
	// may choose. It is a startup error, not a protocol error.
	ErrLimitOutOfRange = errors.New("configured limit outside the permitted range")

	// ErrStreamIDRange is an encoder-side stream id that does not fit the u24
	// field. It cannot arise from decoding.
	ErrStreamIDRange = errors.New("stream id does not fit 24 bits")

	// ErrNotHello is a session-creation body that is anything other than
	// exactly one HELLO frame.
	ErrNotHello = errors.New("session-creation body is not exactly one HELLO frame")
)
