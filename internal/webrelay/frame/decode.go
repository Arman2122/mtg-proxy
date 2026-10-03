package frame

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Both decoders return frames only when every frame in the batch validated.
// The spec requires a batch to be checked in full before any of it is applied,
// so that rule lives in the signature rather than in a comment for the caller
// to honour: on any error the frame slice is nil and there is nothing to apply.
// The case that rule exists for is a late frame -- a zero WINDOW at index 3 of
// four -- where a decoder is already holding three good frames it must drop.
//
// Payloads are copied out of the input. A carrier hands us a buffer it intends
// to reuse for the next read while the session layer is still holding a DATA
// frame queued for a backend write, and aliasing that buffer is a silent
// corruption bug rather than a crash.

// parseHeader splits the fixed 8-byte header. h must be exactly HeaderSize
// long; both callers guarantee that before they call.
func parseHeader(h []byte) (frameType Type, streamID, payloadLen uint32) {
	return Type(h[0]),
		uint32(h[1])<<16 | uint32(h[2])<<8 | uint32(h[3]),
		binary.BigEndian.Uint32(h[4:HeaderSize])
}

// DecodeBatch decodes one whole carrier message under l. b is not retained.
//
// A zero-length b yields no frames and no error. The spec does not say whether
// an empty batch is malformed, so that judgement is left to the session layer,
// which knows whether it just answered a poll or received a spurious wakeup.
func (l Limits) DecodeBatch(b []byte, dir Direction) ([]Frame, error) {
	return l.decodeBatch(b, dir, true)
}

// DecodeBatchAliased is DecodeBatch without the copies: every payload is a
// slice of b, capped at its own end. It is for a caller that never writes b
// again -- the relay's read loop, whose carrier hands out a fresh message per
// read -- and it refuses exactly what DecodeBatch refuses.
func (l Limits) DecodeBatchAliased(b []byte, dir Direction) ([]Frame, error) {
	return l.decodeBatch(b, dir, false)
}

func (l Limits) decodeBatch(b []byte, dir Direction, copyPayloads bool) ([]Frame, error) {
	var (
		frames []Frame
		offset int
	)

	// The whole message is already in memory, so the budget is checked once
	// here rather than per frame; trailing bytes that form no frame count too.
	if budget := l.batchBytes(); int64(len(b)) > budget {
		return nil, fmt.Errorf("%w: %d bytes, budget %d", ErrBatchTooLarge, len(b), budget)
	}

	maxPayload := l.maxPayload()

	for offset < len(b) {
		if len(frames) == MaxFramesPerBatch {
			return nil, fmt.Errorf("%w: more than %d", ErrTooManyFrames, MaxFramesPerBatch)
		}

		if len(b)-offset < HeaderSize {
			return nil, fmt.Errorf("%w: %d header bytes at offset %d",
				ErrPartialFrame, len(b)-offset, offset)
		}

		frameType, streamID, payloadLen := parseHeader(b[offset : offset+HeaderSize])

		if err := checkHeader(frameType, streamID, payloadLen, maxPayload, dir); err != nil {
			return nil, fmt.Errorf("frame %d at offset %d: %w", len(frames), offset, err)
		}

		// Safe: checkHeader rejected anything above maxPayload, itself at most
		// MaxPayloadSize.
		length := int(payloadLen)
		offset += HeaderSize

		// Subtraction rather than offset+length, which is the shape that
		// overflows on a hostile length.
		if len(b)-offset < length {
			return nil, fmt.Errorf("%w: frame %d wants %d payload bytes, %d left",
				ErrPartialFrame, len(frames), length, len(b)-offset)
		}

		frame := Frame{Type: frameType, StreamID: streamID}

		switch {
		case length == 0:
		case copyPayloads:
			frame.Payload = make([]byte, length)
			copy(frame.Payload, b[offset:offset+length])
		default:
			frame.Payload = b[offset : offset+length : offset+length]
		}

		offset += length

		if err := checkPayload(frameType, frame.Payload); err != nil {
			return nil, fmt.Errorf("frame %d: %w", len(frames), err)
		}

		frames = append(frames, frame)
	}

	return frames, nil
}

// DecodeBatchFrom decodes one whole batch from r under l. It exists for
// carriers that deliver a body rather than a message; it never buys a buffer
// for the whole body, only for the payload of the frame it is on.
//
// Overrunning l's byte budget is reported as ErrBatchTooLarge rather than as a
// truncated frame, which is why r is not wrapped in an io.LimitReader.
func (l Limits) DecodeBatchFrom(r io.Reader, dir Direction) ([]Frame, error) {
	var (
		frames   []Frame
		consumed int64
		header   [HeaderSize]byte
	)

	maxBytes := l.batchBytes()
	maxPayload := l.maxPayload()

	for {
		switch _, err := io.ReadFull(r, header[:]); {
		case errors.Is(err, io.EOF):
			// A clean end exactly on a frame boundary: the batch is complete.
			return frames, nil
		case errors.Is(err, io.ErrUnexpectedEOF):
			return nil, fmt.Errorf("%w: truncated header of frame %d", ErrPartialFrame, len(frames))
		case err != nil:
			return nil, fmt.Errorf("reading the header of frame %d: %w", len(frames), err)
		}

		if len(frames) == MaxFramesPerBatch {
			return nil, fmt.Errorf("%w: more than %d", ErrTooManyFrames, MaxFramesPerBatch)
		}

		frameType, streamID, payloadLen := parseHeader(header[:])

		if err := checkHeader(frameType, streamID, payloadLen, maxPayload, dir); err != nil {
			return nil, fmt.Errorf("frame %d: %w", len(frames), err)
		}

		// Safe: checkHeader rejected anything above maxPayload, itself at most
		// MaxPayloadSize, so the widening to int64 and the addition below
		// cannot overflow either.
		length := int(payloadLen)

		if consumed+HeaderSize+int64(length) > maxBytes {
			return nil, fmt.Errorf("%w: frame %d would reach %d bytes, budget %d",
				ErrBatchTooLarge, len(frames), consumed+HeaderSize+int64(length), maxBytes)
		}

		consumed += HeaderSize + int64(length)

		frame := Frame{Type: frameType, StreamID: streamID}
		if length > 0 {
			frame.Payload = make([]byte, length)

			switch _, err := io.ReadFull(r, frame.Payload); {
			case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
				return nil, fmt.Errorf("%w: truncated payload of frame %d", ErrPartialFrame, len(frames))
			case err != nil:
				return nil, fmt.Errorf("reading the payload of frame %d: %w", len(frames), err)
			}
		}

		if err := checkPayload(frameType, frame.Payload); err != nil {
			return nil, fmt.Errorf("frame %d: %w", len(frames), err)
		}

		frames = append(frames, frame)
	}
}

// DecodeHello parses a session-creation body, which the spec fixes at exactly
// one HELLO frame and nothing else. The length is checked first so an oversized
// body is rejected without being parsed.
func DecodeHello(body []byte) error {
	if len(body) > MaxSessionCreateBody {
		return fmt.Errorf("%w: %d bytes, cap %d", ErrBatchTooLarge, len(body), MaxSessionCreateBody)
	}

	frames, err := Limits{}.DecodeBatch(body, ClientToRelay)
	if err != nil {
		return err
	}

	if len(frames) != 1 || frames[0].Type != TypeHello {
		return fmt.Errorf("%w: %d frames", ErrNotHello, len(frames))
	}

	return nil
}
