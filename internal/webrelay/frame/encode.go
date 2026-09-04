package frame

import (
	"encoding/binary"
	"fmt"
)

// AppendTo validates the frame for dir under the protocol ceilings and appends
// its wire bytes to dst, returning the extended slice. Nothing is appended when
// validation fails, so a caller that ignores the error still cannot emit a
// half-written frame.
func (f Frame) AppendTo(dst []byte, dir Direction) ([]byte, error) {
	return f.appendTo(dst, Limits{}, dir)
}

func (f Frame) appendTo(dst []byte, lim Limits, dir Direction) ([]byte, error) {
	if err := f.validate(lim, dir); err != nil {
		return dst, err
	}

	// Safe: validate bounded the id at MaxStreamID, so the u24 field holds it.
	header := [HeaderSize]byte{
		byte(f.Type),
		byte(f.StreamID >> 16),
		byte(f.StreamID >> 8),
		byte(f.StreamID),
	}
	// Safe: validate bounded the length at lim's payload cap, itself at most
	// MaxPayloadSize.
	binary.BigEndian.PutUint32(header[4:], uint32(len(f.Payload))) //nolint:gosec // bounded by validate

	dst = append(dst, header[:]...)
	dst = append(dst, f.Payload...)

	return dst, nil
}

// EncodeForClient encodes one relay-to-client frame on its own -- the shape the
// WELCOME body needs. The direction is in the name rather than in a parameter
// because this is not the general form: a carrier assembling several frames
// should use Limits.EncodeBatch, which is the only form that bounds a batch.
func (f Frame) EncodeForClient() ([]byte, error) {
	return f.AppendTo(make([]byte, 0, f.EncodedLen()), RelayToClient)
}

// EncodeBatch appends a whole carrier batch to dst, enforcing on the way out
// every bound the peer's decoder enforces on the way in: the frame cap, l's
// per-frame payload cap, and l's whole-batch byte budget.
//
// The byte budget is the one that matters in practice and the one a count of
// frames does not imply. 4096 individually legal 64 KiB DATA frames are 256 MiB
// together, and the client drops an oversized message whole rather than
// truncating it, so the session dies with nothing to see on this side.
func (l Limits) EncodeBatch(dst []byte, frames []Frame, dir Direction) ([]byte, error) {
	if len(frames) > MaxFramesPerBatch {
		return dst, fmt.Errorf("%w: %d, cap %d", ErrTooManyFrames, len(frames), MaxFramesPerBatch)
	}

	// Before the allocation below, not after: a batch at both caps asks for
	// 4 GiB, which is also why the total is accumulated in an int64.
	total := encodedLen(frames)
	if budget := l.batchBytes(); total > budget {
		return dst, fmt.Errorf("%w: %d bytes, budget %d", ErrBatchTooLarge, total, budget)
	}

	// Encode into a separate slice so a failure halfway through cannot leave
	// the caller's buffer holding a partial batch.
	out := make([]byte, 0, int(total)) //nolint:gosec // bounded by the budget check above

	for i := range frames {
		var err error

		if out, err = frames[i].appendTo(out, l, dir); err != nil {
			return dst, fmt.Errorf("frame %d: %w", i, err)
		}
	}

	return append(dst, out...), nil
}

func encodedLen(frames []Frame) int64 {
	total := int64(0)
	for i := range frames {
		total += int64(frames[i].EncodedLen())
	}

	return total
}
