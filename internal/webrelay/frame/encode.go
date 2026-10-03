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

	var header [HeaderSize]byte

	f.putHeader(header[:])

	dst = append(dst, header[:]...)
	dst = append(dst, f.Payload...)

	return dst, nil
}

// putHeader writes f's 8-byte header into dst. f has passed validate.
func (f Frame) putHeader(dst []byte) {
	// Safe: validate bounded the id at MaxStreamID, so the u24 field holds it.
	dst[0] = byte(f.Type)
	dst[1] = byte(f.StreamID >> 16) //nolint:gosec // validate bounded the id at MaxStreamID
	dst[2] = byte(f.StreamID >> 8)  //nolint:gosec // same
	dst[3] = byte(f.StreamID)       //nolint:gosec // same
	// Safe: validate bounded the length at the payload cap, itself at most
	// MaxPayloadSize.
	binary.BigEndian.PutUint32(dst[4:HeaderSize], uint32(len(f.Payload))) //nolint:gosec // bounded by validate
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

// inlinePayload is the largest payload BatchVectors copies beside its header
// rather than giving it a vector of its own: WINDOW's four bytes, CLOSE's none.
// A batch of thousands of control frames is then a handful of vectors, not
// thousands -- a single writev takes at most 1,024 and would be split.
const inlinePayload = 64

// BatchVectors is EncodeBatch as write vectors, for a single vectored write
// of the batch: no batch buffer, and no copy of any DATA payload. Headers, and
// payloads of at most inlinePayload bytes, are written into scratch, which is
// grown once to fit; every larger payload is a vector of its own, the frame's
// own slice. It appends to vecs and returns vecs and scratch for reuse, and
// refuses exactly what EncodeBatch refuses, leaving vecs as it was.
//
// The vectors alias scratch and the frames' payloads: they are valid until
// either is written again.
func (l Limits) BatchVectors(vecs [][]byte, scratch []byte, frames []Frame, dir Direction) ([][]byte, []byte, error) {
	if len(frames) > MaxFramesPerBatch {
		return vecs, scratch, fmt.Errorf("%w: %d, cap %d", ErrTooManyFrames, len(frames), MaxFramesPerBatch)
	}

	total := encodedLen(frames)
	if budget := l.batchBytes(); total > budget {
		return vecs, scratch, fmt.Errorf("%w: %d bytes, budget %d", ErrBatchTooLarge, total, budget)
	}

	need := 0

	for i := range frames {
		if err := frames[i].validate(l, dir); err != nil {
			return vecs, scratch, fmt.Errorf("frame %d: %w", i, err)
		}

		need += HeaderSize
		if len(frames[i].Payload) <= inlinePayload {
			need += len(frames[i].Payload)
		}
	}

	if cap(scratch) < need {
		scratch = make([]byte, need)
	}

	scratch = scratch[:need]

	// run is where the stretch of scratch not yet in a vector starts: headers
	// and inline payloads lie contiguous, so one vector carries them all.
	run, at := 0, 0

	for i := range frames {
		frames[i].putHeader(scratch[at : at+HeaderSize])
		at += HeaderSize

		if payload := frames[i].Payload; len(payload) <= inlinePayload {
			at += copy(scratch[at:], payload)

			continue
		}

		vecs = append(vecs, scratch[run:at:at], frames[i].Payload)
		run = at
	}

	if at > run {
		vecs = append(vecs, scratch[run:at:at])
	}

	return vecs, scratch, nil
}

func encodedLen(frames []Frame) int64 {
	total := int64(0)
	for i := range frames {
		total += int64(frames[i].EncodedLen())
	}

	return total
}
