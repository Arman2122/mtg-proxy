package frame

import "fmt"

// Limits are the two wire bounds a deployment is allowed to move, and the only
// tuning this codec accepts. Both are ceilings compiled into the client rather
// than values it learns: WELCOME carries no parameters, so a peer that raises
// one breaks interop silently, while lowering one is always safe because the
// peer accepts everything a stricter sender emits. The published example is a
// deployment still serving Linux Desktop builds from before the 2 MiB message
// cap, which must set the frame payload bound to 512 KiB.
//
// The zero value is the protocol default. A field above its ceiling is clamped
// down to it rather than honoured, so a misconfiguration can only ever make
// this side stricter than the client, never looser; Validate exists so a
// config loader can refuse that input instead of running a quietly different
// bound. Every batch operation hangs off this type: there is deliberately no
// unbounded form of either encoding or decoding a batch.
type Limits struct {
	// MaxPayload is the largest payload one frame may carry, at most
	// MaxPayloadSize. Zero means MaxPayloadSize.
	MaxPayload int

	// BatchBytes is the largest encoded size of one whole batch, at most
	// MaxBatchBytes. Zero means MaxBatchBytes.
	BatchBytes int64
}

// maxPayload is the effective per-frame bound, clamped into (0, MaxPayloadSize].
func (l Limits) maxPayload() int {
	if l.MaxPayload <= 0 || l.MaxPayload > MaxPayloadSize {
		return MaxPayloadSize
	}

	return l.MaxPayload
}

// batchBytes is the effective whole-batch bound, clamped into (0, MaxBatchBytes].
func (l Limits) batchBytes() int64 {
	if l.BatchBytes <= 0 || l.BatchBytes > MaxBatchBytes {
		return MaxBatchBytes
	}

	return l.BatchBytes
}

// Validate reports a Limits that a config loader should refuse at startup. The
// accessors clamp an out-of-range field anyway, so this is not a safety check;
// it is how an operator who typed a bound the client cannot honour is told,
// rather than running a configuration that is not the one on disk.
func (l Limits) Validate() error {
	if l.MaxPayload < 0 || l.MaxPayload > MaxPayloadSize {
		return fmt.Errorf("%w: frame payload %d, ceiling %d",
			ErrLimitOutOfRange, l.MaxPayload, MaxPayloadSize)
	}

	if l.BatchBytes < 0 || l.BatchBytes > MaxBatchBytes {
		return fmt.Errorf("%w: batch bytes %d, ceiling %d",
			ErrLimitOutOfRange, l.BatchBytes, MaxBatchBytes)
	}

	return nil
}
