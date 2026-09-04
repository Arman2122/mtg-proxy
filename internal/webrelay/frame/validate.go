package frame

import (
	"encoding/binary"
	"fmt"
)

// Validation is split in two so a decoder can reject a hostile header before it
// allocates anything for the payload it declares. checkHeader needs only the
// eight header bytes; checkPayload looks at content the header cannot describe.
//
// The order inside checkHeader is fixed -- type, direction, stream shape,
// universal length bound, per-type length -- so that an input which breaks
// several rules always reports the same one.
//
// maxPayload is the deployment's own bound rather than MaxPayloadSize, because
// the universal length check is the one place a lowered frame cap has to bite:
// it runs before anything is allocated and before any per-type rule.

func checkHeader(t Type, streamID, payloadLen uint32, maxPayload int, dir Direction) error {
	spec := frameSpecs[t]
	if !spec.known() {
		return fmt.Errorf("%w: 0x%02x", ErrUnknownType, uint8(t))
	}

	if !spec.allows(dir) {
		return fmt.Errorf("%w: %s on the %s path", ErrWrongDirection, t, dir)
	}

	switch {
	case spec.session && streamID != 0:
		return fmt.Errorf("%w: %s on stream %d", ErrSessionFrameOnStream, t, streamID)
	case !spec.session && streamID == 0:
		return fmt.Errorf("%w: %s", ErrStreamFrameOnZero, t)
	}

	// Bound before buffering: this is the only length check that runs before a
	// decoder is allowed to allocate, so it has to be the strict one. Compared
	// as int64 because maxPayload is an int and payloadLen is attacker-chosen.
	if int64(payloadLen) > int64(maxPayload) {
		return fmt.Errorf("%w: %s declares %d bytes, cap %d",
			ErrPayloadTooLarge, t, payloadLen, maxPayload)
	}

	length := int(payloadLen)
	if length < spec.minPayload || length > spec.maxPayload {
		if t == TypeData {
			return ErrEmptyData
		}

		return fmt.Errorf("%w: %s declares %d bytes, wants %d..%d",
			ErrPayloadLength, t, length, spec.minPayload, spec.maxPayload)
	}

	return nil
}

// checkPayload covers the two rules that live in the payload bytes themselves.
// It assumes checkHeader already fixed the length.
func checkPayload(t Type, payload []byte) error {
	switch t {
	case TypeWindow:
		if binary.BigEndian.Uint32(payload) == 0 {
			return ErrZeroWindow
		}
	case TypeHello:
		if payload[0] != Version {
			return fmt.Errorf("%w: 0x%02x", ErrUnsupportedVersion, payload[0])
		}
	default:
	}

	return nil
}

// Validate reports whether the frame is legal to put on the wire in dir under
// the protocol ceilings. The encoder runs it on every frame, so a relay bug
// cannot emit a frame this package would refuse to decode.
func (f Frame) Validate(dir Direction) error {
	return f.validate(Limits{}, dir)
}

// validate is Validate under a deployment's own bounds. A batch encoder runs
// this one, because a frame that is legal at the ceiling but over the peer's
// lowered cap is exactly the frame that must not reach the wire.
func (f Frame) validate(lim Limits, dir Direction) error {
	if f.StreamID > MaxStreamID {
		return fmt.Errorf("%w: %d", ErrStreamIDRange, f.StreamID)
	}

	maxPayload := lim.maxPayload()
	if len(f.Payload) > maxPayload {
		return fmt.Errorf("%w: %s carries %d bytes, cap %d",
			ErrPayloadTooLarge, f.Type, len(f.Payload), maxPayload)
	}

	// Safe: the line above bounds the length at maxPayload, itself at most
	// MaxPayloadSize.
	if err := checkHeader(f.Type, f.StreamID, uint32(len(f.Payload)), maxPayload, dir); err != nil { //nolint:gosec // bounded above
		return err
	}

	return checkPayload(f.Type, f.Payload)
}
