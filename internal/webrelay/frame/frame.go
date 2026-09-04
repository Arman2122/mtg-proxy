// Package frame implements the shared-frame codec of Telegram's WEB proxy v1.
//
// The wire layout is a fixed 8-byte big-endian header followed by the payload:
//
//	type:u8 | stream_id:u24 | payload_length:u32 | payload[payload_length]
//
// Frames are self-delimiting and concatenate directly: a carrier message or an
// HTTP body is a bare sequence of whole frames with no envelope, count prefix
// or separator. There is no version field, no flags, no checksum and no
// trailer, so nothing about the framing is negotiated -- every bound in this
// file is compiled into the client too and must never be raised. Two of them
// may be lowered for one deployment; see Limits.
//
// Stream 0 carries session frames (PING, PONG, HELLO, WELCOME, BYE); every
// other frame (OPEN, DATA, CLOSE, WINDOW) needs a nonzero id.
//
// This package deliberately holds no state at all, which fixes where two
// classes of check live:
//
// It validates the *shape* of a stream id -- zero for session frames, nonzero
// for stream frames -- and nothing about whether that id is live, closed or
// never opened. Only the session layer can tell a frame for a live stream from
// a late frame for a stream whose tombstone it still holds.
//
// It likewise validates a frame's type, direction and payload but not its
// *context*. A HELLO or a PONG inside an ordinary data batch decodes cleanly
// here; rejecting a second HELLO, or a PONG for a PING that was never sent, is
// the session layer's job because only it knows the handshake is over.
package frame

import (
	"encoding/binary"
	"fmt"
)

// Type is the frame type byte.
type Type uint8

// The nine v1 frame types. Every other value of the type byte is unassigned
// and fatal on receipt; AUTH_CHAL and AUTH_RESP are reserved with no value.
const (
	TypeOpen    Type = 0x01
	TypeData    Type = 0x02
	TypeClose   Type = 0x03
	TypeWindow  Type = 0x04
	TypePing    Type = 0x05
	TypePong    Type = 0x06
	TypeHello   Type = 0x10
	TypeWelcome Type = 0x11
	TypeBye     Type = 0x1f
)

// Wire bounds. These are ceilings, not frozen values: WELCOME is empty, so a
// client learns none of them and a server that raises one breaks interop
// silently, but a server that lowers one stays interoperable because the client
// accepts anything stricter. MaxPayloadSize and MaxBatchBytes are the two a
// deployment may lower, through Limits.
const (
	// HeaderSize is the fixed header length in bytes.
	HeaderSize = 8

	// MaxPayloadSize is the largest payload any single frame may carry. It is
	// the ceiling and the default; Limits.MaxPayload lowers it.
	MaxPayloadSize = 1 << 20

	// MaxBatchBytes is the largest encoded batch one carrier message or body
	// may hold. It is the ceiling and the default; Limits.BatchBytes lowers it.
	// A message past it is dropped whole by the client rather than truncated,
	// which kills the session with nothing to see on this side.
	MaxBatchBytes = 2 << 20

	// MaxStreamID is the largest value the u24 stream id field can hold.
	MaxStreamID = 1<<24 - 1

	// MaxFramesPerBatch is the most frames one carrier body or message may
	// contain.
	MaxFramesPerBatch = 4096

	// MaxSessionCreateBody caps the session-creation request body, which is a
	// single HELLO frame and nothing else.
	MaxSessionCreateBody = 64

	// MaxRelayDataChunk bounds a DATA frame the relay generates from a backend
	// read. It is a producer-side rule, so the codec does not enforce it on
	// decode: a client may legitimately send DATA up to MaxPayloadSize.
	MaxRelayDataChunk = 64 << 10

	// WindowPayloadSize is the exact payload length of a WINDOW frame.
	WindowPayloadSize = 4

	// Version is the single byte a v1 HELLO carries.
	Version byte = 0x01
)

// Direction says which peer put the frame on the wire. The zero value is not a
// direction, so a caller that forgets to pass one is rejected rather than
// silently allowed everything.
type Direction uint8

// The two directions of the carrier.
const (
	ClientToRelay Direction = iota + 1
	RelayToClient
)

func (d Direction) String() string {
	switch d {
	case ClientToRelay:
		return "client-to-relay"
	case RelayToClient:
		return "relay-to-client"
	default:
		return fmt.Sprintf("invalid-direction(%d)", uint8(d))
	}
}

// frameSpec is the per-type rule set. A table rather than a switch, so adding a
// type cannot leave one of the four checks behind.
type frameSpec struct {
	name       string
	session    bool // true when the frame must travel on stream 0
	fromClient bool
	fromRelay  bool
	minPayload int
	maxPayload int
}

// known reports whether the type byte is assigned in v1.
func (s frameSpec) known() bool { return s.name != "" }

func (s frameSpec) allows(d Direction) bool {
	switch d {
	case ClientToRelay:
		return s.fromClient
	case RelayToClient:
		return s.fromRelay
	default:
		return false
	}
}

var frameSpecs = [256]frameSpec{
	TypeOpen:    {name: "OPEN", fromClient: true},
	TypeData:    {name: "DATA", fromClient: true, fromRelay: true, minPayload: 1, maxPayload: MaxPayloadSize},
	TypeClose:   {name: "CLOSE", fromClient: true, fromRelay: true},
	TypeWindow:  {name: "WINDOW", fromClient: true, fromRelay: true, minPayload: WindowPayloadSize, maxPayload: WindowPayloadSize},
	TypePing:    {name: "PING", session: true, fromRelay: true, maxPayload: MaxPayloadSize},
	TypePong:    {name: "PONG", session: true, fromClient: true, maxPayload: MaxPayloadSize},
	TypeHello:   {name: "HELLO", session: true, fromClient: true, minPayload: 1, maxPayload: 1},
	TypeWelcome: {name: "WELCOME", session: true, fromRelay: true},
	TypeBye:     {name: "BYE", session: true, fromRelay: true, maxPayload: MaxPayloadSize},
}

func (t Type) String() string {
	if s := frameSpecs[t]; s.known() {
		return s.name
	}

	return fmt.Sprintf("unknown(0x%02x)", uint8(t))
}

// Frame is one decoded shared frame. Payload is nil for the empty-payload
// types. Decoders always hand back a payload that the caller owns outright, so
// a carrier is free to reuse its read buffer immediately.
type Frame struct {
	Type     Type
	StreamID uint32
	Payload  []byte
}

// NewOpen asks the relay to dial its one configured backend for a new stream.
func NewOpen(streamID uint32) Frame {
	return Frame{Type: TypeOpen, StreamID: streamID}
}

// NewData carries opaque bytes for a stream. The frame takes ownership of
// payload; the caller must not mutate it afterwards.
func NewData(streamID uint32, payload []byte) Frame {
	return Frame{Type: TypeData, StreamID: streamID, Payload: payload}
}

// NewClose aborts a stream. It is not a half-close: whatever is still queued
// for that stream on either side is dropped.
func NewClose(streamID uint32) Frame {
	return Frame{Type: TypeClose, StreamID: streamID}
}

// NewWindow grants delta more bytes of receive credit on a stream.
func NewWindow(streamID, delta uint32) Frame {
	payload := make([]byte, WindowPayloadSize)
	binary.BigEndian.PutUint32(payload, delta)

	return Frame{Type: TypeWindow, StreamID: streamID, Payload: payload}
}

// NewPing builds a liveness probe. v1 never emits one; it exists so a decoder
// test and a future drain can share the same constructor.
func NewPing(token []byte) Frame {
	return Frame{Type: TypePing, Payload: token}
}

// NewPong echoes a PING token verbatim.
func NewPong(token []byte) Frame {
	return Frame{Type: TypePong, Payload: token}
}

// NewHello is the client's first frame and the whole session-creation body.
func NewHello() Frame {
	return Frame{Type: TypeHello, Payload: []byte{Version}}
}

// NewWelcome is the relay's answer to HELLO. It carries no parameters at all.
func NewWelcome() Frame {
	return Frame{Type: TypeWelcome}
}

// NewBye reserves a graceful carrier-level drain. v1 never emits one.
func NewBye(reason []byte) Frame {
	return Frame{Type: TypeBye, Payload: reason}
}

// WindowDelta returns the credit a WINDOW frame grants. The second result is
// false for any other frame type.
func (f Frame) WindowDelta() (uint32, bool) {
	if f.Type != TypeWindow || len(f.Payload) != WindowPayloadSize {
		return 0, false
	}

	return binary.BigEndian.Uint32(f.Payload), true
}

// EncodedLen is the number of bytes this frame occupies on the wire.
func (f Frame) EncodedLen() int {
	return HeaderSize + len(f.Payload)
}

func (f Frame) String() string {
	return fmt.Sprintf("%s(stream=%d, payload=%d)", f.Type, f.StreamID, len(f.Payload))
}
