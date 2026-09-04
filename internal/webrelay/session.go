package webrelay

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/Arman2122/mtg-proxy/internal/webrelay/frame"
	"github.com/Arman2122/mtg-proxy/internal/webrelay/ws"
	"github.com/Arman2122/mtg-proxy/mtglib"
)

// Session-level bounds and errors.
const (
	// MaxTombstones is how many recently closed stream ids a session remembers.
	// They exist for one reason: a CLOSE and the peer's last DATA cross on the
	// wire constantly, and without tombstones that ordinary race would look
	// like a frame for a stream that never existed.
	MaxTombstones = 4096

	// DefaultMaxStreams bounds the logical connections one session may hold
	// open. A WEB client uses several times the connections of a direct one, so
	// this is generous; it is a ceiling against a client gone wrong, not a
	// quota.
	DefaultMaxStreams = 512

	// DefaultDialTimeout bounds one backend dial.
	DefaultDialTimeout = 5 * time.Second
)

var (
	// ErrSecondHello means a HELLO arrived on the carrier. HELLO is the session
	// creation body and appears nowhere else; a second one means the peer
	// believes it is starting a session that already exists.
	ErrSecondHello = errors.New("HELLO on an established carrier")

	// ErrUnknownStream means a frame named a stream that was never opened and
	// is not in the tombstone set.
	ErrUnknownStream = errors.New("frame for a stream that was never opened")

	// ErrStreamReused means an OPEN named an id that is live or recently
	// closed. Ids are never reused within a session.
	ErrStreamReused = errors.New("OPEN for a stream id already used in this session")
)

// Backend opens the loopback connection one OPEN asks for. It is an interface
// so the session can be tested without a listener, and so the PROXY-protocol
// decision lives in one place rather than in the session's flow control.
type Backend interface {
	// Dial connects to the configured backend on behalf of client, which is the
	// browser's address as this process learned it.
	Dial(ctx context.Context, client net.Addr) (net.Conn, error)
}

// SessionOptions configures one carrier session.
type SessionOptions struct {
	Backend     Backend
	Limits      frame.Limits
	Global      *budget
	Logger      mtglib.Logger
	ClientAddr  net.Addr
	MaxStreams  int
	DialTimeout time.Duration

	// PendingBytes and PendingItems bound this one session's downlink queue.
	// Zero means the defaults. They are separate from the global budget because
	// the two answer different questions: the global one stops the process
	// growing without limit, this one stops a single session doing it.
	PendingBytes int64
	PendingItems int64
}

func (o SessionOptions) withDefaults() SessionOptions {
	if o.MaxStreams <= 0 {
		o.MaxStreams = DefaultMaxStreams
	}

	if o.PendingBytes <= 0 {
		o.PendingBytes = DefaultPendingBytes
	}

	if o.PendingItems <= 0 {
		o.PendingItems = DefaultPendingItems
	}

	if o.DialTimeout <= 0 {
		o.DialTimeout = DefaultDialTimeout
	}

	if o.Global == nil {
		o.Global = newBudget(DefaultGlobalPendingBytes, DefaultGlobalPendingItems)
	}

	return o
}

// carrier is the transport a session runs over. It is an interface for one
// reason that pays for itself immediately: the flow-control rules below are the
// hardest part of this package to get right and the easiest to get wrong
// silently, and a test that has to negotiate a WebSocket first cannot drive the
// pathological orderings that break them.
type carrier interface {
	Read() ([]byte, error)
	Write(payload []byte) error
	Close(code uint16, reason string) error
}

// session is one WEB carrier session: a carrier, the streams multiplexed over
// it, and the one ordered queue everything leaves through.
type session struct {
	conn    carrier
	out     *outbox
	backend Backend
	limits  frame.Limits
	log     mtglib.Logger

	clientAddr  net.Addr
	maxStreams  int
	dialTimeout time.Duration

	ctx    context.Context
	cancel context.CancelFunc

	mu         sync.Mutex
	streams    map[uint32]*stream
	tombstones *tombstones

	wg sync.WaitGroup
}

func newSession(conn carrier, opts SessionOptions) *session {
	opts = opts.withDefaults()

	return &session{
		conn:        conn,
		out:         newOutbox(newBudget(opts.PendingBytes, opts.PendingItems), opts.Global, opts.Limits),
		backend:     opts.Backend,
		limits:      opts.Limits,
		log:         opts.Logger,
		clientAddr:  opts.ClientAddr,
		maxStreams:  opts.MaxStreams,
		dialTimeout: opts.DialTimeout,
		streams:     make(map[uint32]*stream),
		tombstones:  newTombstones(MaxTombstones),
	}
}

// Serve runs the session until the carrier ends or the peer breaks the
// protocol. It always returns having closed the WebSocket and every stream.
func (s *session) Serve(ctx context.Context) error {
	s.ctx, s.cancel = context.WithCancel(ctx)
	defer s.cancel()

	s.wg.Add(1)

	go func() {
		defer s.wg.Done()
		s.writeLoop()
	}()

	err := s.readLoop()
	s.shutdown(err)
	s.wg.Wait()

	return err
}

func (s *session) readLoop() error {
	for {
		message, err := s.conn.Read()
		if err != nil {
			return err
		}

		// A wakeup with nothing queued is plausible and harmless. The
		// specification says a body carries "one or more" frames without saying
		// what an empty one is, and killing a session over it would trade a real
		// outage for a hypothetical strictness.
		if len(message) == 0 {
			continue
		}

		frames, err := s.limits.DecodeBatch(message, frame.ClientToRelay)
		if err != nil {
			return err
		}

		if err := s.apply(frames); err != nil {
			return err
		}
	}
}

func (s *session) writeLoop() {
	for {
		batch := s.out.Take()
		if batch == nil {
			return
		}

		payload, err := s.limits.EncodeBatch(nil, batch, frame.RelayToClient)
		if err != nil {
			// The relay built a batch its own client would reject. That is a
			// fault on this side, not the peer's.
			s.logError("cannot encode a downlink batch", err)
			s.cancel()

			return
		}

		if err := s.conn.Write(payload); err != nil {
			s.cancel()

			return
		}
	}
}

// action is one planned effect of a frame. The kinds exist so that planning and
// applying are two passes over the same list rather than one pass that has to
// undo itself.
type actionKind uint8

const (
	actIgnore actionKind = iota
	actOpen
	actRefuse
	actData
	actWindow
	actClose
)

type action struct {
	kind   actionKind
	frame  frame.Frame
	stream *stream
}

// apply commits a whole batch or none of it.
//
// The specification requires validation to complete before any frame is
// applied, and that rule is not decoration: a batch is the unit the peer
// retries, so a half-applied one leaves the two ends disagreeing about what
// happened with no way to say so.
//
// The half that is easy to get wrong is that a batch is allowed to be
// self-referential. The client may send DATA immediately after OPEN, in the
// same message, and OPEN has no acknowledgement -- so a validator that asks
// "is this stream live?" against current state alone rejects the very first
// thing a real client does. Planning therefore simulates the batch: an OPEN
// earlier in the list makes its id live for the frames that follow, a CLOSE
// makes it a tombstone, and a refused OPEN makes the DATA riding behind it
// ignorable rather than fatal.
func (s *session) apply(frames []frame.Frame) error {
	plan, err := s.plan(frames)
	if err != nil {
		return err
	}

	for _, act := range plan {
		if err := s.perform(act); err != nil {
			return err
		}
	}

	return nil
}

func (s *session) plan(frames []frame.Frame) ([]action, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var (
		plan     = make([]action, 0, len(frames))
		opened   = make(map[uint32]*stream)
		refused  = make(map[uint32]bool)
		gone     = make(map[uint32]bool)
		credit   = make(map[uint32]uint32)
		newCount int
	)

	for i, f := range frames {
		switch f.Type {
		case frame.TypeHello:
			return nil, fmt.Errorf("frame %d: %w", i, ErrSecondHello)

		case frame.TypePong:
			// v1 never emits PING, so a PONG answers nothing. Accepting and
			// discarding it costs nothing and keeps a client that probes
			// liveness on its own from being killed for it.
			plan = append(plan, action{kind: actIgnore})

		case frame.TypeOpen:
			if _, live := s.streams[f.StreamID]; live || opened[f.StreamID] != nil ||
				refused[f.StreamID] || s.tombstones.has(f.StreamID) {
				return nil, fmt.Errorf("frame %d: %w: %d", i, ErrStreamReused, f.StreamID)
			}

			// A capacity refusal is a stream-level failure, never a session
			// one: the client gets CLOSE for that id and keeps everything else.
			if len(s.streams)+newCount >= s.maxStreams {
				refused[f.StreamID] = true

				plan = append(plan, action{kind: actRefuse, frame: f})

				continue
			}

			newCount++

			st := newStream(f.StreamID, s)
			opened[f.StreamID] = st
			credit[f.StreamID] = InitialWindow

			plan = append(plan, action{kind: actOpen, frame: f, stream: st})

		case frame.TypeData, frame.TypeWindow, frame.TypeClose:
			act, err := s.planStreamFrame(i, f, opened, refused, gone, credit)
			if err != nil {
				return nil, err
			}

			plan = append(plan, act)

		default:
			// Unreachable: the codec rejects every other type and both wrong
			// directions before a frame reaches here.
			return nil, fmt.Errorf("frame %d: %w: %s", i, frame.ErrUnknownType, f.Type)
		}
	}

	return plan, nil
}

func (s *session) planStreamFrame(
	index int,
	f frame.Frame,
	opened map[uint32]*stream,
	refused, gone map[uint32]bool,
	credit map[uint32]uint32,
) (action, error) {
	// A frame for an id this batch already closed, for one a refused OPEN never
	// created, or for one whose tombstone is still held, is the close race the
	// tombstones exist for. Ignored, not fatal.
	if gone[f.StreamID] || refused[f.StreamID] || s.tombstones.has(f.StreamID) {
		return action{kind: actIgnore}, nil
	}

	st := opened[f.StreamID]
	if st == nil {
		st = s.streams[f.StreamID]
	}

	if st == nil {
		return action{}, fmt.Errorf("frame %d: %w: %d", index, ErrUnknownStream, f.StreamID)
	}

	switch f.Type {
	case frame.TypeData:
		left, seen := credit[f.StreamID]
		if !seen {
			left = st.credit()
		}

		// Simulated against a snapshot that never counts the credit an
		// in-flight backend write is about to return, so the simulation is
		// conservative: anything it admits, the apply pass can charge.
		size := uint32(len(f.Payload)) //nolint:gosec // bounded at 1 MiB by the codec
		if size > left {
			return action{}, fmt.Errorf("frame %d: %w: stream %d wanted %d, %d left",
				index, ErrCreditExhausted, f.StreamID, size, left)
		}

		credit[f.StreamID] = left - size

		return action{kind: actData, frame: f, stream: st}, nil

	case frame.TypeWindow:
		return action{kind: actWindow, frame: f, stream: st}, nil

	default: // frame.TypeClose
		gone[f.StreamID] = true

		return action{kind: actClose, frame: f, stream: st}, nil
	}
}

func (s *session) perform(act action) error {
	switch act.kind {
	case actIgnore:
		return nil

	case actOpen:
		s.mu.Lock()
		s.streams[act.frame.StreamID] = act.stream
		s.mu.Unlock()

		act.stream.start(s.ctx, s.dialTimeout)

		return nil

	case actRefuse:
		s.retire(act.frame.StreamID)

		return s.out.PushControl(frame.NewClose(act.frame.StreamID))

	case actData:
		if err := act.stream.consume(len(act.frame.Payload)); err != nil {
			return err
		}

		act.stream.queue(act.frame.Payload)

		return nil

	case actWindow:
		delta, ok := act.frame.WindowDelta()
		if !ok {
			return fmt.Errorf("%w: stream %d", frame.ErrZeroWindow, act.frame.StreamID)
		}

		return act.stream.grant(delta)

	default: // actClose
		// The client aborted the stream, so it is not told about it again. A
		// CLOSE it did not ask for would be tolerated by its own tombstones,
		// but the quiet direction is the one that cannot desynchronise.
		s.retire(act.frame.StreamID)
		act.stream.close()

		return nil
	}
}

// streamEnded is called when a stream's uplink goroutine finishes. It only
// tears the stream down; it deliberately does not queue the CLOSE.
//
// The CLOSE belongs to the downlink goroutine, and the reason is an ordering
// one. This runs on the uplink goroutine, and PushControl draws on the reserve,
// so it never blocks -- while the downlink pump's PushData does block once the
// session's pending budget is full. A CLOSE queued from here while the pump is
// holding the last DATA of a response would be delivered ahead of it, and the
// client tombstones the id the moment it sees a CLOSE: the tail would be
// dropped. Ordering that depends on which goroutine happened to be scheduled is
// not ordering, so a stream that was opened is closed through closeStream, and
// the pump is what calls it -- or start, when the dial failed and there never
// was a pump. An OPEN refused before either exists is answered in perform.
func (s *session) streamEnded(st *stream) {
	st.close()
}

// closeStream retires a stream and tells the client, exactly once. It is called
// from the goroutine that pushed that stream's DATA, so the CLOSE lands behind
// every byte the backend produced: CLOSE is an abort, and one that overtook the
// last DATA would truncate a Telegram response.
//
// A stream the client closed itself is already retired, and is not told again.
// The quiet direction is the one that cannot desynchronise.
func (s *session) closeStream(id uint32) {
	s.mu.Lock()
	_, tracked := s.streams[id]

	if tracked {
		delete(s.streams, id)
		s.tombstones.add(id)
	}

	s.mu.Unlock()

	if !tracked {
		return
	}

	_ = s.out.PushControl(frame.NewClose(id))
}

// retire drops a stream from the live set and remembers its id.
func (s *session) retire(id uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.streams, id)
	s.tombstones.add(id)
}

func (s *session) shutdown(cause error) {
	s.cancel()
	s.out.Close()

	s.mu.Lock()
	streams := make([]*stream, 0, len(s.streams))

	for _, st := range s.streams {
		streams = append(streams, st)
	}

	s.streams = make(map[uint32]*stream)
	s.mu.Unlock()

	for _, st := range streams {
		st.close()
	}

	_ = s.conn.Close(closeCodeFor(cause), "")
}

// closeCodeFor maps a session outcome to a WebSocket close code. The published
// specification does not say which code a protocol violation carries, so these
// are this implementation's choice from RFC 6455's own registry.
func closeCodeFor(err error) uint16 {
	switch {
	case err == nil || errors.Is(err, ws.ErrClosed):
		return ws.CloseNormal
	case errors.Is(err, ws.ErrMessageTooBig) || errors.Is(err, frame.ErrBatchTooLarge):
		return ws.CloseTooBig
	default:
		return ws.CloseProtocolError
	}
}

func (s *session) logStreamError(id uint32, err error) {
	if s.log == nil {
		return
	}

	s.log.BindInt("stream", int(id)).DebugError("web relay stream ended", err)
}

func (s *session) logError(message string, err error) {
	if s.log == nil {
		return
	}

	s.log.WarningError(message, err)
}

// tombstones remembers recently closed stream ids so a late frame from a close
// race can be told apart from a frame for an id that never existed. It is a
// fixed-size ring: the oldest id is forgotten when the newest arrives, which is
// the trade the specification names -- bounded memory in exchange for a window
// beyond which the two cases are indistinguishable again.
type tombstones struct {
	ring  []uint32
	index int
	set   map[uint32]struct{}
}

func newTombstones(size int) *tombstones {
	return &tombstones{ring: make([]uint32, 0, size), set: make(map[uint32]struct{}, size)}
}

func (t *tombstones) add(id uint32) {
	if _, ok := t.set[id]; ok {
		return
	}

	if len(t.ring) < cap(t.ring) {
		t.ring = append(t.ring, id)
	} else {
		delete(t.set, t.ring[t.index])
		t.ring[t.index] = id
		t.index = (t.index + 1) % len(t.ring)
	}

	t.set[id] = struct{}{}
}

func (t *tombstones) has(id uint32) bool {
	_, ok := t.set[id]

	return ok
}
