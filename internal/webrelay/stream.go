package webrelay

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/Arman2122/mtg-proxy/internal/webrelay/frame"
)

// InitialWindow is the receive credit each direction of every stream starts
// with. It is implicit: no frame carries it, WELCOME is empty, there is no OPEN
// acknowledgement, and the client has the same number compiled in. A relay that
// starts from a different figure is not misconfigured, it is silently broken --
// which is why this is a constant and not an option.
//
// The value is deliberately twice the carrier batch, so one stream can keep
// sending while returned credit is still crossing the opposite direction.
const InitialWindow uint32 = 4 << 20

var (
	// ErrCreditExhausted means the peer sent DATA past the credit granted to
	// it. The specification makes this fatal rather than something to absorb: a
	// peer that miscounts credit will miscount it again, and from that point
	// the two ends disagree about how much is in flight.
	ErrCreditExhausted = errors.New("DATA beyond the granted receive window")

	// ErrWindowOverflow means granted credit would pass the 32-bit maximum.
	// Saturating instead would leave the two ends counting different totals with
	// nothing to notice it, so this is fatal too.
	ErrWindowOverflow = errors.New("WINDOW grant overflows the receive window")
)

// stream is one logical MTProto connection: a client-allocated id and the
// backend socket opened for it.
//
// The two directions are asymmetric in when credit is returned, and that
// asymmetry is the entire backpressure design:
//
//   - Uplink. Client DATA spends the credit this side granted. The WINDOW that
//     replaces it goes out only after the write to the backend socket has
//     returned -- not on receipt, not on enqueue. A backend that has stopped
//     draining therefore stops the credit, which stops the client, so the app
//     feels a stalled DC instead of this process growing a queue.
//   - Downlink. Backend reads spend the credit the client granted. At zero the
//     relay stops reading the backend socket, so the kernel's own receive
//     window closes and the backpressure reaches Telegram's side.
//
// Neither direction sends a probe, a zero-length DATA or a stall notice at zero
// credit. There is no window-update timer and no deadlock breaker: correctness
// rests on the peer eventually draining and granting, which is what the client
// implements.
//
// A stream runs two goroutines. The uplink one dials the backend and then
// drains the queue the carrier read loop fills; the downlink one reads the
// backend. Dialing there rather than in the read loop is what keeps a slow or
// dead backend from stalling every other stream on the carrier -- the read loop
// never blocks on a stream, because per-stream credit already bounds what it
// can be handed.
type stream struct {
	id      uint32
	session *session

	// conn is written once by the uplink goroutine before ready is closed, and
	// read by the downlink goroutine only after it. No lock is needed for that
	// handover; the happens-before comes from the channel.
	conn  net.Conn
	ready chan struct{}

	upMu     sync.Mutex
	upCond   *sync.Cond
	up       [][]byte
	upClosed bool

	sendMu     sync.Mutex
	sendCond   *sync.Cond
	sendWindow uint32

	// recvWindow is the credit granted to the client. The carrier read loop
	// subtracts from it and the uplink goroutine adds back to it, so it is the
	// one counter here touched by two goroutines.
	recvMu     sync.Mutex
	recvWindow uint32

	dead      bool
	closeOnce sync.Once
}

func newStream(id uint32, session *session) *stream {
	s := &stream{
		id:         id,
		session:    session,
		ready:      make(chan struct{}),
		sendWindow: InitialWindow,
		recvWindow: InitialWindow,
	}
	s.upCond = sync.NewCond(&s.upMu)
	s.sendCond = sync.NewCond(&s.sendMu)

	return s
}

// start dials the backend and begins both pumps. A dial that fails ends the
// stream with a CLOSE for that id alone -- the session and every other stream
// carry on, which is what the specification asks for and what makes a backend
// hiccup survivable.
func (s *stream) start(ctx context.Context, dialTimeout time.Duration) {
	go func() {
		defer s.session.streamEnded(s)

		dialCtx, cancel := context.WithTimeout(ctx, dialTimeout)
		conn, err := s.session.backend.Dial(dialCtx, s.session.clientAddr)

		cancel()

		if err != nil {
			s.session.logStreamError(s.id, err)

			// The only CLOSE this side generates that does not come from the
			// downlink pump, because there is no pump: nothing was ever read
			// from this backend, so nothing can be ordered behind.
			s.session.closeStream(s.id)

			return
		}

		s.conn = conn
		close(s.ready)

		defer conn.Close() //nolint: errcheck // an aborted stream has nothing to report

		go s.pump()

		s.drainUplink()
	}()
}

// queue hands the carrier read loop's payload to the uplink goroutine. It never
// blocks: the client's receive credit already bounds what can be queued here to
// one window, because no WINDOW is returned until the bytes have been written.
func (s *stream) queue(payload []byte) {
	s.upMu.Lock()
	defer s.upMu.Unlock()

	if s.upClosed {
		return
	}

	s.up = append(s.up, payload)
	s.upCond.Signal()
}

func (s *stream) takeUplink() []byte {
	s.upMu.Lock()
	defer s.upMu.Unlock()

	for len(s.up) == 0 && !s.upClosed {
		s.upCond.Wait()
	}

	if len(s.up) == 0 {
		return nil
	}

	payload := s.up[0]
	s.up = s.up[1:]

	return payload
}

func (s *stream) drainUplink() {
	for {
		payload := s.takeUplink()
		if payload == nil {
			return
		}

		if _, err := s.conn.Write(payload); err != nil {
			if !errors.Is(err, net.ErrClosed) {
				s.session.logStreamError(s.id, err)
			}

			return
		}

		// Only now. The whole point of the ordering is that credit follows the
		// write, so a backend that is not draining cannot be hidden from the
		// client by a queue on this side. The byte count follows the same rule:
		// a byte still sitting in this queue has not gone anywhere.
		s.session.counters.addBytesUp(len(payload))

		size := uint32(len(payload)) //nolint:gosec // a frame payload is bounded at 1 MiB

		s.recvMu.Lock()
		s.recvWindow += size
		s.recvMu.Unlock()

		if err := s.session.out.PushControl(frame.NewWindow(s.id, size)); err != nil {
			return
		}
	}
}

// consume charges client DATA against the credit this side granted.
func (s *stream) consume(n int) error {
	size := uint32(n) //nolint:gosec // a frame payload is bounded at 1 MiB

	s.recvMu.Lock()
	defer s.recvMu.Unlock()

	if size > s.recvWindow {
		return fmt.Errorf("%w: stream %d wanted %d, %d left", ErrCreditExhausted, s.id, size, s.recvWindow)
	}

	s.recvWindow -= size

	return nil
}

// credit reads the current uplink allowance, for the batch simulation.
func (s *stream) credit() uint32 {
	s.recvMu.Lock()
	defer s.recvMu.Unlock()

	return s.recvWindow
}

// grant adds client-granted credit for the downlink direction.
func (s *stream) grant(delta uint32) error {
	s.sendMu.Lock()
	defer s.sendMu.Unlock()

	if s.sendWindow > ^uint32(0)-delta {
		return fmt.Errorf("%w: stream %d", ErrWindowOverflow, s.id)
	}

	s.sendWindow += delta
	s.sendCond.Broadcast()

	return nil
}

// spend takes up to want bytes of downlink credit, blocking while there is
// none. It returns 0 once the stream is dead.
func (s *stream) spend(want int) int {
	s.sendMu.Lock()
	defer s.sendMu.Unlock()

	for s.sendWindow == 0 && !s.dead {
		s.sendCond.Wait()
	}

	if s.dead {
		return 0
	}

	if uint32(want) > s.sendWindow { //nolint:gosec // want is a positive read size
		want = int(s.sendWindow)
	}

	s.sendWindow -= uint32(want) //nolint:gosec // bounded immediately above

	return want
}

func (s *stream) refund(n int) {
	if n <= 0 {
		return
	}

	_ = s.grant(uint32(n)) //nolint:gosec // a refund is never larger than what was taken
}

// pump reads the backend and turns it into downlink DATA, one credit-bounded,
// chunk-bounded frame at a time.
//
// Its exit tears the whole stream down, which is not tidiness: a backend that
// reached EOF has ended the stream in both directions -- CLOSE is an abort, not
// a half-close -- and without this the uplink goroutine would sit in its queue
// forever, so the CLOSE that tells the client would never be queued at all.
//
// The CLOSE is queued here, on this goroutine, rather than wherever the stream
// happens to end. PushData blocks when the session's pending budget is full, so
// at the moment a stream dies this goroutine may be holding the last DATA of a
// response; a CLOSE queued from anywhere else draws on the control reserve,
// does not block, and would overtake it. Queueing it after the loop makes the
// ordering a property of the code path instead of the scheduler.
func (s *stream) pump() {
	// Counted here rather than at OPEN: a stream that never got a backend is
	// not one this relay is carrying, and pairing the increment with the
	// deferred decrement in the same function is what stops the gauge drifting.
	s.session.counters.onStreamOpened()

	defer func() {
		// close() first, so the uplink goroutine stops before the client is
		// told, then the CLOSE itself.
		s.close()
		s.session.closeStream(s.id)
		s.session.counters.onStreamClosed()
	}()

	chunk := s.session.limits.EffectivePayload()

	// Relay-generated DATA is capped at 64 KiB unconditionally. The published
	// documents disagree about whether coalescing above it is allowed, and both
	// client IPC descriptions size their buffers assuming it is not -- so the
	// stricter reading is the only safe one, and it costs nothing.
	if chunk > frame.MaxRelayDataChunk {
		chunk = frame.MaxRelayDataChunk
	}

	// Each read takes a buffer from the pools and the DATA frame carries it to
	// the write loop, which releases it once written: no copy, and a stream
	// waiting on an idle backend holds a small buffer, not a large one.
	large := false

	for {
		buf := getReadBuffer(large)

		allowed := s.spend(min(len(buf), chunk))
		if allowed == 0 {
			releaseReadBuffer(buf)

			return
		}

		n, err := s.conn.Read(buf[:allowed])
		large = nextReadLarge(large, n)

		if n > 0 {
			// Refund what the read did not use: credit is spent on bytes that
			// exist, not on the size of the buffer offered.
			s.refund(allowed - n)

			if pushErr := s.session.out.PushData(frame.NewData(s.id, buf[:n])); pushErr != nil {
				return
			}

			s.session.counters.addBytesDown(n)
		} else {
			s.refund(allowed)
			releaseReadBuffer(buf)
		}

		if err != nil {
			// EOF and error are the same outcome, because CLOSE is an abort and
			// carries no reason. The CLOSE is queued behind everything this
			// stream already pushed, so the tail of a response reaches the
			// client before it is told the stream ended.
			if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
				s.session.logStreamError(s.id, err)
			}

			return
		}
	}
}

// close tears the stream down. It is an abort in both directions -- an MTProto
// socket is never half-closed -- and it is idempotent, because a stream can end
// from the client, from the backend and from session teardown at once.
func (s *stream) close() {
	s.closeOnce.Do(func() {
		s.sendMu.Lock()
		s.dead = true
		s.sendCond.Broadcast()
		s.sendMu.Unlock()

		s.upMu.Lock()
		s.upClosed = true
		s.up = nil
		s.upCond.Broadcast()
		s.upMu.Unlock()

		select {
		case <-s.ready:
			_ = s.conn.Close()
		default:
			// The dial has not finished. start's own defer closes whatever it
			// ends up with, and the context it dials under is already cancelled
			// by session teardown.
		}
	})
}
