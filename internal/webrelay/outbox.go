package webrelay

import (
	"errors"
	"sync"

	"github.com/Arman2122/mtg-proxy/internal/webrelay/frame"
)

// Pending accounting -- memory admission control, separate from and additional
// to the per-stream window.
//
// The unit of charge is the encoded size plus a flat allowance for every queued
// item, because the byte figure alone is a poor proxy for what a queue costs:
// a WINDOW frame is twelve bytes on the wire and a whole allocation, a slice
// header and a scheduling decision in this process. The item budget is what
// stops a flood of tiny frames exhausting memory while staying far below the
// byte budget.
const (
	// QueueItemCharge is the flat per-item allowance added to every queued
	// frame's encoded size.
	QueueItemCharge = 256

	// DefaultPendingBytes and DefaultPendingItems bound one session's downlink
	// queue.
	DefaultPendingBytes int64 = 32 << 20
	DefaultPendingItems int64 = 16384

	// DefaultGlobalPendingBytes and DefaultGlobalPendingItems bound every
	// session in the process together.
	DefaultGlobalPendingBytes int64 = 512 << 20
	DefaultGlobalPendingItems int64 = 262144

	// ControlReserveItems is the item headroom held back from bulk DATA so that
	// WINDOW, CLOSE and session frames can always be queued. Without it a
	// saturated downlink would block the very frames that unblock it: the relay
	// would stop being able to grant credit precisely when the peer is waiting
	// for credit.
	ControlReserveItems int64 = 256

	// ControlReserveBytes is the same reserve counted in bytes. Control frames
	// are at most twelve bytes plus the item charge, so this is generous.
	ControlReserveBytes int64 = ControlReserveItems * (QueueItemCharge + 16)
)

// ErrOutboxClosed means the session is finished and nothing more will be sent.
var ErrOutboxClosed = errors.New("session outbox is closed")

// budget is a pair of counters with a ceiling, and a condition to wait on. Both
// dimensions are authoritative: whichever binds first blocks.
type budget struct {
	mu    sync.Mutex
	cond  *sync.Cond
	bytes int64
	items int64

	maxBytes int64
	maxItems int64
	closed   bool
}

func newBudget(maxBytes, maxItems int64) *budget {
	b := &budget{maxBytes: maxBytes, maxItems: maxItems}
	b.cond = sync.NewCond(&b.mu)

	return b
}

// acquire waits until cost fits under the ceilings, then charges it. reserve is
// the headroom withheld from this caller, so a bulk writer can be blocked while
// a control writer passing reserve=0 still fits.
func (b *budget) acquire(cost, reserveBytes, reserveItems int64) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	for {
		if b.closed {
			return ErrOutboxClosed
		}

		if b.bytes+cost <= b.maxBytes-reserveBytes && b.items+1 <= b.maxItems-reserveItems {
			b.bytes += cost
			b.items++

			return nil
		}

		b.cond.Wait()
	}
}

func (b *budget) release(cost, items int64) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.bytes -= cost
	b.items -= items

	b.cond.Broadcast()
}

func (b *budget) close() {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.closed = true
	b.cond.Broadcast()
}

// outbox is the one ordered queue of frames leaving a session. Everything the
// relay sends passes through it, which is what makes ordering a property of the
// type rather than of the callers: a CLOSE queued after a stream's last DATA is
// delivered after it, so a backend that reached EOF does not lose its tail.
//
// It is deliberately not a channel. A channel bounds items and not bytes, gives
// no way to hold a reserve for one class of sender, and cannot express "take
// everything queued right now, up to a batch".
type outbox struct {
	mu     sync.Mutex
	cond   *sync.Cond
	frames []frame.Frame
	cost   int64
	closed bool

	session *budget
	global  *budget
	limits  frame.Limits
}

func newOutbox(session, global *budget, limits frame.Limits) *outbox {
	o := &outbox{session: session, global: global, limits: limits}
	o.cond = sync.NewCond(&o.mu)

	return o
}

// PushData queues a downlink DATA frame, blocking while the queue is full. The
// block is the point: it stops the stream pump, which stops it reading the
// backend socket, which is how a client that has stopped draining ends up
// applying TCP backpressure to Telegram rather than to this process's heap.
func (o *outbox) PushData(f frame.Frame) error {
	return o.push(f, ControlReserveBytes, ControlReserveItems)
}

// PushControl queues a WINDOW, CLOSE or session frame. It draws on the reserve,
// so it cannot be starved by bulk DATA.
func (o *outbox) PushControl(f frame.Frame) error {
	return o.push(f, 0, 0)
}

func (o *outbox) push(f frame.Frame, reserveBytes, reserveItems int64) error {
	cost := int64(f.EncodedLen()) + QueueItemCharge

	// The global budget is acquired first and always in this order, so two
	// sessions cannot hold each other's half.
	if err := o.global.acquire(cost, reserveBytes, reserveItems); err != nil {
		return err
	}

	if err := o.session.acquire(cost, reserveBytes, reserveItems); err != nil {
		o.global.release(cost, 1)

		return err
	}

	o.mu.Lock()

	if o.closed {
		o.mu.Unlock()
		o.session.release(cost, 1)
		o.global.release(cost, 1)

		return ErrOutboxClosed
	}

	o.frames = append(o.frames, f)
	o.cost += cost
	o.cond.Signal()
	o.mu.Unlock()

	return nil
}

// Take blocks until at least one frame is queued and returns as many as fit one
// carrier message. It returns nil once the outbox is closed and drained.
func (o *outbox) Take() []frame.Frame {
	o.mu.Lock()

	for len(o.frames) == 0 && !o.closed {
		o.cond.Wait()
	}

	if len(o.frames) == 0 {
		o.mu.Unlock()

		return nil
	}

	// A batch is bounded by both the frame cap and the byte budget, and the
	// byte one is the one a frame count does not imply: 4096 legal 64 KiB DATA
	// frames are 256 MiB together, and the client drops an oversized message
	// whole rather than truncating it.
	var (
		taken  int
		bytes  int64
		budget = o.limits.EffectiveBatchBytes()
	)

	for taken < len(o.frames) && taken < frame.MaxFramesPerBatch {
		size := int64(o.frames[taken].EncodedLen())
		if bytes+size > budget {
			break
		}

		bytes += size
		taken++
	}

	batch := make([]frame.Frame, taken)
	copy(batch, o.frames[:taken])

	var released int64
	for _, f := range batch {
		released += int64(f.EncodedLen()) + QueueItemCharge
	}

	o.frames = append(o.frames[:0], o.frames[taken:]...)
	o.cost -= released
	o.mu.Unlock()

	// Released after the frames leave the queue and before they are written.
	// The charge exists to bound what this process is holding, and once the
	// batch is in the caller's hands the queue is no longer holding it.
	o.session.release(released, int64(taken))
	o.global.release(released, int64(taken))

	return batch
}

// Close wakes every blocked writer and stops the queue accepting anything else.
// Whatever is still queued is discarded: the carrier that would have carried it
// is gone.
func (o *outbox) Close() {
	o.mu.Lock()

	if o.closed {
		o.mu.Unlock()

		return
	}

	o.closed = true
	discarded := o.cost
	items := int64(len(o.frames))
	o.frames = nil
	o.cost = 0
	o.cond.Broadcast()
	o.mu.Unlock()

	o.session.release(discarded, items)
	o.global.release(discarded, items)
	o.session.close()
}
