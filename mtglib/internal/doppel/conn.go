package doppel

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"time"

	"github.com/Arman2122/mtg-proxy/essentials"
	"github.com/Arman2122/mtg-proxy/mtglib/internal/tls"
)

// DrainTimeout bounds how long CloseWrite keeps delivering what is buffered to
// a client that has stopped reading. What is left after it is dropped.
const DrainTimeout = 5 * time.Second

// MaxBuffered bounds the queue between the relay and the paced writer. Write
// waits while this much is queued, so a client that reads slowly slows the
// relay's reads from Telegram instead of growing the heap, and what the speed
// limit charges is never far ahead of what is sent. The buffer holding the
// queue grows by doubling, so its capacity peaks near twice this.
const MaxBuffered = 256 << 10

// keepQueueMax is the most queue capacity a connection keeps once it has gone
// idle. A queue that grew to the bound for a download is let go of after it,
// rather than held -- at twice its size, as buffers grow -- for the
// connection's life. Idle is TLSRecordSizeResetAfter without a Write, the
// threshold DRS and burst shaping already use: the queue empties many times a
// second inside a transfer, and letting go of it there would regrow it for
// every piece of the answer.
const keepQueueMax = 64 << 10

var (
	errDrainTimeout = errors.New("the client did not take the rest of the response in time")
	errWriteClosed  = errors.New("write after CloseWrite")
)

var doppelBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, tls.MaxRecordSize)
		return &b
	},
}

// burstBufPool holds the batches burst shaping builds: records, headers and
// all, up to BurstWriteMax.
var burstBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, BurstWriteMax)
		return &b
	},
}

type Conn struct {
	essentials.Conn

	p *connPayload
}

type connPayload struct {
	ctx         context.Context
	ctxCancel   context.CancelCauseFunc
	stats       Stats
	shaping     Shaping
	wg          sync.WaitGroup
	writeStream bytes.Buffer
	writtenCond sync.Cond
	done        bool

	// closing is set by CloseWrite: the writer leaves once the buffer is
	// empty instead of waiting for more. stopped is closed when it leaves.
	closing bool
	stopped chan struct{}

	// writes counts Writes; release lets go of the queue's peak once a
	// connection has gone idle, armed with the count it saw (releaseMark)
	// while releaseArmed. All under writtenCond.L; release is created the
	// first time a queue outgrows keepQueueMax, so most connections never
	// have one.
	writes       uint64
	release      *time.Timer
	releaseArmed bool
	releaseMark  uint64
}

// Write queues p for the paced writer. It waits while MaxBuffered bytes are
// already queued, so the queue peaks at MaxBuffered plus one write; Stop,
// CloseWrite and the end of the conn's context all release it with an error.
func (c Conn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, context.Cause(c.p.ctx)
	}

	c.p.writtenCond.L.Lock()

	for c.p.writeStream.Len() >= MaxBuffered && !c.p.done && !c.p.closing && c.p.ctx.Err() == nil {
		c.p.writtenCond.Wait()
	}

	if err := context.Cause(c.p.ctx); err != nil {
		c.p.writtenCond.L.Unlock()

		return 0, err
	}

	if c.p.done || c.p.closing {
		c.p.writtenCond.L.Unlock()

		return 0, errWriteClosed
	}

	c.p.writeStream.Write(p)
	c.p.writes++
	c.p.writtenCond.L.Unlock()

	// Broadcast, not Signal: the paced writer and blocked Writes wait on the
	// same condition, and a Signal could wake the wrong one.
	c.p.writtenCond.Broadcast()

	return len(p), nil
}

func (c Conn) start() {
	if c.p.shaping == ShapingBurst {
		c.startBurst()

		return
	}

	c.startRecord()
}

// startRecord is record shaping: a delay drawn before every record.
func (c Conn) startRecord() {
	bp, ok := doppelBufPool.Get().(*[]byte)
	if !ok {
		// Unreachable: doppelBufPool.New only ever returns a *[]byte.
		b := make([]byte, tls.MaxRecordSize)
		bp = &b
	}

	buf := *bp

	defer doppelBufPool.Put(bp)

	timer := time.NewTimer(c.p.stats.Delay())
	defer timer.Stop()

	for {
		select {
		case <-c.p.ctx.Done():
			return
		case <-timer.C:
			timer.Reset(c.p.stats.Delay())
		}

		size := c.p.stats.Size()

		c.p.writtenCond.L.Lock()
		for c.p.writeStream.Len() == 0 && !c.p.done && !c.p.closing && c.p.ctx.Err() == nil {
			c.p.armRelease()
			c.p.writtenCond.Wait()
		}
		n, _ := c.p.writeStream.Read(buf[tls.SizeHeader : tls.SizeHeader+size])
		closing := c.p.closing
		c.p.writtenCond.L.Unlock()

		// Room in the queue: wake any Write waiting on the bound.
		c.p.writtenCond.Broadcast()

		if n == 0 {
			if closing {
				return
			}

			continue
		}

		if err := tls.WriteRecordInPlace(c.Conn, buf, n); err != nil {
			c.p.ctxCancel(err)
			return
		}
	}
}

// startBurst is burst shaping: one delay when the connection wakes from
// idle, then records back to back, several to a write. Record sizes are drawn
// from Stats exactly as record shaping draws them -- DRS ramp and idle reset
// included -- and a record that does not fit the current batch keeps its
// drawn size for the next one, so batching never changes a record's size.
// Like record shaping, it sends a shorter record when the queue holds less
// than the size drawn.
func (c Conn) startBurst() {
	timer := time.NewTimer(time.Hour)
	timer.Stop()

	defer timer.Stop()

	var lastWrite time.Time

	pending := 0 // a drawn record size that did not fit the last batch

	for {
		c.p.writtenCond.L.Lock()
		for c.p.writeStream.Len() == 0 && !c.p.done && !c.p.closing && c.p.ctx.Err() == nil {
			c.p.armRelease()
			c.p.writtenCond.Wait()
		}

		if c.p.writeStream.Len() == 0 || c.p.done || c.p.ctx.Err() != nil {
			// Closing with nothing left, stopped, or the context ended. Stopped
			// and the context ending cut whatever is still queued: the bursts
			// are back to back, so this is the only place a burst sees them.
			c.p.writtenCond.L.Unlock()

			return
		}
		c.p.writtenCond.L.Unlock()

		if lastWrite.IsZero() || time.Since(lastWrite) >= TLSRecordSizeResetAfter {
			timer.Reset(c.p.stats.Delay())

			select {
			case <-c.p.ctx.Done():
				return
			case <-timer.C:
			}
		}

		// The batch buffer is taken for the write and given back after it, so
		// a connection between bursts -- most of them, most of the time --
		// holds none.
		bp, ok := burstBufPool.Get().(*[]byte)
		if !ok {
			// Unreachable: burstBufPool.New only ever returns a *[]byte.
			b := make([]byte, BurstWriteMax)
			bp = &b
		}

		buf := *bp
		batch := buf[:0]

		c.p.writtenCond.L.Lock()
		for queued := c.p.writeStream.Len(); queued > 0; queued = c.p.writeStream.Len() {
			size := pending
			if size == 0 {
				size = c.p.stats.Size()
			}

			n := min(size, queued)
			if len(batch) > 0 && len(batch)+tls.SizeHeader+n > len(buf) {
				pending = size

				break
			}

			pending = 0
			record := buf[len(batch) : len(batch)+tls.SizeHeader+n]

			tls.PutRecordHeader(record, n)                //nolint: errcheck // n <= TLSRecordSizeMax
			c.p.writeStream.Read(record[tls.SizeHeader:]) //nolint: errcheck // n <= queued

			batch = buf[:len(batch)+len(record)]
		}
		c.p.writtenCond.L.Unlock()

		// Room in the queue: wake any Write waiting on the bound.
		c.p.writtenCond.Broadcast()

		_, err := c.Conn.Write(batch)

		burstBufPool.Put(bp)

		if err != nil {
			c.p.ctxCancel(err)

			return
		}

		lastWrite = time.Now()
	}
}

// armRelease is called, with the queue's lock held, by a writer about to wait
// on an empty queue. If the queue has outgrown keepQueueMax it schedules a
// check, one at a time, for when the connection may have gone idle.
func (p *connPayload) armRelease() {
	if p.releaseArmed || p.done || p.writeStream.Cap() <= keepQueueMax {
		return
	}

	p.releaseArmed = true
	p.releaseMark = p.writes

	if p.release == nil {
		p.release = time.AfterFunc(TLSRecordSizeResetAfter, p.releaseIfIdle)
	} else {
		p.release.Reset(TLSRecordSizeResetAfter)
	}
}

// releaseIfIdle lets go of the queue's peak if nothing was written since the
// check was armed. Written since and empty again: check again later. Not
// empty: a transfer is on, and the writer arms a new check when it next
// waits.
func (p *connPayload) releaseIfIdle() {
	p.writtenCond.L.Lock()
	defer p.writtenCond.L.Unlock()

	p.releaseArmed = false

	switch {
	case p.writeStream.Len() > 0 || p.writeStream.Cap() <= keepQueueMax:
	case p.writes != p.releaseMark:
		p.armRelease()
	default:
		p.writeStream = bytes.Buffer{}
	}
}

// CloseWrite ends the response rather than aborting it. What is buffered keeps
// going out at the pace it was going, and once all of it is on the wire the
// client is sent EOF. A client that has stopped reading cannot hold this up for
// longer than DrainTimeout; whatever is still buffered then is dropped.
func (c Conn) CloseWrite() error {
	c.p.writtenCond.L.Lock()
	c.p.closing = true
	c.p.writtenCond.L.Unlock()
	c.p.writtenCond.Broadcast()

	timer := time.NewTimer(DrainTimeout)
	defer timer.Stop()

	select {
	case <-c.p.stopped:
	case <-timer.C:
		c.p.ctxCancel(errDrainTimeout)
	}

	return c.Conn.CloseWrite() //nolint: wrapcheck // the underlying connection's own error
}

func (c Conn) Stop() {
	c.p.ctxCancel(nil)

	c.p.writtenCond.L.Lock()
	c.p.done = true

	if c.p.release != nil {
		c.p.release.Stop()
	}
	c.p.writtenCond.L.Unlock()
	c.p.writtenCond.Broadcast()

	c.p.wg.Wait()
}

func NewConn(ctx context.Context, conn essentials.Conn, stats Stats, shaping Shaping) Conn {
	ctx, cancel := context.WithCancelCause(ctx)
	rv := Conn{
		Conn: conn,
		p: &connPayload{
			ctx:       ctx,
			ctxCancel: cancel,
			stats:     stats,
			shaping:   shaping,
			writtenCond: sync.Cond{
				L: &sync.Mutex{},
			},
			stopped: make(chan struct{}),
		},
	}

	rv.p.writeStream.Grow(tls.DefaultBufferSize)

	// The context ending must wake whoever waits on the queue -- a Write held
	// at the bound, or the writer waiting for data. Taking the lock first means
	// a waiter is either before its check, and sees the context done, or
	// already waiting, and gets this broadcast: never in between.
	context.AfterFunc(ctx, func() {
		rv.p.writtenCond.L.Lock()
		rv.p.writtenCond.L.Unlock() //nolint: staticcheck // an empty critical section is the point
		rv.p.writtenCond.Broadcast()
	})

	rv.p.wg.Go(func() {
		defer close(rv.p.stopped)

		rv.start()
	})

	return rv
}
