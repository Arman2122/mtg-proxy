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
// limit charges is never far ahead of what is sent.
const MaxBuffered = 256 << 10

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

type Conn struct {
	essentials.Conn

	p *connPayload
}

type connPayload struct {
	ctx         context.Context
	ctxCancel   context.CancelCauseFunc
	stats       Stats
	wg          sync.WaitGroup
	writeStream bytes.Buffer
	writtenCond sync.Cond
	done        bool

	// closing is set by CloseWrite: the writer leaves once the buffer is
	// empty instead of waiting for more. stopped is closed when it leaves.
	closing bool
	stopped chan struct{}
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
	c.p.writtenCond.L.Unlock()

	// Broadcast, not Signal: the paced writer and blocked Writes wait on the
	// same condition, and a Signal could wake the wrong one.
	c.p.writtenCond.Broadcast()

	return len(p), nil
}

func (c Conn) start() {
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
	c.p.writtenCond.L.Unlock()
	c.p.writtenCond.Broadcast()

	c.p.wg.Wait()
}

func NewConn(ctx context.Context, conn essentials.Conn, stats Stats) Conn {
	ctx, cancel := context.WithCancelCause(ctx)
	rv := Conn{
		Conn: conn,
		p: &connPayload{
			ctx:       ctx,
			ctxCancel: cancel,
			stats:     stats,
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
