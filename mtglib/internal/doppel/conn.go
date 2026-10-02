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

var errDrainTimeout = errors.New("the client did not take the rest of the response in time")

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

func (c Conn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, context.Cause(c.p.ctx)
	}

	c.p.writtenCond.L.Lock()
	c.p.writeStream.Write(p)
	c.p.writtenCond.L.Unlock()

	c.p.writtenCond.Signal()

	return len(p), context.Cause(c.p.ctx)
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
		for c.p.writeStream.Len() == 0 && !c.p.done && !c.p.closing {
			c.p.writtenCond.Wait()
		}
		n, _ := c.p.writeStream.Read(buf[tls.SizeHeader : tls.SizeHeader+size])
		closing := c.p.closing
		c.p.writtenCond.L.Unlock()

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

	rv.p.wg.Go(func() {
		defer close(rv.p.stopped)

		rv.start()
	})

	return rv
}
