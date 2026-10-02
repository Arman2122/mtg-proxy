package relay

import (
	"context"
	"errors"
	"io"

	"github.com/Arman2122/mtg-proxy/essentials"
)

// Relay copies between Telegram and the client until either side finishes,
// then ends the stream.
//
// Neither Telegram nor its clients keep one half of a connection open after
// closing the other, so a stream is over as soon as either side ends it. What
// has already been read for the direction that ended is still delivered: its
// destination's write side is closed, which flushes anything a wrapper there is
// holding and then sends the peer its EOF. Only then are both connections
// closed, which ends the other direction wherever it is. Keeping that other
// direction open instead would hold a departed client's sockets until the idle
// timeout, for a half-connection nobody reads.
func Relay(ctx context.Context, log Logger, telegramConn, clientConn essentials.Conn) {
	defer telegramConn.Close() //nolint: errcheck
	defer clientConn.Close()   //nolint: errcheck

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	stop := context.AfterFunc(ctx, func() {
		telegramConn.Close() //nolint: errcheck
		clientConn.Close()   //nolint: errcheck
	})
	defer stop()

	closeChan := make(chan struct{})

	go func() {
		defer close(closeChan)
		defer cancel()

		pump(ctx, log, telegramConn, clientConn, "client -> telegram")
	}()

	func() {
		defer cancel()

		pump(ctx, log, clientConn, telegramConn, "telegram -> client")
	}()

	<-closeChan
}

// pump copies src into dst until src ends. A direction that ended by itself
// then closes dst's write side, so that everything it read is delivered and
// dst's peer sees EOF; one cut short by the stream ending (ctx done) does not,
// because nobody is left to deliver to.
func pump(ctx context.Context, log Logger, dst, src essentials.Conn, direction string) {
	buf := acquireBuffer()
	defer releaseBuffer(buf)

	n, err := io.CopyBuffer(dst, src, *buf)

	if ctx.Err() == nil {
		dst.CloseWrite() //nolint: errcheck
	}

	switch {
	case err == nil:
		log.Printf("%s has been finished", direction)
	case errors.Is(err, io.EOF):
		log.Printf("%s has been finished because of EOF. Written %d bytes", direction, n)
	default:
		log.Printf("%s has been finished (written %d bytes): %v", direction, n, err)
	}
}
