package utils

import (
	"context"
	"fmt"
	"net"

	"github.com/Arman2122/mtg-proxy/network"
)

type Listener struct {
	net.Listener
}

func (l Listener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err //nolint: wrapcheck
	}

	if err := network.SetClientSocketOptions(conn, 0); err != nil {
		conn.Close() //nolint: errcheck

		return nil, fmt.Errorf("cannot set TCP options: %w", err)
	}

	return conn, nil
}

func NewListener(bindTo string, bufferSize int) (net.Listener, error) {
	// (&net.ListenConfig{}).Listen with a background context is the literal
	// body of net.Listen; spelling it out is what lets a caller thread a
	// context through later without touching the call site again.
	base, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", bindTo)
	if err != nil {
		return nil, fmt.Errorf("cannot build a base listener: %w", err)
	}

	return Listener{
		Listener: base,
	}, nil
}

type acceptResult struct {
	conn net.Conn
	err  error
}

// MultiListener fans-in Accept calls from multiple underlying listeners.
type MultiListener struct {
	listeners []net.Listener
	connCh    chan acceptResult
}

func NewMultiListener(listeners ...net.Listener) *MultiListener {
	ml := &MultiListener{
		listeners: listeners,
		connCh:    make(chan acceptResult, len(listeners)),
	}

	for _, l := range listeners {
		go ml.acceptLoop(l)
	}

	return ml
}

func (ml *MultiListener) acceptLoop(l net.Listener) {
	for {
		conn, err := l.Accept()
		ml.connCh <- acceptResult{conn: conn, err: err}

		if err != nil {
			return
		}
	}
}

func (ml *MultiListener) Accept() (net.Conn, error) {
	r := <-ml.connCh
	return r.conn, r.err
}

func (ml *MultiListener) Close() error {
	var firstErr error

	for _, l := range ml.listeners {
		if err := l.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}

	return firstErr
}

func (ml *MultiListener) Addr() net.Addr {
	return ml.listeners[0].Addr()
}
