package proxyprotocol

import (
	"net"

	"github.com/pires/go-proxyproto"
)

type ListenerAdapter struct {
	proxyproto.Listener
}

func (l *ListenerAdapter) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}

	pConn, ok := conn.(*proxyproto.Conn)
	if !ok {
		// proxyproto.Listener has always handed back a *proxyproto.Conn, so
		// this branch is unreachable today. It exists because the accept loop
		// is the one place in this process where a wrong guess about a type
		// is a process kill rather than a dropped connection -- see 005b58d.
		// A connection that is not a *proxyproto.Conn is still perfectly
		// usable; it just does not get the half-close shims.
		return conn, nil
	}

	return connWrapper{pConn}, nil
}
