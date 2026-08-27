package proxyprotocol

import "github.com/pires/go-proxyproto"

type connWrapper struct {
	*proxyproto.Conn
}

// CloseRead and CloseWrite fall back to a full close when the connection
// underneath is not TCP, matching essentials.netConnWrapper. They used to
// panic, which ended the process from inside the relay.

func (c connWrapper) CloseRead() error {
	tcpConn, ok := c.TCPConn()
	if !ok {
		return c.Close()
	}

	return tcpConn.CloseRead()
}

func (c connWrapper) CloseWrite() error {
	tcpConn, ok := c.TCPConn()
	if !ok {
		return c.Close()
	}

	return tcpConn.CloseWrite()
}
