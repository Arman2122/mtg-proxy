package proxyprotocol

import (
	"net"
	"testing"

	"github.com/pires/go-proxyproto"
)

/*
connWrapper's half-close shims used to `panic("we support only tcp connections")`
whenever the connection underneath was not a *net.TCPConn.

That is a process kill, not an error: the relay calls CloseRead and CloseWrite
from a worker goroutine, and an unrecovered panic in any goroutine ends the Go
program. So the proxy dies and takes every client with it.

essentials.netConnWrapper, in this same repository, already had the answer for
exactly this case: fall back to a full Close when the half-close is not
available. Both shims do that now. Closing both ends of a connection that cannot
half-close is what "close the reading end" means for it.
*/
func TestAHalfCloseOnANonTCPConnectionClosesItInsteadOfKillingTheProcess(t *testing.T) {
	for _, c := range []struct {
		name string
		call func(connWrapper) error
	}{
		{"CloseRead", connWrapper.CloseRead},
		{"CloseWrite", connWrapper.CloseWrite},
	} {
		t.Run(c.name, func(t *testing.T) {
			client, server := net.Pipe()
			defer server.Close()

			// net.Pipe is not a TCPConn, which is what TCPConn() answers false to.
			wrapped := connWrapper{proxyproto.NewConn(client)}
			if _, ok := wrapped.TCPConn(); ok {
				t.Fatal("fixture is wrong: this connection IS a TCPConn, so it never reached the panic")
			}

			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("%s panicked, which ends the whole process from a relay goroutine: %v", c.name, r)
				}
			}()

			if err := c.call(wrapped); err != nil {
				t.Fatalf("%s: %v", c.name, err)
			}

			// The fallback is a real close, not a silent success.
			if _, err := client.Write([]byte("x")); err == nil {
				t.Fatalf("%s reported success but left the connection open", c.name)
			}
		})
	}
}
