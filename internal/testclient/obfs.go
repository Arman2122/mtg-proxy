package testclient

import (
	"bytes"
	"errors"
	"fmt"
	"net"

	"github.com/Arman2122/mtg-proxy/essentials"
	"github.com/Arman2122/mtg-proxy/mtglib/obfuscation"
)

// ObfuscatedFrame returns exactly the 64 bytes a client sends to open an
// obfuscated2 stream for this key, transport tag and data centre. The cipher
// state is not kept: a client that goes on talking uses
// obfuscation.Obfuscator.SendHandshake on its connection instead.
func ObfuscatedFrame(key [16]byte, tag obfuscation.ConnectionTag, dc int) ([]byte, error) {
	sink := &frameSink{}

	if _, err := (obfuscation.Obfuscator{Secret: key[:]}).SendHandshake(sink, dc, tag); err != nil {
		return nil, fmt.Errorf("cannot build the obfuscated2 frame: %w", err)
	}

	return sink.wrote.Bytes(), nil
}

// frameSink is an essentials.Conn that only supports Write. The embedded
// interface is nil on purpose, so any other call panics loudly.
type frameSink struct {
	essentials.Conn

	wrote bytes.Buffer
}

func (f *frameSink) Write(p []byte) (int, error) {
	return f.wrote.Write(p) //nolint: wrapcheck
}

var errNotTCP = errors.New("not a TCP connection")

// ResetOnClose makes closing c send a reset instead of a FIN, so a run that
// ends thousands of connections does not fill the kernel's TIME_WAIT table.
func ResetOnClose(c net.Conn) error {
	tcp, ok := c.(*net.TCPConn)
	if !ok {
		return fmt.Errorf("%T: %w", c, errNotTCP)
	}

	return tcp.SetLinger(0) //nolint: wrapcheck
}
