package mtglib

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"net"
	"time"

	"github.com/Arman2122/mtg-proxy/essentials"
	"github.com/Arman2122/mtg-proxy/mtglib/obfuscation"
)

type streamContext struct {
	ctx              context.Context
	ctxCancel        context.CancelFunc
	clientConn       essentials.Conn
	telegramConn     essentials.Conn
	streamID         string
	dc               int
	matchedSecretKey []byte
	secretName       string
	adTag            *[AdTagLength]byte
	logger           Logger

	// entry is the door this stream came in through. It decides whether the
	// FakeTLS write framing (the doppelganger plus the obfuscated handshake read
	// back out through it) applies -- on a plaintext listener that framing would
	// stamp a TLS record header onto a non-TLS port.
	entry entryKind

	// connTag is the client's own transport selector. The relay above is
	// byte-transparent, so the tag announced to Telegram must be this one.
	connTag obfuscation.ConnectionTag
}

func (s *streamContext) Deadline() (time.Time, bool) {
	return s.ctx.Deadline()
}

func (s *streamContext) Done() <-chan struct{} {
	return s.ctx.Done()
}

func (s *streamContext) Err() error {
	return s.ctx.Err() //nolint: wrapcheck
}

func (s *streamContext) Value(key any) any {
	return s.ctx.Value(key)
}

func (s *streamContext) Close() {
	s.ctxCancel()

	if s.clientConn != nil {
		s.clientConn.Close() //nolint: errcheck
	}

	if s.telegramConn != nil {
		s.telegramConn.Close() //nolint: errcheck
	}
}

// ClientIP is nil when the connection carries no IP the policy layer can read.
// It runs inside newStreamContext BEFORE `defer ctx.Close()` is registered, so
// the forced assert it used to be leaked the socket on the way out.
func (s *streamContext) ClientIP() net.IP {
	ip, _ := acceptedClientIP(s.clientConn.RemoteAddr())

	return ip
}

func newStreamContext(ctx context.Context, logger Logger, clientConn essentials.Conn) *streamContext {
	connIDBytes := make([]byte, ConnectionIDBytesLength)

	if _, err := rand.Read(connIDBytes); err != nil {
		panic(err)
	}

	ctx, cancel := context.WithCancel(ctx)
	streamCtx := &streamContext{
		ctx:        ctx,
		ctxCancel:  cancel,
		clientConn: clientConn,
		streamID:   base64.RawURLEncoding.EncodeToString(connIDBytes),
		// Default to today's tag so any path that forgets to set one emits
		// exactly the bytes this proxy has always emitted.
		connTag: obfuscation.TagPaddedIntermediate,
	}
	streamCtx.logger = logger.
		BindStr("stream-id", streamCtx.streamID).
		BindStr("client-ip", streamCtx.ClientIP().String())

	return streamCtx
}
