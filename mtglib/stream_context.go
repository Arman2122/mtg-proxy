package mtglib

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Arman2122/mtg-proxy/essentials"
	"github.com/Arman2122/mtg-proxy/mtglib/obfuscation"
)

type streamContext struct {
	ctx       context.Context
	ctxCancel context.CancelFunc

	// connMu guards the two sockets and the closed flag. Reach them through
	// client/setClient and telegram/setTelegram, never directly.
	//
	// This stream's own goroutine writes them as the handshake proceeds: the
	// client socket is re-wrapped up to three times on the way in, and the
	// Telegram one does not exist at all until the dial returns. Close reads
	// both -- and a secret reload calls Close from an entirely different
	// goroutine, to revoke a stream that is still running.
	//
	// The lock is not only about the race detector. A Close that reads a nil
	// telegramSocket a moment before the dial assigns one leaves that socket
	// with nobody left to close it: the revocation silently does not happen,
	// and the stream a reload was meant to kill keeps carrying traffic. The
	// closed flag is what makes the two orderings equivalent.
	connMu         sync.Mutex
	clientSocket   essentials.Conn
	telegramSocket essentials.Conn
	closed         bool

	streamID         string
	dc               int
	matchedSecretKey []byte
	secretName       string
	adTag            *[AdTagLength]byte
	logger           Logger

	// attrSet is the secret set attribute matched this stream against, which
	// matchedSecretKey points into. Registration compares it with the set in
	// force: the same set still accepts the key it matched, and any other set
	// is asked whether it does. Set to nil once the stream is registered, so a
	// stream that lives for hours does not pin a whole old set -- candidates,
	// pad states -- for as long; matchedSecretKey is kept.
	attrSet *secretSet

	// entry is the door this stream came in through. It decides whether the
	// FakeTLS write framing (the doppelganger plus the obfuscated handshake read
	// back out through it) applies -- on a plaintext listener that framing would
	// stamp a TLS record header onto a non-TLS port.
	entry entryKind

	// connTag is the client's own transport selector. The relay above is
	// byte-transparent, so the tag announced to Telegram must be this one.
	connTag obfuscation.ConnectionTag

	// ipLimit is the user's address limit as it stood when the secret
	// matched, read from the same snapshot as the rest of the attribution.
	ipLimit int

	// clientConns is the user's per-address connection cap as it stood when
	// the secret matched, read with ipLimit; zero is no cap.
	clientConns int

	// addrKey is the address this stream was counted under in its user's
	// ledger, and addrCounted says whether it was counted at all -- so the
	// release on the way out undoes exactly what admission did, whichever
	// snapshot of the limit it happened under.
	addrKey     addressKey
	addrCounted bool

	// addrKeyed says whether the address stands for one place (clientKeyed):
	// a keyed stream gets an entry of its own in the per-address table, any
	// other joins its secret's rest entry. Set at admission with the two
	// fields above, under liveMu, so a reload's backfill can read it there
	// without resolving the address again.
	addrKeyed bool

	// addrEntry is the per-address table entry this stream is governed by, or
	// nil when its secret needs none. Stored once admission has passed every
	// step, or by a reload's backfill, both under liveMu, and given back by
	// unregisterConn. Atomic because the data path reads it without a lock.
	addrEntry atomic.Pointer[clientEntry]

	// scanRes is what the FakeTLS door's scan was charged to the handshake
	// budget, or nil when nothing was (a hinted match, the budget off, another
	// door). ServeConn refunds it once admission has succeeded; every earlier
	// exit leaves it unsettled, which keeps the charge.
	scanRes *scanReservation

	// lastActiveUnix is the second this stream last moved a byte, stamped at
	// admission and by the data path, for the per-address activity report.
	lastActiveUnix atomic.Int64
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

// client returns the socket the client is currently speaking through: the raw
// one early in the handshake, and whatever wraps it afterwards.
func (s *streamContext) client() essentials.Conn {
	s.connMu.Lock()
	defer s.connMu.Unlock()

	return s.clientSocket
}

// setClient replaces the client socket, usually with a wrapper around the one
// already there.
//
// A socket handed over after Close has run is closed here rather than stored.
// Storing it would be worse than dropping it: nothing would ever close it, and
// the stream a reload just revoked would still be holding a live connection.
func (s *streamContext) setClient(conn essentials.Conn) {
	s.connMu.Lock()
	closed := s.closed

	if !closed {
		s.clientSocket = conn
	}

	s.connMu.Unlock()

	if closed {
		conn.Close() //nolint: errcheck // a socket nobody will ever read
	}
}

// telegram returns the upstream socket, which is nil until the dial returns.
func (s *streamContext) telegram() essentials.Conn {
	s.connMu.Lock()
	defer s.connMu.Unlock()

	return s.telegramSocket
}

// setTelegram records the upstream socket, or closes it if this stream has
// already been revoked. This is the ordering the whole lock exists for.
func (s *streamContext) setTelegram(conn essentials.Conn) {
	s.connMu.Lock()
	closed := s.closed

	if !closed {
		s.telegramSocket = conn
	}

	s.connMu.Unlock()

	if closed {
		conn.Close() //nolint: errcheck // a socket nobody will ever read
	}
}

// Close revokes the stream. It is called by this stream's own goroutine on the
// way out, and by a secret reload from another goroutine to kill a stream whose
// secret is gone -- so it takes one snapshot under the lock and closes outside
// it, and marks the stream closed so a socket assigned afterwards is closed
// rather than orphaned.
func (s *streamContext) Close() {
	s.ctxCancel()

	s.connMu.Lock()
	s.closed = true
	clientConn, telegramConn := s.clientSocket, s.telegramSocket
	s.connMu.Unlock()

	if clientConn != nil {
		clientConn.Close() //nolint: errcheck
	}

	if telegramConn != nil {
		telegramConn.Close() //nolint: errcheck
	}
}

// ClientIP is nil when the connection carries no IP the policy layer can read.
// It runs inside newStreamContext BEFORE `defer ctx.Close()` is registered, so
// the forced assert it used to be leaked the socket on the way out.
func (s *streamContext) ClientIP() net.IP {
	conn := s.client()
	if conn == nil {
		return nil
	}

	ip, _ := acceptedClientIP(conn.RemoteAddr())

	return ip
}

func newStreamContext(ctx context.Context, logger Logger, clientConn essentials.Conn) *streamContext {
	connIDBytes := make([]byte, ConnectionIDBytesLength)

	if _, err := rand.Read(connIDBytes); err != nil {
		panic(err)
	}

	ctx, cancel := context.WithCancel(ctx)
	streamCtx := &streamContext{
		ctx:          ctx,
		ctxCancel:    cancel,
		clientSocket: clientConn,
		streamID:     base64.RawURLEncoding.EncodeToString(connIDBytes),
		// Default to today's tag so any path that forgets to set one emits
		// exactly the bytes this proxy has always emitted.
		connTag: obfuscation.TagPaddedIntermediate,
	}
	streamCtx.logger = logger.
		BindStr("stream-id", streamCtx.streamID).
		BindStr("client-ip", streamCtx.ClientIP().String())

	return streamCtx
}
