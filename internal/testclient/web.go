package testclient

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/Arman2122/mtg-proxy/internal/webrelay/frame"
)

// Copied from internal/webrelay (origin.go and stream.go), which this package
// cannot import.
const (
	webSessionPath = "/api/v1/session"
	webCarrierPath = "/api/v1/ws"
	webSubprotocol = "tproxy-v1."

	// webInitialWindow is the credit each direction of a stream starts with
	// (webrelay.InitialWindow). No frame carries it: both ends compile it in.
	webInitialWindow = 4 << 20

	// webDataChunk is the most one DATA frame from this client carries, the
	// relay's own downlink chunk (frame.MaxRelayDataChunk).
	webDataChunk = 64 << 10

	// webGrantEvery is how much a stream consumes before returning the credit.
	webGrantEvery = 1 << 20
)

var (
	errNoBootstrap     = errors.New("the bridge page carried no bootstrap token")
	errSessionRefused  = errors.New("the relay refused the session")
	errStreamClosed    = errors.New("the WEB stream is closed")
	errStreamInUse     = errors.New("the stream id is already open")
	errNotHTTP         = errors.New("only a plain-HTTP relay origin is supported")
	errCarrierClosed   = errors.New("the relay closed the carrier")
	errDownlinkOverrun = errors.New("the relay sent past the credit this stream granted")
)

// WebOptions shapes how a WEB client presents itself to the relay.
type WebOptions struct {
	// Origin is the relay's own host name ([web] host), sent as the Origin
	// header of the carrier upgrade.
	Origin string

	// ForwardedFor, when set, is sent as X-Forwarded-For, for a relay that takes
	// the client address from it (client-ip = "x-forwarded-for").
	ForwardedFor string

	// DialTimeout bounds every HTTP step and the upgrade. Default 5s.
	DialTimeout time.Duration

	// ResetOnClose makes closing the carrier send a reset, so a run that opens
	// thousands of sessions leaves no TIME_WAIT behind.
	ResetOnClose bool

	// ReadBufferSize is the carrier's read buffer. Default 256 KiB, for bulk
	// transfers; a run that holds thousands of idle sessions sets it small, so
	// the memory it measures is the relay's and not the client's.
	ReadBufferSize int
}

// WebSession is one WEB proxy session: a bootstrap spent on a session, and the
// carrier WebSocket its streams share.
type WebSession struct {
	baseURL string
	token   string
	client  *http.Client

	conn net.Conn
	r    *bufio.Reader

	writeMu sync.Mutex
	batch   []byte
	wire    []byte

	mu      sync.Mutex
	streams map[uint32]*WebStream
	err     error
}

// OpenWebSession walks what the bridge script does: fetch the bridge page for
// capability, spend the bootstrap token it embeds on a session, and open the
// carrier. baseURL is the relay origin, e.g. "http://127.0.0.1:47003".
func OpenWebSession(ctx context.Context, baseURL, capability string, o WebOptions) (*WebSession, error) {
	if !strings.HasPrefix(baseURL, "http://") {
		return nil, fmt.Errorf("%q: %w", baseURL, errNotHTTP)
	}

	if o.ReadBufferSize == 0 {
		o.ReadBufferSize = 256 << 10
	}

	if o.DialTimeout == 0 {
		o.DialTimeout = 5 * time.Second
	}

	client := &http.Client{Timeout: o.DialTimeout}

	bootstrap, err := bridgeToken(ctx, client, baseURL, capability, o.ForwardedFor)
	if err != nil {
		return nil, err
	}

	token, err := spendBootstrap(ctx, client, baseURL, bootstrap, o.ForwardedFor)
	if err != nil {
		return nil, err
	}

	conn, reader, err := dialWebSocket(ctx, strings.TrimPrefix(baseURL, "http://"), webCarrierPath,
		webSubprotocol+token, o.Origin, o.ForwardedFor, o.DialTimeout, o.ReadBufferSize)
	if err != nil {
		// The session exists; without a carrier it would hold a slot against
		// the relay's session limit for its reconnect grace. Give it back.
		deleteSession(context.WithoutCancel(ctx), client, baseURL, token) //nolint: errcheck

		return nil, err
	}

	if o.ResetOnClose {
		if err := ResetOnClose(conn); err != nil {
			conn.Close() //nolint: errcheck

			return nil, err
		}
	}

	s := &WebSession{
		baseURL: baseURL,
		token:   token,
		client:  client,
		conn:    conn,
		r:       reader,
		streams: make(map[uint32]*WebStream),
	}

	go s.readLoop()

	return s, nil
}

func bridgeToken(ctx context.Context, client *http.Client, baseURL, capability, forwardedFor string) (string, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/?bridge="+capability, nil)
	if err != nil {
		return "", fmt.Errorf("cannot build the bridge request: %w", err)
	}

	setForwardedFor(request, forwardedFor)

	response, err := client.Do(request)
	if err != nil {
		return "", fmt.Errorf("cannot fetch the bridge page: %w", err)
	}

	defer response.Body.Close() //nolint: errcheck

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return "", fmt.Errorf("cannot read the bridge page: %w", err)
	}

	const marker = `"token":"`

	start := bytes.Index(body, []byte(marker))
	if response.StatusCode != http.StatusOK || start < 0 {
		return "", fmt.Errorf("%w (HTTP %d)", errNoBootstrap, response.StatusCode)
	}

	rest := body[start+len(marker):]

	end := bytes.IndexByte(rest, '"')
	if end < 0 {
		return "", errNoBootstrap
	}

	return string(rest[:end]), nil
}

func spendBootstrap(ctx context.Context, client *http.Client, baseURL, bootstrap, forwardedFor string) (string, error) {
	hello, err := frame.Limits{}.EncodeBatch(nil, []frame.Frame{frame.NewHello()}, frame.ClientToRelay)
	if err != nil {
		return "", fmt.Errorf("cannot encode HELLO: %w", err)
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+webSessionPath, bytes.NewReader(hello))
	if err != nil {
		return "", fmt.Errorf("cannot build the session request: %w", err)
	}

	request.Header.Set("Authorization", "Bearer "+bootstrap)
	setForwardedFor(request, forwardedFor)

	response, err := client.Do(request)
	if err != nil {
		return "", fmt.Errorf("cannot create the session: %w", err)
	}

	defer response.Body.Close() //nolint: errcheck

	io.Copy(io.Discard, response.Body) //nolint: errcheck

	token := response.Header.Get("X-Session-Token")
	if response.StatusCode != http.StatusOK || token == "" {
		return "", fmt.Errorf("%w (HTTP %d)", errSessionRefused, response.StatusCode)
	}

	return token, nil
}

func setForwardedFor(request *http.Request, forwardedFor string) {
	if forwardedFor != "" {
		request.Header.Set("X-Forwarded-For", forwardedFor)
	}
}

// OpenStream opens stream id on the carrier. Its credit starts at the relay's
// initial window in both directions.
func (s *WebSession) OpenStream(id uint32) (*WebStream, error) {
	stream := &WebStream{session: s, id: id, credit: webInitialWindow, window: webInitialWindow}
	stream.cond = sync.NewCond(&stream.mu)

	s.mu.Lock()
	if s.err != nil {
		err := s.err
		s.mu.Unlock()

		return nil, err
	}

	if _, open := s.streams[id]; open {
		s.mu.Unlock()

		return nil, fmt.Errorf("stream %d: %w", id, errStreamInUse)
	}

	s.streams[id] = stream
	s.mu.Unlock()

	if err := s.writeFrames(frame.NewOpen(id)); err != nil {
		s.forget(id)

		return nil, err
	}

	return stream, nil
}

// Delete ends the session the way a browser does when its tab closes: a DELETE,
// so the relay reaps it at once rather than after the reconnect grace, and then
// the carrier goes too, as the closing tab takes its WebSocket with it. (The
// relay's DELETE alone does not end a carrier the client keeps open.)
func (s *WebSession) Delete(ctx context.Context) error {
	defer s.Close() //nolint: errcheck
	return deleteSession(ctx, s.client, s.baseURL, s.token)
}

// Token is the session's bearer, for a test that drives the session API
// itself.
func (s *WebSession) Token() string { return s.token }

func deleteSession(ctx context.Context, client *http.Client, baseURL, token string) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodDelete, baseURL+webSessionPath, nil)
	if err != nil {
		return fmt.Errorf("cannot build the delete request: %w", err)
	}

	request.Header.Set("Authorization", "Bearer "+token)

	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("cannot delete the session: %w", err)
	}

	response.Body.Close() //nolint: errcheck

	if response.StatusCode != http.StatusNoContent {
		return fmt.Errorf("deleting the session: HTTP %d: %w", response.StatusCode, errSessionRefused)
	}

	return nil
}

// Close drops the carrier; every stream on it fails.
func (s *WebSession) Close() error {
	s.fail(net.ErrClosed)

	return s.conn.Close() //nolint: wrapcheck
}

func (s *WebSession) writeFrames(frames ...frame.Frame) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	batch, err := frame.Limits{}.EncodeBatch(s.batch[:0], frames, frame.ClientToRelay)
	if err != nil {
		return fmt.Errorf("cannot encode the batch: %w", err)
	}

	s.batch = batch
	s.wire = appendClientFrame(s.wire[:0], opBinary, batch)

	if _, err := s.conn.Write(s.wire); err != nil {
		s.fail(err)

		return fmt.Errorf("cannot write to the carrier: %w", err)
	}

	return nil
}

func (s *WebSession) writeControl(opcode byte, payload []byte) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	s.wire = appendClientFrame(s.wire[:0], opcode, payload)

	_, err := s.conn.Write(s.wire)

	return err //nolint: wrapcheck
}

// readLoop owns the carrier's read side: pings are answered, relay batches are
// decoded and handed to their streams, and any error fails them all.
func (s *WebSession) readLoop() {
	// Grown to the largest frame seen rather than allocated up front: an idle
	// session holds only what it has needed.
	var buf []byte

	// Whatever ends the loop ends the carrier: the socket is closed here so
	// neither end is left holding goroutines for a carrier nobody reads.
	defer s.conn.Close() //nolint: errcheck

	for {
		opcode, payload, err := readServerFrame(s.r, buf)
		if cap(payload) > cap(buf) {
			buf = payload[:0]
		}

		if err != nil {
			// A carrier that ends without a close frame ended mid-stream as far
			// as every stream on it is concerned: never the io.EOF of a clean end.
			if errors.Is(err, io.EOF) {
				err = io.ErrUnexpectedEOF
			}

			s.fail(err)

			return
		}

		switch opcode {
		case opPing:
			if err := s.writeControl(opPong, append([]byte(nil), payload...)); err != nil {
				s.fail(err)

				return
			}
		case opClose:
			// The closing handshake: echo the close, then let go of the socket.
			// Whatever the code, the streams on the carrier did not end cleanly.
			code := 0
			if len(payload) >= 2 {
				code = int(binary.BigEndian.Uint16(payload))
			}

			s.writeControl(opClose, append([]byte(nil), payload...)) //nolint: errcheck
			s.fail(fmt.Errorf("%w (code %d)", errCarrierClosed, code))

			return
		case opBinary:
			// Decoded payloads are the caller's own, so buf can be reused.
			frames, err := frame.Limits{}.DecodeBatch(payload, frame.RelayToClient)
			if err != nil {
				s.fail(fmt.Errorf("the relay sent an undecodable batch: %w", err))

				return
			}

			for _, f := range frames {
				s.dispatch(f)
			}
		}
	}
}

func (s *WebSession) dispatch(f frame.Frame) {
	s.mu.Lock()
	stream := s.streams[f.StreamID]
	s.mu.Unlock()

	if stream == nil {
		return
	}

	switch f.Type {
	case frame.TypeData:
		stream.deliver(f.Payload)
	case frame.TypeWindow:
		if delta, ok := f.WindowDelta(); ok {
			stream.grant(delta)
		}
	case frame.TypeClose:
		stream.remoteClose()
	default:
	}
}

func (s *WebSession) fail(err error) {
	s.mu.Lock()
	if s.err == nil {
		s.err = err
	}

	streams := make([]*WebStream, 0, len(s.streams))
	for _, stream := range s.streams {
		streams = append(streams, stream)
	}
	s.mu.Unlock()

	for _, stream := range streams {
		stream.fail(err)
	}
}

func (s *WebSession) forget(id uint32) {
	s.mu.Lock()
	delete(s.streams, id)
	s.mu.Unlock()
}

// WebStream is one logical connection on a WEB carrier, with the relay's flow
// control honoured both ways: it returns credit as it consumes, and writes no
// more than the relay has granted. It is an ordered byte stream, so an
// obfuscated2 client runs over it unchanged.
type WebStream struct {
	session *WebSession
	id      uint32

	mu       sync.Mutex
	cond     *sync.Cond
	queue    [][]byte
	consumed int
	credit   int // uplink: what the relay has granted and this side not spent
	window   int // downlink: what this side has granted and the relay not spent
	eof      bool
	closed   bool
	err      error

	readDeadline, writeDeadline time.Time
	readTimer, writeTimer       *time.Timer
}

var _ net.Conn = (*WebStream)(nil)

func (st *WebStream) Read(p []byte) (int, error) {
	st.mu.Lock()

	for len(st.queue) == 0 {
		if err := st.blockedLocked(st.readDeadline); err != nil {
			st.mu.Unlock()

			return 0, err
		}

		if st.eof {
			st.mu.Unlock()

			return 0, io.EOF
		}

		st.cond.Wait()
	}

	n := copy(p, st.queue[0])
	if n == len(st.queue[0]) {
		st.queue[0] = nil
		st.queue = st.queue[1:]
	} else {
		st.queue[0] = st.queue[0][n:]
	}

	st.consumed += n

	grant := 0
	if st.consumed >= webGrantEvery {
		grant, st.consumed = st.consumed, 0
		st.window += grant
	}
	st.mu.Unlock()

	if grant > 0 {
		if err := st.session.writeFrames(frame.NewWindow(st.id, uint32(grant))); err != nil { //nolint: gosec // < webInitialWindow
			return n, err
		}
	}

	return n, nil
}

func (st *WebStream) Write(p []byte) (int, error) {
	written := 0

	for written < len(p) {
		st.mu.Lock()

		if st.eof && st.err == nil && !st.closed {
			st.mu.Unlock()

			return written, io.ErrClosedPipe
		}

		for st.credit == 0 {
			if err := st.blockedLocked(st.writeDeadline); err != nil {
				st.mu.Unlock()

				return written, err
			}

			if st.eof {
				st.mu.Unlock()

				return written, io.ErrClosedPipe
			}

			st.cond.Wait()
		}

		if err := st.blockedLocked(st.writeDeadline); err != nil {
			st.mu.Unlock()

			return written, err
		}

		n := min(len(p)-written, webDataChunk, st.credit)
		st.credit -= n
		st.mu.Unlock()

		// EncodeBatch copies the payload into the batch, so p is not retained.
		if err := st.session.writeFrames(frame.NewData(st.id, p[written:written+n])); err != nil {
			return written, err
		}

		written += n
	}

	return written, nil
}

// blockedLocked reports why the stream cannot go on, if it cannot: a failed
// carrier, a local close or a passed deadline.
func (st *WebStream) blockedLocked(deadline time.Time) error {
	switch {
	case st.err != nil:
		return st.err
	case st.closed:
		return errStreamClosed
	case !deadline.IsZero() && !time.Now().Before(deadline):
		return os.ErrDeadlineExceeded
	}

	return nil
}

func (st *WebStream) deliver(payload []byte) {
	st.mu.Lock()

	if len(payload) > st.window {
		window := st.window
		st.mu.Unlock()

		st.session.fail(fmt.Errorf("%w: stream %d got %d bytes with %d of credit",
			errDownlinkOverrun, st.id, len(payload), window))

		return
	}

	st.window -= len(payload)
	st.queue = append(st.queue, payload)
	st.mu.Unlock()
	st.cond.Broadcast()
}

func (st *WebStream) grant(delta uint32) {
	st.mu.Lock()
	st.credit += int(delta)
	st.mu.Unlock()
	st.cond.Broadcast()
}

func (st *WebStream) remoteClose() {
	st.mu.Lock()
	st.eof = true
	st.mu.Unlock()
	st.cond.Broadcast()
}

func (st *WebStream) fail(err error) {
	st.mu.Lock()
	if st.err == nil {
		st.err = err
	}
	st.mu.Unlock()
	st.cond.Broadcast()
}

// Close aborts the stream: the protocol has no half-close, and CLOSE drops what
// is still queued on either side.
func (st *WebStream) Close() error {
	st.mu.Lock()
	if st.closed {
		st.mu.Unlock()

		return nil
	}

	st.closed = true
	st.mu.Unlock()
	st.cond.Broadcast()

	st.session.forget(st.id)

	return st.session.writeFrames(frame.NewClose(st.id))
}

// CloseRead and CloseWrite exist so a stream satisfies essentials.Conn. The
// protocol has no half-close, so they do nothing.
func (st *WebStream) CloseRead() error  { return nil }
func (st *WebStream) CloseWrite() error { return nil }

func (st *WebStream) LocalAddr() net.Addr  { return st.session.conn.LocalAddr() }
func (st *WebStream) RemoteAddr() net.Addr { return st.session.conn.RemoteAddr() }

func (st *WebStream) SetDeadline(t time.Time) error {
	st.SetReadDeadline(t)  //nolint: errcheck
	st.SetWriteDeadline(t) //nolint: errcheck

	return nil
}

func (st *WebStream) SetReadDeadline(t time.Time) error {
	st.mu.Lock()
	st.readDeadline = t
	st.readTimer = st.armLocked(st.readTimer, t)
	st.mu.Unlock()

	return nil
}

func (st *WebStream) SetWriteDeadline(t time.Time) error {
	st.mu.Lock()
	st.writeDeadline = t
	st.writeTimer = st.armLocked(st.writeTimer, t)
	st.mu.Unlock()

	return nil
}

// armLocked wakes the stream's waiters when a deadline passes, so a blocked
// Read or Write sees it.
func (st *WebStream) armLocked(timer *time.Timer, t time.Time) *time.Timer {
	if timer != nil {
		timer.Stop()
	}

	if t.IsZero() {
		return nil
	}

	// Taking the lock first means a waiter is either before its deadline check,
	// and sees the deadline passed, or already waiting, and gets the broadcast.
	return time.AfterFunc(time.Until(t), func() {
		st.mu.Lock()
		st.mu.Unlock() //nolint: staticcheck // an empty critical section is the point
		st.cond.Broadcast()
	})
}
