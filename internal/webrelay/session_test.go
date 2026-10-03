package webrelay

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Arman2122/mtg-proxy/internal/webrelay/frame"
	"github.com/Arman2122/mtg-proxy/internal/webrelay/ws"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

// testCarrier stands in for the WebSocket. Driving the session through one lets
// a test deliver a batch as a single indivisible message, which is what the
// atomicity rules are written about and what a real socket would let a test
// accidentally split.
type testCarrier struct {
	in   chan []byte
	out  chan []byte
	done chan struct{}

	mu        sync.Mutex
	closeCode uint16
	closed    bool

	// failWrites makes every write fail, as a socket whose peer has gone.
	failWrites atomic.Bool
}

func newTestCarrier() *testCarrier {
	return &testCarrier{in: make(chan []byte, 64), out: make(chan []byte, 256), done: make(chan struct{})}
}

// newSyncCarrier is the same carrier with no room to buffer, so a test that
// does not read is a client that is not draining. That is what lets the pending
// budget actually fill: with a buffered channel the write loop empties the
// outbox as fast as it is filled and the backpressure path never runs.
func newSyncCarrier() *testCarrier {
	return &testCarrier{in: make(chan []byte, 64), out: make(chan []byte), done: make(chan struct{})}
}

// Read returns the next message, or ErrClosed once the carrier is closed, as
// a socket's read fails when the socket is closed under it.
func (c *testCarrier) Read() ([]byte, error) {
	select {
	case message, ok := <-c.in:
		if !ok {
			return nil, ws.ErrClosed
		}

		return message, nil
	case <-c.done:
		return nil, ws.ErrClosed
	}
}

// WriteBuffers delivers the vectors as one message, as the WebSocket carrier
// sends them as one.
func (c *testCarrier) WriteBuffers(bufs [][]byte) error {
	c.mu.Lock()
	closed := c.closed
	c.mu.Unlock()

	if closed || c.failWrites.Load() {
		return net.ErrClosed
	}

	payload := bytes.Join(bufs, nil)

	// A real socket fails a blocked write when it is closed, and the session
	// joins its write loop before returning, so a carrier that could block for
	// ever here would hang shutdown rather than test it.
	select {
	case c.out <- payload:
		return nil
	case <-c.done:
		return net.ErrClosed
	}
}

func (c *testCarrier) Close(code uint16, _ string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.closed {
		c.closed = true
		c.closeCode = code
		close(c.done)
	}

	return nil
}

func (c *testCarrier) code() uint16 {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.closeCode
}

// pipeBackend hands every OPEN one end of a net.Pipe and gives the test the
// other. The pipe is unbuffered and synchronous, which is exactly the property
// the backpressure tests need: a test that simply does not read is a backend
// that is not draining.
type pipeBackend struct {
	conns chan net.Conn
	err   error
	mu    sync.Mutex
	dials int
}

func newPipeBackend() *pipeBackend {
	return &pipeBackend{conns: make(chan net.Conn, 16)}
}

func (b *pipeBackend) Dial(_ context.Context, _ net.Addr) (net.Conn, error) {
	b.mu.Lock()
	b.dials++
	b.mu.Unlock()

	if b.err != nil {
		return nil, b.err
	}

	relaySide, testSide := net.Pipe()
	b.conns <- testSide

	return relaySide, nil
}

func (b *pipeBackend) accept(t *testing.T) net.Conn {
	t.Helper()

	select {
	case conn := <-b.conns:
		return conn
	case <-time.After(5 * time.Second):
		t.Fatal("the relay never dialled the backend")

		return nil
	}
}

type harness struct {
	t       *testing.T
	carrier *testCarrier
	backend *pipeBackend
	session *session
	done    chan error
	frames  []frame.Frame
}

func newHarness(t *testing.T, opts SessionOptions) *harness {
	t.Helper()

	return newHarnessOn(t, newTestCarrier(), opts)
}

func newHarnessOn(t *testing.T, carrier *testCarrier, opts SessionOptions) *harness {
	t.Helper()

	backend := newPipeBackend()
	opts.Backend = backend

	h := &harness{t: t, carrier: carrier, backend: backend, done: make(chan error, 1)}
	h.session = newSession(carrier, opts)

	go func() {
		h.done <- h.session.Serve(t.Context())
	}()

	t.Cleanup(func() {
		close(carrier.in)

		select {
		case <-h.done:
		case <-time.After(5 * time.Second):
			t.Error("the session did not finish")
		}
	})

	return h
}

// send delivers one carrier message holding the whole batch.
func (h *harness) send(frames ...frame.Frame) {
	h.t.Helper()

	payload, err := frame.Limits{}.EncodeBatch(nil, frames, frame.ClientToRelay)
	require.NoError(h.t, err)

	h.carrier.in <- payload
}

// next returns the next frame the relay emitted, decoding batches as needed.
func (h *harness) next() frame.Frame {
	h.t.Helper()

	for len(h.frames) == 0 {
		select {
		case payload := <-h.carrier.out:
			decoded, err := frame.Limits{}.DecodeBatch(payload, frame.RelayToClient)
			require.NoError(h.t, err)

			h.frames = decoded
		case <-time.After(5 * time.Second):
			h.t.Fatal("the relay emitted nothing")
		}
	}

	next := h.frames[0]
	h.frames = h.frames[1:]

	return next
}

func (h *harness) nextOfType(t frame.Type) frame.Frame {
	h.t.Helper()

	for range 64 {
		if f := h.next(); f.Type == t {
			return f
		}
	}

	h.t.Fatalf("no %s frame arrived", t)

	return frame.Frame{}
}

// drain collects every frame the relay emits until it has been quiet for one
// interval. Ordering tests need the whole sequence, not the next frame.
func (h *harness) drain(quiet time.Duration) []frame.Frame {
	h.t.Helper()

	collected := h.frames
	h.frames = nil

	for {
		select {
		case payload := <-h.carrier.out:
			decoded, err := frame.Limits{}.DecodeBatch(payload, frame.RelayToClient)
			require.NoError(h.t, err)

			collected = append(collected, decoded...)
		case <-time.After(quiet):
			return collected
		}
	}
}

// fatal waits for the session to end and returns why.
func (h *harness) fatal() error {
	h.t.Helper()

	select {
	case err := <-h.done:
		h.done <- err

		return err
	case <-time.After(5 * time.Second):
		h.t.Fatal("the session stayed alive")

		return nil
	}
}

// quiet asserts the session is still running: nothing killed it.
func (h *harness) quiet() {
	h.t.Helper()

	select {
	case err := <-h.done:
		h.done <- err
		h.t.Fatalf("the session ended: %v", err)
	case <-time.After(200 * time.Millisecond):
	}
}

type SessionTestSuite struct {
	suite.Suite
}

// The first thing a real client does. OPEN has no acknowledgement, so DATA may
// ride in the same message -- and a validator that asks "is this stream live?"
// against current state alone rejects it.
func (suite *SessionTestSuite) TestOpenAndDataInOneBatch() {
	t := suite.T()
	h := newHarness(t, SessionOptions{})

	h.send(frame.NewOpen(17), frame.NewData(17, []byte("abc")))

	backend := h.backend.accept(t)

	buf := make([]byte, 3)
	require.NoError(t, backend.SetReadDeadline(time.Now().Add(5*time.Second)))
	_, err := io.ReadFull(backend, buf)
	suite.Require().NoError(err)
	suite.Equal("abc", string(buf))

	window := h.nextOfType(frame.TypeWindow)
	delta, ok := window.WindowDelta()
	suite.True(ok)
	suite.Equal(uint32(3), delta)
	suite.Equal(uint32(17), window.StreamID)
}

// The rule the whole two-pass design exists for: a batch that fails validation
// leaves nothing behind. The OPEN ahead of the bad frame must not have dialled.
func (suite *SessionTestSuite) TestARejectedBatchAppliesNothing() {
	t := suite.T()
	h := newHarness(t, SessionOptions{})

	h.send(
		frame.NewOpen(17),
		frame.NewData(17, []byte("ok")),
		frame.NewData(99, []byte("no such stream")),
	)

	suite.Require().ErrorIs(h.fatal(), ErrUnknownStream)

	h.backend.mu.Lock()
	defer h.backend.mu.Unlock()
	suite.Zero(h.backend.dials, "a rejected batch must not have opened a backend connection")
}

func (suite *SessionTestSuite) TestUnknownStreamIsFatal() {
	t := suite.T()
	h := newHarness(t, SessionOptions{})

	h.send(frame.NewData(17, []byte("x")))

	suite.Require().ErrorIs(h.fatal(), ErrUnknownStream)
	suite.Equal(ws.CloseProtocolError, h.carrier.code())
}

func (suite *SessionTestSuite) TestSecondHelloIsFatal() {
	t := suite.T()
	h := newHarness(t, SessionOptions{})

	h.send(frame.NewHello())

	suite.Require().ErrorIs(h.fatal(), ErrSecondHello)
}

// Ids are never reused inside a session, so an OPEN naming one that is live or
// recently closed is the peer contradicting itself.
func (suite *SessionTestSuite) TestReusedStreamIDIsFatal() {
	t := suite.T()
	h := newHarness(t, SessionOptions{})

	h.send(frame.NewOpen(17))
	h.backend.accept(t)
	h.send(frame.NewOpen(17))

	suite.Require().ErrorIs(h.fatal(), ErrStreamReused)
}

// The close race tombstones exist for: the client's last DATA and its own CLOSE
// cross on the wire. Killing the session over it would be a real outage caused
// by an ordinary event.
func (suite *SessionTestSuite) TestLateFramesForAClosedStreamAreIgnored() {
	t := suite.T()
	h := newHarness(t, SessionOptions{})

	h.send(frame.NewOpen(17))
	h.backend.accept(t)
	h.send(frame.NewClose(17))
	h.send(frame.NewData(17, []byte("late")), frame.NewWindow(17, 4096), frame.NewClose(17))

	h.quiet()
}

// A capacity refusal is stream-level, never session-level -- and the DATA that
// was already riding behind the refused OPEN has to become ignorable, or the
// refusal kills the session it was meant to protect.
func (suite *SessionTestSuite) TestARefusedOpenClosesOnlyThatStream() {
	t := suite.T()
	h := newHarness(t, SessionOptions{MaxStreams: 1})

	h.send(
		frame.NewOpen(1),
		frame.NewOpen(2),
		frame.NewData(2, []byte("refused")),
		frame.NewData(1, []byte("kept")),
	)

	closed := h.nextOfType(frame.TypeClose)
	suite.Equal(uint32(2), closed.StreamID)

	backend := h.backend.accept(t)
	buf := make([]byte, 4)
	require.NoError(t, backend.SetReadDeadline(time.Now().Add(5*time.Second)))
	_, err := io.ReadFull(backend, buf)
	suite.Require().NoError(err)
	suite.Equal("kept", string(buf))

	h.quiet()
}

// The load-bearing ordering rule. Credit is returned after the write to the
// backend socket returns -- not on receipt, not on enqueue -- so a backend that
// is not draining stops the client instead of growing a queue here.
func (suite *SessionTestSuite) TestWindowFollowsTheBackendWriteAndNotReceipt() {
	t := suite.T()
	h := newHarness(t, SessionOptions{})

	h.send(frame.NewOpen(17), frame.NewData(17, []byte("stalled")))

	backend := h.backend.accept(t)

	// The backend has not read a byte, so no credit may come back.
	select {
	case payload := <-h.carrier.out:
		t.Fatalf("credit was returned before the backend drained: %x", payload)
	case <-time.After(300 * time.Millisecond):
	}

	buf := make([]byte, 7)
	require.NoError(t, backend.SetReadDeadline(time.Now().Add(5*time.Second)))
	_, err := io.ReadFull(backend, buf)
	suite.Require().NoError(err)

	window := h.nextOfType(frame.TypeWindow)
	delta, _ := window.WindowDelta()
	suite.Equal(uint32(7), delta)
}

// A peer that spends more credit than it was granted has lost count, and from
// that point the two ends disagree about what is in flight.
func (suite *SessionTestSuite) TestDataBeyondTheWindowIsFatal() {
	t := suite.T()
	h := newHarness(t, SessionOptions{})

	h.send(frame.NewOpen(17))
	h.backend.accept(t)

	// The backend is never read, so nothing is ever refunded. A 1 MiB frame is
	// the largest one allowed and two of them plus their headers are past the
	// 2 MiB batch bound, so they go one per message: four spend the whole 4 MiB
	// window and the fifth is past it.
	chunk := make([]byte, 1<<20)

	for range 4 {
		h.send(frame.NewData(17, chunk))
	}

	h.send(frame.NewData(17, []byte("one byte too many")))

	suite.Require().ErrorIs(h.fatal(), ErrCreditExhausted)
}

// Relay-generated DATA is capped at 64 KiB whatever the frame limit allows,
// because both client IPC descriptions size their buffers for it.
func (suite *SessionTestSuite) TestDownlinkIsChunkedAtTheRelayLimit() {
	t := suite.T()
	h := newHarness(t, SessionOptions{})

	h.send(frame.NewOpen(17))
	backend := h.backend.accept(t)

	payload := make([]byte, 200<<10)
	for i := range payload {
		payload[i] = byte(i)
	}

	go func() {
		_, _ = backend.Write(payload)
		_ = backend.Close()
	}()

	var got []byte

	for {
		f := h.next()
		if f.Type == frame.TypeClose {
			break
		}

		suite.Require().Equal(frame.TypeData, f.Type)
		suite.LessOrEqual(len(f.Payload), frame.MaxRelayDataChunk)

		got = append(got, f.Payload...)
	}

	suite.Equal(payload, got)
}

// CLOSE is an abort, so a CLOSE that overtook the last DATA would truncate a
// Telegram response. The queue is ordered for exactly this reason.
func (suite *SessionTestSuite) TestBackendEOFDeliversTheTailBeforeClose() {
	t := suite.T()
	h := newHarness(t, SessionOptions{})

	h.send(frame.NewOpen(17))
	backend := h.backend.accept(t)

	go func() {
		_, _ = backend.Write([]byte("the tail"))
		_ = backend.Close()
	}()

	data := h.next()
	suite.Equal(frame.TypeData, data.Type)
	suite.Equal("the tail", string(data.Payload))

	closed := h.next()
	suite.Equal(frame.TypeClose, closed.Type)
	suite.Equal(uint32(17), closed.StreamID)
}

// The same ordering rule at the only moment it is actually hard to hold.
//
// TestBackendEOFDeliversTheTailBeforeClose passes on an empty queue, where
// every push succeeds immediately and any implementation looks correct. Here the
// session's pending budget is full, so the stream's downlink pump is parked
// inside PushData holding data the client has not seen -- and the stream is then
// killed from the uplink side. A CLOSE queued by that goroutine draws on the
// control reserve, never blocks, and so reaches the client first; the client
// tombstones the id, and the tail that arrives afterwards is discarded. It is a
// truncated Telegram response with nothing anywhere reporting an error.
func (suite *SessionTestSuite) TestACloseNeverOvertakesABlockedTail() {
	t := suite.T()

	// Room for three 64 KiB DATA frames beyond the control reserve, which is
	// enough for the fourth push to park. The item ceiling is deliberately not
	// the binding one.
	h := newHarnessOn(t, newSyncCarrier(), SessionOptions{
		PendingBytes: ControlReserveBytes + 200<<10,
		PendingItems: ControlReserveItems + 32,
	})

	h.send(frame.NewOpen(17), frame.NewData(17, []byte("q")))

	backend := h.backend.accept(t)

	// Nothing here ever reads the pipe, so the relay's uplink goroutine is
	// blocked writing that one byte -- and the downlink pump fills the queue
	// until PushData parks. Both goroutines are now stuck, which is the state
	// the ordering has to survive.
	go func() {
		_, _ = backend.Write(bytes.Repeat([]byte("x"), 512<<10))
	}()

	require.Eventually(t, func() bool {
		_, items := h.session.out.session.pending()

		return items >= 3
	}, 5*time.Second, 5*time.Millisecond, "the pending budget never filled")

	// Kill the backend. The uplink write fails first: that is the goroutine
	// that must not be the one to announce the close.
	require.NoError(t, backend.Close())

	frames := h.drain(500 * time.Millisecond)

	var (
		data   int
		closed = -1
	)

	for i, f := range frames {
		if f.StreamID != 17 {
			continue
		}

		switch f.Type { //nolint: exhaustive // only these two are ordered against each other
		case frame.TypeClose:
			closed = i
		case frame.TypeData:
			data++

			suite.Equal(-1, closed, "DATA for stream 17 arrived after its CLOSE")
		}
	}

	suite.NotEqual(-1, closed, "the stream was never closed")

	// Four means the queue really did fill: three parked plus the one the write
	// loop had already taken. A smaller number would make the assertion above
	// pass without the pressure it is written about ever existing.
	suite.GreaterOrEqual(data, 4, "the backend's data never reached the client")
}

// A dial that fails is a stream-level failure. The session and every other
// stream survive it.
func (suite *SessionTestSuite) TestADialFailureClosesOnlyThatStream() {
	t := suite.T()

	carrier := newTestCarrier()
	backend := newPipeBackend()
	backend.err = errors.New("connection refused")

	h := &harness{t: t, carrier: carrier, backend: backend, done: make(chan error, 1)}
	h.session = newSession(carrier, SessionOptions{Backend: backend})

	go func() { h.done <- h.session.Serve(t.Context()) }()

	t.Cleanup(func() {
		close(carrier.in)
		<-h.done
	})

	h.send(frame.NewOpen(17))

	closed := h.nextOfType(frame.TypeClose)
	suite.Equal(uint32(17), closed.StreamID)

	h.quiet()
}

// Granted credit is counted, not saturated: two ends that stop agreeing about
// the total have no way to discover it later.
func (suite *SessionTestSuite) TestWindowOverflowIsFatal() {
	t := suite.T()
	h := newHarness(t, SessionOptions{})

	h.send(frame.NewOpen(17))
	h.backend.accept(t)

	h.send(frame.NewWindow(17, ^uint32(0)))
	h.send(frame.NewWindow(17, ^uint32(0)))

	suite.Require().ErrorIs(h.fatal(), ErrWindowOverflow)
}

// v1 never emits PING, so a PONG answers nothing. Discarding it is cheaper than
// killing a client that probes liveness on its own.
func (suite *SessionTestSuite) TestPongIsDiscarded() {
	t := suite.T()
	h := newHarness(t, SessionOptions{})

	h.send(frame.NewPong([]byte("token")))
	h.quiet()
}

// A wakeup with nothing queued is plausible, and the specification does not say
// it is malformed.
func (suite *SessionTestSuite) TestAnEmptyMessageIsNotFatal() {
	t := suite.T()
	h := newHarness(t, SessionOptions{})

	h.carrier.in <- []byte{}
	h.quiet()
}

func TestSession(t *testing.T) {
	t.Parallel()
	suite.Run(t, &SessionTestSuite{})
}

// A client that stops granting credit must stop the relay reading its backend,
// so the backpressure reaches Telegram's side rather than this process's heap.
// The relay may emit exactly one window's worth and not one byte more.
func TestAStalledClientStopsBackendReads(t *testing.T) {
	t.Parallel()

	h := newHarness(t, SessionOptions{})

	h.send(frame.NewOpen(17))
	backend := h.backend.accept(t)

	written := make(chan int, 1)

	go func() {
		total := 0
		buf := make([]byte, 64<<10)

		for total < int(InitialWindow)+(1<<20) {
			n, err := backend.Write(buf)
			total += n

			if err != nil {
				break
			}
		}

		written <- total
	}()

	var delivered int

	for delivered < int(InitialWindow) {
		f := h.next()
		require.Equal(t, frame.TypeData, f.Type)

		delivered += len(f.Payload)
	}

	require.Equal(t, int(InitialWindow), delivered, "the relay spent exactly the initial window")

	// Nothing more may arrive: the client granted no further credit.
	select {
	case payload := <-h.carrier.out:
		t.Fatalf("the relay read past the window: %d bytes", len(payload))
	case <-time.After(300 * time.Millisecond):
	}

	// And the moment credit arrives, it resumes.
	h.send(frame.NewWindow(17, 64<<10))

	f := h.next()
	require.Equal(t, frame.TypeData, f.Type)
	require.NotEmpty(t, f.Payload)
}
