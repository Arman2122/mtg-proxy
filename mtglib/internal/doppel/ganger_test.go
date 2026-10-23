package doppel

import (
	"bytes"
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/Arman2122/mtg-proxy/essentials"
	"github.com/Arman2122/mtg-proxy/internal/testlib"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type GangerTestSuite struct {
	TLSServerTestSuite

	log *LoggerMock
	g   *Ganger
}

func (suite *GangerTestSuite) SetupTest() {
	suite.TLSServerTestSuite.SetupTest()

	suite.log = &LoggerMock{}
	suite.log.
		On("Info", mock.AnythingOfType("string")).
		Maybe()
	suite.log.
		On("WarningError", mock.AnythingOfType("string"), mock.Anything).
		Maybe()

	suite.g = NewGanger(suite.ctx, suite.network, suite.log, time.Hour, 1, suite.urls, true, ShapingRecord, false)
	suite.g.Run()
}

func (suite *GangerTestSuite) TearDownTest() {
	suite.g.Shutdown()

	suite.log.AssertExpectations(suite.T())
	suite.TLSServerTestSuite.TearDownTest()
}

func (suite *GangerTestSuite) TestNewConnAfterShutdown() {
	suite.g.Shutdown()
	connMock := &testlib.EssentialsConnMock{}

	_, err := suite.g.NewConn(connMock)
	suite.Error(err)
}

func (suite *GangerTestSuite) TestNewConnWhileRunning() {
	connMock := &testlib.EssentialsConnMock{}
	connMock.
		On("Write", mock.AnythingOfType("[]uint8")).
		Return(0, nil).
		Maybe()
	connMock.On("Close").
		Return(nil).
		Maybe()

	conn, err := suite.g.NewConn(connMock)
	suite.NoError(err)

	conn.Stop()
}

func (suite *GangerTestSuite) TestNewConnWriteProducesTLSRecords() {
	var (
		mu  sync.Mutex
		buf bytes.Buffer
	)

	connMock := &testlib.EssentialsConnMock{}
	connMock.On("Write", mock.AnythingOfType("[]uint8")).
		Run(func(args mock.Arguments) {
			mu.Lock()
			buf.Write(args.Get(0).([]byte))
			mu.Unlock()
		}).
		Return(0, nil).
		Maybe()
	connMock.On("Close").
		Return(nil).
		Maybe()

	conn, err := suite.g.NewConn(connMock)
	suite.NoError(err)

	payload := bytes.Repeat([]byte("x"), 512)
	_, err = conn.Write(payload)
	suite.NoError(err)

	time.Sleep(500 * time.Millisecond)
	conn.Stop()

	mu.Lock()
	written := buf.Bytes()
	mu.Unlock()

	suite.NotEmpty(written)
}

func TestGanger(t *testing.T) {
	t.Parallel()

	suite.Run(t, &GangerTestSuite{})
}

// A NewConn that gives up because the ganger is shutting down must leave the
// run loop nothing it can panic on. The run loop may already hold the request
// when the caller leaves, and it answers on the request's channel: when the
// caller closed that channel on its way out, the answer was a send on a closed
// channel, chosen at random against the context's end, and it panicked the run
// loop's goroutine -- which nothing recovers, so the whole process died during
// a graceful shutdown, before the proxy flushed its usage file. CI's race
// detector caught it on Linux in TestHandshakeIsSizedLikeTheNamedCoverSite.
func TestNewConnRacingShutdownNeverPanics(t *testing.T) {
	t.Parallel()

	for range 200 {
		g := NewGanger(context.Background(), nil, nil, time.Hour, 1, nil, false, ShapingRecord, false)
		g.Run()

		var callers sync.WaitGroup

		for range 8 {
			callers.Go(func() {
				client, server := net.Pipe()
				defer client.Close() //nolint: errcheck
				defer server.Close() //nolint: errcheck

				if conn, err := g.NewConn(essentials.WrapNetConn(server)); err == nil {
					conn.Stop()
				}
			})
		}

		g.Shutdown()
		callers.Wait()
	}
}

// Unpace takes the wait out from between records and nothing else: the record
// sizing is the ganger's own, so a DRS ganger still ramps up after it.
func TestGangerUnpace(t *testing.T) {
	t.Parallel()

	for _, drs := range []bool{false, true} {
		g := NewGanger(t.Context(), nil, nil, time.Hour, 1, nil, drs, ShapingRecord, false)
		g.Unpace()

		for range 1000 {
			require.Zero(t, g.stats.Delay())
		}

		assert.Equal(t, drs, g.stats.drs)
	}
}
