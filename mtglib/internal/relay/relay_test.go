package relay_test

import (
	"context"
	"io"
	"testing"

	"github.com/Arman2122/mtg-proxy/internal/testlib"
	"github.com/Arman2122/mtg-proxy/mtglib/internal/relay"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"
)

type RelayTestSuite struct {
	suite.Suite

	loggerMock       relay.Logger
	ctx              context.Context
	ctxCancel        context.CancelFunc
	telegramConnMock *testlib.EssentialsConnMock
	clientConnMock   *testlib.EssentialsConnMock
}

func (suite *RelayTestSuite) SetupTest() {
	ctx, cancel := context.WithCancel(context.Background())
	suite.ctx = ctx
	suite.ctxCancel = cancel
	suite.loggerMock = &loggerMock{}
	suite.telegramConnMock = &testlib.EssentialsConnMock{}
	suite.clientConnMock = &testlib.EssentialsConnMock{}
}

func (suite *RelayTestSuite) TearDownTest() {
	suite.ctxCancel()
	suite.telegramConnMock.AssertExpectations(suite.T())
	suite.clientConnMock.AssertExpectations(suite.T())
}

// Both sides end at once. Which direction finishes first is a race, and only
// a direction that finishes before the stream is torn down closes its
// destination's write side, so each CloseWrite is "maybe". CloseRead is never
// used: the stream ends whole. relay_close_test.go pins the real contract on
// real sockets; this only proves the relay returns and closes both conns.
func (suite *RelayTestSuite) TestExit() {
	suite.telegramConnMock.On("Close").Return(nil)
	suite.telegramConnMock.On("CloseWrite").Return(nil).Maybe()
	suite.telegramConnMock.On("Read", mock.Anything).Return(10, io.EOF).Once()
	suite.telegramConnMock.On("Write", mock.Anything).Return(10, io.EOF).Maybe()

	suite.clientConnMock.On("Read", mock.Anything).Return(0, io.EOF).Once()
	suite.clientConnMock.On("Write", mock.Anything).Return(10, io.EOF).Maybe()
	suite.clientConnMock.On("Close").Return(nil)
	suite.clientConnMock.On("CloseWrite").Return(nil).Maybe()

	relay.Relay(suite.ctx, suite.loggerMock, suite.telegramConnMock, suite.clientConnMock)
}

func TestRelay(t *testing.T) {
	t.Parallel()
	suite.Run(t, &RelayTestSuite{})
}
