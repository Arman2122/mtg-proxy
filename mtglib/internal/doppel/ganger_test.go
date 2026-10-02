package doppel

import (
	"bytes"
	"sync"
	"testing"
	"time"

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

	suite.g = NewGanger(suite.ctx, suite.network, suite.log, time.Hour, 1, suite.urls, true, ShapingRecord)
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

// Unpace takes the wait out from between records and nothing else: the record
// sizing is the ganger's own, so a DRS ganger still ramps up after it.
func TestGangerUnpace(t *testing.T) {
	t.Parallel()

	for _, drs := range []bool{false, true} {
		g := NewGanger(t.Context(), nil, nil, time.Hour, 1, nil, drs, ShapingRecord)
		g.Unpace()

		for range 1000 {
			require.Zero(t, g.stats.Delay())
		}

		assert.Equal(t, drs, g.stats.drs)
	}
}
