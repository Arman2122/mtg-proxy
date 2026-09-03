package mtglib

import (
	"errors"
	"net"
	"testing"

	"github.com/Arman2122/mtg-proxy/internal/testlib"
	"github.com/pires/go-proxyproto"
	"github.com/stretchr/testify/suite"
)

type ConnProxyProtocolFormatErrTestSuite struct {
	suite.Suite

	sourceConnMock *testlib.EssentialsConnMock
	targetConnMock *testlib.EssentialsConnMock
	conn           *connProxyProtocol
}

func (suite *ConnProxyProtocolFormatErrTestSuite) SetupTest() {
	suite.sourceConnMock = &testlib.EssentialsConnMock{}
	suite.targetConnMock = &testlib.EssentialsConnMock{}

	// 100000 is outside the uint16 a v2 PROXY header encodes a port in, so
	// Header.Format rejects the pair with ErrInvalidPortNumber. This is the
	// unformattable-address shape the fronting path must survive.
	suite.sourceConnMock.
		On("RemoteAddr").
		Return(&net.TCPAddr{IP: net.ParseIP("127.0.0.1").To4(), Port: 100000})
	suite.targetConnMock.
		On("RemoteAddr").
		Return(&net.TCPAddr{IP: net.ParseIP("127.0.0.2").To4(), Port: 443})

	suite.conn = newConnProxyProtocol(suite.sourceConnMock, suite.targetConnMock)
}

func (suite *ConnProxyProtocolFormatErrTestSuite) TearDownTest() {
	suite.sourceConnMock.AssertExpectations(suite.T())
	suite.targetConnMock.AssertExpectations(suite.T())
}

// A header that cannot be formatted must fail the connection, not the process.
// No Write expectation is registered on the target mock, so a payload leaking
// through to the wire fails the test too.
func (suite *ConnProxyProtocolFormatErrTestSuite) TestWriteReturnsErrorInsteadOfPanic() {
	suite.NotPanics(func() {
		n, err := suite.conn.Write([]byte{1, 2, 3, 4, 5})

		suite.Zero(n)
		suite.Require().Error(err)
		suite.True(errors.Is(err, proxyproto.ErrInvalidPortNumber))
	})
}

// A failed format must leave the flag down, so the header is not silently
// skipped if the caller retries.
func (suite *ConnProxyProtocolFormatErrTestSuite) TestHeadersNotMarkedWrittenOnFormatFailure() {
	suite.NotPanics(func() {
		_, _ = suite.conn.Write([]byte{1, 2, 3, 4, 5})
	})

	suite.False(suite.conn.headersWritten)
}

func TestConnProxyProtocolFormatErr(t *testing.T) {
	t.Parallel()
	suite.Run(t, &ConnProxyProtocolFormatErrTestSuite{})
}
