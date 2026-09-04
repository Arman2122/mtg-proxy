package webrelay

import (
	"bufio"
	"net"
	"testing"
	"time"

	"github.com/pires/go-proxyproto"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type BackendTestSuite struct {
	suite.Suite

	listener net.Listener
	accepted chan net.Conn
}

func (suite *BackendTestSuite) SetupTest() {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	suite.Require().NoError(err)

	suite.listener = listener
	suite.accepted = make(chan net.Conn, 4)

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}

			suite.accepted <- conn
		}
	}()
}

func (suite *BackendTestSuite) TearDownTest() {
	suite.listener.Close()
}

func (suite *BackendTestSuite) accept() net.Conn {
	select {
	case conn := <-suite.accepted:
		return conn
	case <-time.After(5 * time.Second):
		suite.Require().Fail("nothing connected to the backend")

		return nil
	}
}

// Without the listener expecting one, a header would be read as the first bytes
// of the client's obfuscated handshake -- every stream dying at the same place,
// with nothing to see in a log.
func (suite *BackendTestSuite) TestNoHeaderWhenTheListenerExpectsNone() {
	backend, err := NewTCPBackend(suite.listener.Addr().String(), false, 0)
	suite.Require().NoError(err)

	client := &net.TCPAddr{IP: net.IPv4(203, 0, 113, 7), Port: 51000}

	conn, err := backend.Dial(suite.T().Context(), client)
	suite.Require().NoError(err)

	defer conn.Close()

	_, err = conn.Write([]byte("obfuscated"))
	suite.Require().NoError(err)

	server := suite.accept()
	defer server.Close()

	buf := make([]byte, len("obfuscated"))
	suite.Require().NoError(server.SetReadDeadline(time.Now().Add(5 * time.Second)))
	_, err = server.Read(buf)
	suite.Require().NoError(err)
	suite.Equal("obfuscated", string(buf))
}

func (suite *BackendTestSuite) TestHeaderCarriesTheBrowserAddress() {
	backend, err := NewTCPBackend(suite.listener.Addr().String(), true, 0)
	suite.Require().NoError(err)

	client := &net.TCPAddr{IP: net.IPv4(203, 0, 113, 7), Port: 51000}

	conn, err := backend.Dial(suite.T().Context(), client)
	suite.Require().NoError(err)

	defer conn.Close()

	server := suite.accept()
	defer server.Close()

	suite.Require().NoError(server.SetReadDeadline(time.Now().Add(5 * time.Second)))

	header, err := proxyproto.Read(bufio.NewReader(server))
	suite.Require().NoError(err)

	suite.Equal(byte(2), header.Version)
	suite.Equal(proxyproto.PROXY, header.Command)
	suite.Equal(proxyproto.TCPv4, header.TransportProtocol)
	suite.Equal("203.0.113.7:51000", header.SourceAddr.String())
}

// The two addresses in a PROXY header must share a family, and a browser on IPv6
// reaching an IPv4 loopback backend is the ordinary case rather than an exotic
// one. Handing the library a mismatched pair yields a well-formed LOCAL header
// that silently drops the client address -- the one thing this path carries.
func (suite *BackendTestSuite) TestAnIPv6ClientKeepsItsAddressAgainstAnIPv4Backend() {
	backend, err := NewTCPBackend(suite.listener.Addr().String(), true, 0)
	suite.Require().NoError(err)

	client := &net.TCPAddr{IP: net.ParseIP("2001:db8::1"), Port: 51000}

	conn, err := backend.Dial(suite.T().Context(), client)
	suite.Require().NoError(err)

	defer conn.Close()

	server := suite.accept()
	defer server.Close()

	suite.Require().NoError(server.SetReadDeadline(time.Now().Add(5 * time.Second)))

	header, err := proxyproto.Read(bufio.NewReader(server))
	suite.Require().NoError(err)

	suite.Equal(proxyproto.PROXY, header.Command, "a LOCAL header would have discarded the client")
	suite.Equal(proxyproto.TCPv6, header.TransportProtocol)
	suite.Equal("[2001:db8::1]:51000", header.SourceAddr.String())
}

func (suite *BackendTestSuite) TestAnUnknownClientAddressIsRefused() {
	backend, err := NewTCPBackend(suite.listener.Addr().String(), true, 0)
	suite.Require().NoError(err)

	_, err = backend.Dial(suite.T().Context(), nil)
	suite.Require().Error(err)
}

func (suite *BackendTestSuite) TestAnEmptyAddressIsRefusedAtStartup() {
	_, err := NewTCPBackend("", false, 0)
	suite.Require().ErrorIs(err, ErrNoBackendAddress)
}

func TestBackend(t *testing.T) {
	t.Parallel()
	suite.Run(t, &BackendTestSuite{})
}

// A dial that cannot connect must fail rather than hang: the stream-level CLOSE
// it produces is what keeps one dead backend from stalling a session.
func TestBackendDialFailureIsPrompt(t *testing.T) {
	t.Parallel()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	address := listener.Addr().String()
	require.NoError(t, listener.Close())

	backend, err := NewTCPBackend(address, false, 0)
	require.NoError(t, err)

	_, err = backend.Dial(t.Context(), &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1})
	require.Error(t, err)
}
