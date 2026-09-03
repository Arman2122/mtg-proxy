package obfuscation

import (
	"crypto/aes"
	"crypto/cipher"
	"io"
	"testing"

	"github.com/Arman2122/mtg-proxy/internal/testlib"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type ConnReadErrorTestSuite struct {
	suite.Suite

	secret []byte
	iv     []byte
}

func (s *ConnReadErrorTestSuite) SetupSuite() {
	s.secret = []byte("0123456789abcdef0123456789abcdef")
	s.iv = []byte("fedcba9876543210")
}

// io.Reader may return n > 0 alongside an error, and io.CopyBuffer forwards
// those n bytes. A *tls.Conn happens to return (0, err) on record errors, which
// masks the bug today, so it has to be provoked with a raw conn.
func (s *ConnReadErrorTestSuite) TestReadDecryptsBytesReturnedWithError() {
	plaintext := []byte("relayed before the error")

	connMock := &testlib.EssentialsConnMock{}
	connMock.
		On("Read", mock.AnythingOfType("[]uint8")).
		Once().
		Return(len(plaintext), io.ErrUnexpectedEOF).
		Run(func(args mock.Arguments) {
			copy(args.Get(0).([]byte), plaintext)
		})

	testConn := s.makeConn(connMock)

	buf := make([]byte, 64)
	n, err := testConn.Read(buf)

	require.Equal(s.T(), len(plaintext), n)
	require.ErrorIs(s.T(), err, io.ErrUnexpectedEOF, "underlying error must survive")
	assert.Equal(s.T(), s.reference(plaintext), buf[:n])

	connMock.AssertExpectations(s.T())
}

// The keystream has to advance by exactly n even on the error path, otherwise
// the next read decrypts at offset 0 instead of n. This is the realistic shape:
// a read deadline fires with partial data, the caller retries.
func (s *ConnReadErrorTestSuite) TestReadKeepsStreamAlignedAcrossError() {
	first := []byte("partial data then a timeout")
	second := []byte("the rest of the stream arrives later")

	connMock := &testlib.EssentialsConnMock{}
	connMock.
		On("Read", mock.AnythingOfType("[]uint8")).
		Once().
		Return(len(first), io.ErrUnexpectedEOF).
		Run(func(args mock.Arguments) {
			copy(args.Get(0).([]byte), first)
		})
	connMock.
		On("Read", mock.AnythingOfType("[]uint8")).
		Once().
		Return(len(second), nil).
		Run(func(args mock.Arguments) {
			copy(args.Get(0).([]byte), second)
		})

	testConn := s.makeConn(connMock)
	buf := make([]byte, 64)

	got := []byte{}

	n, err := testConn.Read(buf)
	require.Error(s.T(), err)
	got = append(got, buf[:n]...)

	n, err = testConn.Read(buf)
	require.NoError(s.T(), err)
	got = append(got, buf[:n]...)

	assert.Equal(s.T(), s.reference(append(append([]byte{}, first...), second...)), got)

	connMock.AssertExpectations(s.T())
}

// reference decrypts with an independently constructed stream at offset 0.
func (s *ConnReadErrorTestSuite) reference(plaintext []byte) []byte {
	block, err := aes.NewCipher(s.secret)
	require.NoError(s.T(), err)

	out := make([]byte, len(plaintext))
	cipher.NewCTR(block, s.iv).XORKeyStream(out, plaintext)

	return out
}

func (s *ConnReadErrorTestSuite) makeConn(rawConn *testlib.EssentialsConnMock) conn {
	rblock, err := aes.NewCipher(s.secret)
	require.NoError(s.T(), err)

	wblock, err := aes.NewCipher(s.secret)
	require.NoError(s.T(), err)

	return conn{
		Conn:       rawConn,
		sendCipher: cipher.NewCTR(wblock, s.iv),
		recvCipher: cipher.NewCTR(rblock, s.iv),
	}
}

func TestConnReadError(t *testing.T) {
	t.Parallel()
	suite.Run(t, &ConnReadErrorTestSuite{})
}
