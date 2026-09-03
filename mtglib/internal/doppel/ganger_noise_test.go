package doppel

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/Arman2122/mtg-proxy/mtglib/internal/tls"
	"github.com/Arman2122/mtg-proxy/mtglib/internal/tls/fake"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"
)

type NoiseParamsTestSuite struct {
	suite.Suite

	log    *LoggerMock
	g      *Ganger
	hello  *fake.ClientHello
	secret []byte
}

func (suite *NoiseParamsTestSuite) SetupTest() {
	suite.log = &LoggerMock{}
	suite.log.
		On("Info", mock.AnythingOfType("string")).
		Maybe()

	suite.g = &Ganger{logger: suite.log}

	suite.hello = &fake.ClientHello{
		CipherSuite: 4867,
		SessionID:   make([]byte, 32),
	}

	_, err := rand.Read(suite.hello.SessionID)
	suite.NoError(err)

	_, err = rand.Read(suite.hello.Random[:])
	suite.NoError(err)

	suite.secret = make([]byte, 32)

	_, err = rand.Read(suite.secret)
	suite.NoError(err)
}

func (suite *NoiseParamsTestSuite) TearDownTest() {
	suite.log.AssertExpectations(suite.T())
}

// assertServerHelloRecords sends a ServerHello with the given params and
// verifies the client sees all three records it computes the HMAC over.
func (suite *NoiseParamsTestSuite) assertServerHelloRecords(params NoiseParams) {
	suite.T().Helper()

	noise := fake.NoiseParams{Mean: params.Mean, Jitter: params.Jitter}

	for range 64 {
		buf := &bytes.Buffer{}

		suite.NoError(fake.SendServerHello(buf, suite.secret, suite.hello, noise))

		var rec bytes.Buffer

		recordType, _, err := tls.ReadRecord(buf, &rec)
		suite.Require().NoError(err)
		suite.Equal(byte(tls.TypeHandshake), recordType)

		rec.Reset()

		recordType, _, err = tls.ReadRecord(buf, &rec)
		suite.Require().NoError(err)
		suite.Equal(byte(tls.TypeChangeCipherSpec), recordType)

		rec.Reset()

		recordType, length, err := tls.ReadRecord(buf, &rec)
		suite.Require().NoError(err)
		suite.Equal(byte(tls.TypeApplicationData), recordType)
		suite.LessOrEqual(length, int64(tls.MaxRecordPayloadSize))

		suite.Empty(buf.Bytes())
	}
}

func (suite *NoiseParamsTestSuite) TestOversizedMeanFitsSingleRecord() {
	suite.g.certSizes = []int{17000, 17000, 17000}
	suite.g.updateNoiseParams()

	params := suite.g.NoiseParams()
	suite.Positive(params.Mean)
	suite.LessOrEqual(params.Mean+params.Jitter, tls.MaxRecordPayloadSize)

	suite.assertServerHelloRecords(params)
}

func (suite *NoiseParamsTestSuite) TestOversizedJitterFitsSingleRecord() {
	suite.g.certSizes = []int{1000, 30000, 1000}
	suite.g.updateNoiseParams()

	params := suite.g.NoiseParams()
	suite.Positive(params.Mean)
	suite.Positive(params.Jitter)
	suite.LessOrEqual(params.Mean+params.Jitter, tls.MaxRecordPayloadSize)

	suite.assertServerHelloRecords(params)
}

func (suite *NoiseParamsTestSuite) TestRealisticSizesAreNotClamped() {
	suite.g.certSizes = []int{4000, 4100, 4200}
	suite.g.updateNoiseParams()

	params := suite.g.NoiseParams()
	suite.Equal(4100, params.Mean)
	suite.Equal(100, params.Jitter)

	suite.assertServerHelloRecords(params)
}

func TestNoiseParams(t *testing.T) {
	t.Parallel()

	suite.Run(t, &NoiseParamsTestSuite{})
}
