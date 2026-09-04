package fake_test

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/Arman2122/mtg-proxy/mtglib"
	"github.com/Arman2122/mtg-proxy/mtglib/internal/tls"
	"github.com/Arman2122/mtg-proxy/mtglib/internal/tls/fake"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// makeRecord wraps payload into a TLS handshake record. length overrides the
// length field so a lying header can be built.
func makeRecord(payload []byte, length uint16) []byte {
	buf := &bytes.Buffer{}
	buf.Write([]byte{tls.TypeHandshake, 3, 1})
	binary.Write(buf, binary.BigEndian, length) //nolint:errcheck
	buf.Write(payload)

	return buf.Bytes()
}

func readOversized(t *testing.T, data []byte) (int, error) {
	t.Helper()

	secret, err := mtglib.ParseSecret(
		"ee367a189aee18fa31c190054efd4a8e9573746f726167652e676f6f676c65617069732e636f6d",
	)
	require.NoError(t, err)

	readBuf := bytes.NewBuffer(data)
	connMock := &parseClientHelloConnMock{readBuf: readBuf}

	defer connMock.AssertExpectations(t)

	_, err = fake.ReadClientHello(connMock, secret.Key[:], secret.Host, TolerateTime)

	return len(data) - readBuf.Len(), err
}

// A 24-bit handshake length no ClientHello can have must be refused before it
// is allowed to drive io.CopyN into the two in-memory copies.
func TestClientHelloLengthIsBounded(t *testing.T) {
	t.Parallel()

	wire := &bytes.Buffer{}
	// handshake type + 24-bit length of 0xFFFFFF (16 MiB)
	wire.Write(makeRecord([]byte{0x01, 0xFF, 0xFF, 0xFF}, 4))

	junk := make([]byte, tls.MaxRecordSize)
	for range 20 {
		wire.Write(makeRecord(junk, tls.MaxRecordSize))
	}

	consumed, err := readOversized(t, wire.Bytes())

	// only the first record: 5 byte record header + 4 byte handshake header.
	// Asserted before the error so a regression reports the buffering, which
	// is the point of the bound, and not just the missing sentinel.
	assert.Equal(t, 9, consumed)
	require.ErrorIs(t, err, fake.ErrHelloTooLarge)
}

// A record fragment larger than RFC 5246's 2^14 is refused before io.CopyN
// buffers it -- the first fragment is read before any handshake length is
// visible, so this is the only bound on it.
func TestRecordPayloadIsBounded(t *testing.T) {
	t.Parallel()

	wire := &bytes.Buffer{}
	wire.Write(makeRecord(nil, 0xFFFF))
	wire.Write(make([]byte, 0xFFFF))

	consumed, err := readOversized(t, wire.Bytes())

	assert.Equal(t, tls.SizeHeader, consumed)
	require.ErrorIs(t, err, fake.ErrRecordTooLarge)
}

// The record bound sits on 2^14 (RFC 5246 6.2.1). The HELLO bound does not: a
// handshake message may span fragments, so it sits at 65531, the last length
// for which uint16(1+3+length) does not wrap. Rejecting a spanning hello any
// earlier than a wrong secret is rejected would front the two to different
// hosts and hand a prober a distinguisher.
//
// One byte below each bound is legal wire and has to keep parsing; one byte
// above is refused.
func TestSizeBoundaries(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name     string
		data     []byte
		rejected bool
	}{
		{
			// 65531 = 0x00fffb, the largest length uint16(1+3+length) holds.
			name:     "hello at the limit",
			data:     makeRecord([]byte{0x01, 0x00, 0xff, 0xfb}, 4),
			rejected: false,
		},
		{
			name:     "hello one byte over",
			data:     makeRecord([]byte{0x01, 0x00, 0xff, 0xfc}, 4),
			rejected: true,
		},
		{
			// Spanning one record is legal framing and must reach the digest
			// check, not a size refusal -- this is the parity case.
			name:     "hello larger than one record",
			data:     makeRecord([]byte{0x01, 0x00, 0x40, 0x01}, 4),
			rejected: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := readOversized(t, tc.data)

			require.Error(t, err)

			if tc.rejected {
				assert.ErrorIs(t, err, fake.ErrHelloTooLarge)
			} else {
				assert.NotErrorIs(t, err, fake.ErrHelloTooLarge)
			}
		})
	}

	for _, tc := range []struct {
		name     string
		length   uint16
		rejected bool
	}{
		{name: "record at the limit", length: tls.MaxRecordSize, rejected: false},
		{name: "record one byte over", length: tls.MaxRecordSize + 1, rejected: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			data := makeRecord(make([]byte, tc.length), tc.length)

			_, err := readOversized(t, data)

			require.Error(t, err)

			if tc.rejected {
				assert.ErrorIs(t, err, fake.ErrRecordTooLarge)
			} else {
				assert.NotErrorIs(t, err, fake.ErrRecordTooLarge)
			}
		})
	}
}
