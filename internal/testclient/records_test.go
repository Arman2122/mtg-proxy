package testclient

import (
	"bytes"
	"crypto/rand"
	"io"
	"net"
	"testing"

	"github.com/Arman2122/mtg-proxy/essentials"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// What goes through NewRecordConn arrives byte-exact, in records no larger than
// the proxy itself writes, and the reading side skips records that carry no
// application data.
func TestRecordConnRoundTrip(t *testing.T) {
	t.Parallel()

	near, far := net.Pipe()
	t.Cleanup(func() {
		near.Close() //nolint: errcheck
		far.Close()  //nolint: errcheck
	})

	conn := NewRecordConn(essentials.WrapNetConn(near))

	sent := make([]byte, 100<<10)
	_, err := rand.Read(sent)
	require.NoError(t, err)

	go func() {
		_, err := conn.Write(sent)
		assert.NoError(t, err)
	}()

	var got bytes.Buffer

	for got.Len() < len(sent) {
		record, err := ReadRecord(far)
		require.NoError(t, err)
		require.EqualValues(t, TypeApplicationData, record.Type)
		require.LessOrEqual(t, len(record.Payload), MaxRecordPayload)
		got.Write(record.Payload)
	}

	assert.Equal(t, sent, got.Bytes(), "what was written must arrive, in records")

	answer := []byte("the answer, after a change-cipher-spec record")

	go func() {
		_, err := far.Write(append([]byte{TypeChangeCipherSpec, 3, 3, 0, 1, 1}, ApplicationRecord(answer)...))
		assert.NoError(t, err)
	}()

	read := make([]byte, len(answer))
	_, err = io.ReadFull(conn, read)
	require.NoError(t, err)
	assert.Equal(t, answer, read, "a record with no application data is skipped")
}

func TestReadServerFlightNeedsThreeRecords(t *testing.T) {
	t.Parallel()

	two := append(ApplicationRecord([]byte("hello")), ApplicationRecord([]byte("ccs"))...)
	_, _, err := ReadServerFlight(bytes.NewReader(two))
	require.Error(t, err, "two records are not a flight")

	three := append(two, ApplicationRecord([]byte("noise"))...)
	records, flight, err := ReadServerFlight(bytes.NewReader(three))
	require.NoError(t, err)
	assert.Len(t, records, 3)
	assert.Equal(t, three, flight, "the flight is the records' bytes, in order")
}

// A header declaring more than a record may carry is named, not read: it is how
// a stream that is not a TLS record layer shows up.
func TestReadRecordRefusesAnImpossibleLength(t *testing.T) {
	t.Parallel()

	_, err := ReadRecord(bytes.NewReader([]byte{TypeApplicationData, 3, 3, 0xff, 0xff}))
	require.ErrorContains(t, err, "not a TLS record layer")
}
