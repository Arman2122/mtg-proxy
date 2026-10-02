package tls

import (
	"bytes"
	"io"
	"testing"

	"github.com/Arman2122/mtg-proxy/essentials"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// streamConn is an essentials.Conn that serves a fixed byte stream, as many
// bytes per Read as asked, and allocates nothing. Anything else panics
// through the nil embedded interface.
type streamConn struct {
	essentials.Conn

	r *bytes.Reader
}

func (s streamConn) Read(p []byte) (int, error) { return s.r.Read(p) } //nolint: wrapcheck

func streamOf(parts ...[]byte) streamConn {
	return streamConn{r: bytes.NewReader(bytes.Join(parts, nil))}
}

func payloadOf(size int, seed byte) []byte {
	out := make([]byte, size)
	for i := range out {
		out[i] = seed + byte(i)
	}

	return out
}

// readAll reads conn to EOF in pieces of size bytes, failing if any Read
// returns no bytes and no error.
func readAll(t *testing.T, conn Conn, size int) []byte {
	t.Helper()

	var out bytes.Buffer

	buf := make([]byte, size)

	for {
		n, err := conn.Read(buf)
		out.Write(buf[:n])

		if err != nil {
			require.ErrorIs(t, err, io.EOF)

			return out.Bytes()
		}

		require.Positive(t, n, "a Read with no error must carry bytes")
	}
}

// Records already buffered are taken together: one Read, several records.
func TestConnReadSpansRecords(t *testing.T) {
	t.Parallel()

	first, second := payloadOf(100, 1), payloadOf(200, 2)
	conn := New(streamOf(MakeTLSRecord(TypeApplicationData, first), MakeTLSRecord(TypeApplicationData, second)), true, false)

	buf := make([]byte, 1024)

	n, err := conn.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, append(first, second...), buf[:n], "both buffered records must arrive in one Read")
}

func TestConnReadOneByteAtATime(t *testing.T) {
	t.Parallel()

	payloads := [][]byte{payloadOf(7, 3), payloadOf(50, 4), payloadOf(1000, 5)}
	conn := New(streamOf(
		MakeTLSRecord(TypeApplicationData, payloads[0]),
		MakeTLSRecord(TypeApplicationData, payloads[1]),
		MakeTLSRecord(TypeApplicationData, payloads[2]),
	), true, false)

	assert.Equal(t, bytes.Join(payloads, nil), readAll(t, conn, 1))
}

func TestConnReadSkipsRecordsThatCarryNoData(t *testing.T) {
	t.Parallel()

	first, second := payloadOf(300, 6), payloadOf(40, 7)

	for _, size := range []int{1, 3, 17, 4096} {
		conn := New(streamOf(
			MakeTLSRecord(TypeApplicationData, first),
			MakeTLSRecord(TypeChangeCipherSpec, []byte{1}),
			MakeTLSRecord(TypeApplicationData, nil),
			MakeTLSRecord(TypeApplicationData, second),
		), true, false)

		assert.Equal(t, append(first, second...), readAll(t, conn, size),
			"only application data reaches the reader (read size %d)", size)
	}
}

func TestConnReadRejectsWrongVersion(t *testing.T) {
	t.Parallel()

	record := MakeTLSRecord(TypeApplicationData, payloadOf(10, 8))
	record[2] = 1 // 03 01

	_, err := New(streamOf(record), true, false).Read(make([]byte, 64))
	require.ErrorContains(t, err, "incorrect tls version")
}

// Not parallel: AllocsPerRun counts every allocation in the process.
func TestConnReadAllocatesNothing(t *testing.T) { //nolint: paralleltest
	const size = 1 << 14

	records := make([][]byte, 0, 102)
	for range 102 {
		records = append(records, MakeTLSRecord(TypeApplicationData, payloadOf(size, 9)))
	}

	// Boxed into the interface once, as the proxy holds it: converting the
	// Conn value on every call would be the test's allocation, not Read's.
	var conn io.Reader = New(streamOf(records...), true, false)

	buf := make([]byte, size)

	_, err := io.ReadFull(conn, buf) // the reader's buffer is made on first use
	require.NoError(t, err)

	allocs := testing.AllocsPerRun(100, func() {
		if _, err := io.ReadFull(conn, buf); err != nil {
			panic(err)
		}
	})
	assert.Zero(t, allocs, "reading a record must not allocate")
}
