package ws

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

// One message written as vectors is, on the wire, the message Write sends:
// the relay sends its batches this way, with no buffer joining them first.
func TestWriteBuffersSendsWhatWriteSends(t *testing.T) {
	t.Parallel()

	piece := func(n int, b byte) []byte { return bytes.Repeat([]byte{b}, n) }

	many := make([][]byte, 300)
	for i := range many {
		many[i] = piece(300, byte(i))
	}

	for name, bufs := range map[string][][]byte{
		"one short slice":                      {piece(10, 1)},
		"16-bit length, an empty slice inside": {piece(100, 2), {}, piece(200, 3)},
		"64-bit length, 300 slices":            many,
		"nothing at all":                       {},
	} {
		vectored, conn := connOver(nil, Options{})
		require.NoError(t, vectored.WriteBuffers(bufs), name)

		joined, reference := connOver(nil, Options{})
		require.NoError(t, joined.Write(bytes.Join(bufs, nil)), name)

		require.Equal(t, reference.out.Bytes(), conn.out.Bytes(), name)
	}
}
