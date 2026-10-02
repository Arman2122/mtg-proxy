package middleproxy

import (
	"bytes"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// readCounter serves a fixed byte stream and counts the Read calls made on it:
// each one is a read system call on a real socket.
type readCounter struct {
	captureConn

	reads int
}

func (r *readCounter) Read(p []byte) (int, error) {
	r.reads++

	return r.captureConn.Read(p)
}

// answersWire is what a middle proxy sends for count RPC_PROXY_ANS of size
// bytes each, encrypted with the peer's chain.
func answersWire(t *testing.T, count, size int) []byte {
	t.Helper()

	buf := &bytes.Buffer{}
	_, _, peerEnc, _ := fixedCiphers()
	peer := newFrameConn(newCBCConn(buf, peerEnc, nil), 0)

	ans := append(append(append([]byte{}, tagProxyAns...), 0, 0, 0, 0), goldenConnID[:]...)
	ans = append(ans, bytes.Repeat([]byte{0x77}, size)...)

	for range count {
		require.NoError(t, peer.writePacket(ans))
	}

	return buf.Bytes()
}

// The download reads the socket in bulk: a megabyte of 16 KiB answers takes a
// few dozen reads, not one per 16-byte AES block. Not parallel: AllocsPerRun
// counts every allocation in the process.
func TestMiddleConnDownloadReadsInBulk(t *testing.T) { //nolint: paralleltest
	const size = 16 << 10

	raw := &readCounter{}
	raw.buf.Write(answersWire(t, 64, size))

	enc, dec, _, _ := fixedCiphers()
	m := goldenMiddleConn(raw, enc, dec, true)

	packet := make([]byte, 4+size)

	for range 64 {
		_, err := io.ReadFull(m, packet)
		require.NoError(t, err)
	}

	assert.Less(t, raw.reads, 80, "a MiB of 16 KiB answers must take a few dozen reads, not one per AES block")

	// Steady state: once its buffers exist, reading a packet allocates nothing
	// more than the odd buffer growth.
	steady := &readCounter{}
	steady.buf.Write(answersWire(t, 202, size))

	enc, dec, _, _ = fixedCiphers()
	m = goldenMiddleConn(steady, enc, dec, true)

	allocs := testing.AllocsPerRun(200, func() {
		if _, err := io.ReadFull(m, packet); err != nil {
			panic(err)
		}
	})
	assert.LessOrEqual(t, allocs, 1.0, "reading a packet must not allocate per block or per packet")
}
