package middleproxy

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// feedConn serves the chunks sent on feed and blocks, as a socket does, when
// none is waiting; closing feed is EOF.
type feedConn struct {
	captureConn

	feed chan []byte
	rest []byte
}

func (f *feedConn) Read(p []byte) (int, error) {
	if len(f.rest) == 0 {
		chunk, ok := <-f.feed
		if !ok {
			return 0, io.EOF
		}

		f.rest = chunk
	}

	n := copy(p, f.rest)
	f.rest = f.rest[n:]

	return n, nil
}

func proxyAnswer(payload []byte) []byte {
	ans := append(append(append([]byte{}, tagProxyAns...), 0, 0, 0, 0), goldenConnID[:]...)

	return append(ans, payload...)
}

// A frame whose last AES block has only partly arrived is not buffered: it
// cannot be decrypted yet, so a Read that already holds the frame before it
// must return what it holds instead of waiting for the rest of that block.
func TestMiddleConnReadDoesNotWaitOnAPartialBlock(t *testing.T) {
	t.Parallel()

	wire := &bytes.Buffer{}
	_, _, peerEnc, _ := fixedCiphers()
	peer := newFrameConn(newCBCConn(wire, peerEnc, nil), 0)

	// A: a 100-byte answer, a 128-byte frame -- exactly eight blocks.
	// B: an 8-byte answer, a 36-byte frame padded to 48.
	require.NoError(t, peer.writePacket(proxyAnswer(bytes.Repeat([]byte{0xa1}, 100))))
	require.NoError(t, peer.writePacket(proxyAnswer(bytes.Repeat([]byte{0xb2}, 8))))
	require.Equal(t, 128+48, wire.Len())

	raw := &feedConn{feed: make(chan []byte, 2)}
	t.Cleanup(func() { close(raw.feed) })

	raw.feed <- wire.Bytes()[:128+36] // A whole, B up to inside its last block

	enc, dec, _, _ := fixedCiphers()
	m := goldenMiddleConn(raw, enc, dec, true)

	got := make(chan int, 1)

	go func() {
		n, _ := m.Read(make([]byte, 16<<10))
		got <- n
	}()

	select {
	case n := <-got:
		assert.Equal(t, 4+100, n, "the whole of A must come back, and nothing of B")
	case <-time.After(time.Second):
		t.Fatal("Read held A's bytes while waiting for the rest of B's last block")
	}
}

// A large frame passes through without its size staying on the connection:
// buffers that grew past keepBufferMax for one frame are let go, so a media
// download does not leave every connection holding a megabyte for the rest of
// its life.
func TestMiddleConnLetsGoOfLargeBuffers(t *testing.T) {
	t.Parallel()

	wire := &bytes.Buffer{}
	_, _, peerEnc, _ := fixedCiphers()
	peer := newFrameConn(newCBCConn(wire, peerEnc, nil), 0)

	require.NoError(t, peer.writePacket(proxyAnswer(make([]byte, 1<<20))))
	require.NoError(t, peer.writePacket(proxyAnswer(make([]byte, 200))))

	raw := &captureConn{}
	raw.buf.Write(wire.Bytes())

	enc, dec, _, _ := fixedCiphers()
	m := goldenMiddleConn(raw, enc, dec, true)

	_, err := io.ReadFull(m, make([]byte, 4+1<<20+4+200))
	require.NoError(t, err)
	assert.LessOrEqual(t, cap(m.frame.body), keepBufferMax, "a large answer must not leave its size behind")

	// Upload: a 512 KiB packet, written in one go, then a small one.
	big := binary.LittleEndian.AppendUint32(nil, 512<<10)
	big = append(big, make([]byte, 512<<10)...)
	_, err = m.Write(big)
	require.NoError(t, err)

	_, err = m.Write(binary.LittleEndian.AppendUint32(nil, 8))
	require.NoError(t, err)
	_, err = m.Write(make([]byte, 8))
	require.NoError(t, err)

	assert.LessOrEqual(t, cap(m.wbuf), keepBufferMax, "a large upload must not leave its size behind")
	assert.LessOrEqual(t, cap(m.inbuf), keepBufferMax, "nor the client stream buffer")
}
