package middleproxy

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The request header is the same size for every packet; maxClientPacket is
// derived from it, so it must not drift.
func TestRequestHeaderLength(t *testing.T) {
	t.Parallel()

	enc, dec, _, _ := fixedCiphers()
	m := goldenMiddleConn(&captureConn{}, enc, dec, false)

	assert.Len(t, m.header(nil, false), reqHeaderLength)
}

// A client that declares a packet over the cap is refused on its header: the
// write fails, nothing it sent stays buffered and nothing reaches the middle
// proxy.
func TestMiddleConnRefusesOverCapPacket(t *testing.T) {
	t.Parallel()

	overCap := binary.LittleEndian.AppendUint32(nil, maxClientPacket+1)

	cases := map[string][][]byte{
		"header":          {overCap},
		"quick ack":       {binary.LittleEndian.AppendUint32(nil, quickAckLength|(maxClientPacket+1))},
		"largest length":  {binary.LittleEndian.AppendUint32(nil, quickAckLength-1)},
		"header and body": {append(bytes.Clone(overCap), make([]byte, 1000)...)},
		"split header":    {overCap[:2], overCap[2:]},
	}

	for name, writes := range cases {
		for _, padded := range []bool{false, true} {
			t.Run(name+"/"+transportName(padded), func(t *testing.T) {
				t.Parallel()

				raw := &captureConn{}
				enc, dec, _, _ := fixedCiphers()
				m := goldenMiddleConn(raw, enc, dec, padded)

				last := len(writes) - 1
				for _, p := range writes[:last] {
					_, err := m.Write(p)
					require.NoError(t, err)
				}

				_, err := m.Write(writes[last])
				require.ErrorIs(t, err, errPacketTooLarge)

				assert.Empty(t, m.inbuf, "the refused stream must not stay buffered")
				assert.Zero(t, raw.buf.Len(), "nothing may reach the middle proxy")
			})
		}
	}
}

// A packet of exactly the cap is relayed, and its frame is the largest the
// proxy's own frame reader accepts.
func TestMiddleConnRelaysPacketAtCap(t *testing.T) {
	t.Parallel()

	for _, padded := range []bool{false, true} {
		t.Run(transportName(padded), func(t *testing.T) {
			t.Parallel()

			packet := make([]byte, maxClientPacket)
			for i := range packet {
				packet[i] = byte(i*7 + 1)
			}

			raw := &captureConn{}
			enc, dec, _, peerDec := fixedCiphers()
			m := goldenMiddleConn(raw, enc, dec, padded)

			_, err := m.Write(binary.LittleEndian.AppendUint32(nil, maxClientPacket))
			require.NoError(t, err)
			_, err = m.Write(packet)
			require.NoError(t, err)

			wire := raw.buf.Bytes()
			peer := newFrameConn(newCBCConn(bytes.NewBuffer(wire), nil, peerDec), 0)

			msg, err := peer.readPacket()
			require.NoError(t, err)

			assert.Equal(t, frameMaxMessageLength, 4+4+len(msg)+4, "the frame is exactly the reader's limit")
			assert.True(t, bytes.Equal(packet, msg[reqHeaderLength:]), "the packet arrives whole")
		})
	}
}

func transportName(padded bool) string {
	if padded {
		return "padded"
	}

	return "intermediate"
}
