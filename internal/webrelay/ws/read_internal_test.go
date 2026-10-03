package ws

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"math/rand/v2"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// definedUnmask is RFC 6455 §5.3 as written: each byte XORed with the mask
// byte its position names.
func definedUnmask(payload []byte, mask [4]byte, offset int) {
	for i := range payload {
		payload[i] ^= mask[(i+offset)%4]
	}
}

func TestUnmaskMatchesTheDefinition(t *testing.T) {
	t.Parallel()

	rng := rand.New(rand.NewPCG(6455, 53)) //nolint: gosec // a test's reproducible inputs

	for length := 0; length <= 300; length++ {
		for offset := range 4 {
			for range 64 {
				var mask [4]byte

				binary.LittleEndian.PutUint32(mask[:], rng.Uint32())

				payload := make([]byte, length)
				for i := range payload {
					payload[i] = byte(rng.Uint32())
				}

				want := bytes.Clone(payload)
				definedUnmask(want, mask, offset)

				unmask(payload, mask, offset)

				if !bytes.Equal(payload, want) {
					t.Fatalf("length %d, offset %d, mask %x: unmask differs from the definition", length, offset, mask)
				}
			}
		}
	}
}

func FuzzUnmask(f *testing.F) {
	f.Add([]byte("a websocket payload"), uint32(0x37fa213d), uint8(0))
	f.Add([]byte{}, uint32(0), uint8(3))

	f.Fuzz(func(t *testing.T, payload []byte, m uint32, offset uint8) {
		var mask [4]byte

		binary.LittleEndian.PutUint32(mask[:], m)

		want := bytes.Clone(payload)
		definedUnmask(want, mask, int(offset%4))

		unmask(payload, mask, int(offset%4))

		if !bytes.Equal(payload, want) {
			t.Fatalf("unmask differs from the definition")
		}
	})
}

// clientFrame is one masked client frame in the minimal length form.
func clientFrame(fin bool, opcode byte, payload []byte, mask [4]byte) []byte {
	first := opcode
	if fin {
		first |= 0x80
	}

	out := []byte{first}

	switch n := len(payload); {
	case n <= maxControlPayload:
		out = append(out, 0x80|byte(n))
	case n <= 0xFFFF:
		out = binary.BigEndian.AppendUint16(append(out, 0x80|126), uint16(n))
	default:
		out = binary.BigEndian.AppendUint64(append(out, 0x80|127), uint64(n))
	}

	out = append(out, mask[:]...)
	masked := bytes.Clone(payload)
	definedUnmask(masked, mask, 0)

	return append(out, masked...)
}

// recordConn is a net.Conn that is never read -- frames come from the reader
// a test hands the Conn -- and that records what is written to it.
type recordConn struct {
	net.Conn

	out bytes.Buffer
}

func (c *recordConn) Write(p []byte) (int, error)      { return c.out.Write(p) }
func (c *recordConn) SetReadDeadline(time.Time) error  { return nil }
func (c *recordConn) SetWriteDeadline(time.Time) error { return nil }

func connOver(stream []byte, opts Options) (*Conn, *recordConn) {
	conn := &recordConn{}

	return newConn(conn, bufio.NewReaderSize(bytes.NewReader(stream), 4096), opts.withDefaults()), conn
}

// A whole message in one frame -- what a browser sends -- costs one
// allocation: the message itself.
func TestASingleFrameMessageIsOneAllocation(t *testing.T) { //nolint: paralleltest // counts allocations
	payload := make([]byte, 64<<10)

	var stream []byte
	for range 101 { // AllocsPerRun runs once more than asked, to warm up
		stream = append(stream, clientFrame(true, opBinary, payload, [4]byte{1, 2, 3, 4})...)
	}

	c, _ := connOver(stream, Options{})

	allocs := testing.AllocsPerRun(100, func() {
		if _, err := c.Read(); err != nil {
			t.Fatal(err)
		}
	})

	assert.InDelta(t, 1, allocs, 0, "allocations per single-frame message")
}

// A message in fragments, each under its own mask and with a ping between
// them, comes back whole and exact; the limit counts the whole message.
func TestAFragmentedMessageIsAssembledInOneBuffer(t *testing.T) {
	t.Parallel()

	parts := [][]byte{bytes.Repeat([]byte{1}, 10), bytes.Repeat([]byte{2}, 70000), bytes.Repeat([]byte{3}, 5)}

	var stream []byte
	stream = append(stream, clientFrame(false, opBinary, parts[0], [4]byte{9, 8, 7, 6})...)
	stream = append(stream, clientFrame(false, opContinuation, parts[1], [4]byte{0xde, 0xad, 0xbe, 0xef})...)
	stream = append(stream, clientFrame(true, opPing, []byte("are you there"), [4]byte{5, 5, 5, 5})...)
	stream = append(stream, clientFrame(true, opContinuation, parts[2], [4]byte{1, 0, 0, 1})...)

	c, conn := connOver(stream, Options{MaxMessage: 1 << 20})

	message, err := c.Read()
	require.NoError(t, err)
	assert.Equal(t, bytes.Join(parts, nil), message)
	assert.Equal(t, []byte{0x80 | opPong, 13, 'a', 'r', 'e', ' ', 'y', 'o', 'u', ' ', 't', 'h', 'e', 'r', 'e'}, conn.out.Bytes(),
		"the ping between the fragments was answered")

	small, _ := connOver(stream, Options{MaxMessage: 70000})

	_, err = small.Read()
	require.ErrorIs(t, err, ErrMessageTooBig)
}

// Every Read hands out memory of its own: the relay slices DATA payloads out
// of a message and keeps them until written, so a reader that reused its
// buffer would corrupt them.
func TestReadReturnsAFreshBufferEachTime(t *testing.T) {
	t.Parallel()

	first := bytes.Repeat([]byte{0x11}, 1000)
	second := bytes.Repeat([]byte{0x22}, 1000)

	stream := append(clientFrame(true, opBinary, first, [4]byte{1, 2, 3, 4}), clientFrame(true, opBinary, second, [4]byte{4, 3, 2, 1})...)
	c, _ := connOver(stream, Options{})

	a, err := c.Read()
	require.NoError(t, err)

	b, err := c.Read()
	require.NoError(t, err)

	assert.NotSame(t, &a[0], &b[0], "two messages share memory")
	assert.Equal(t, first, a, "the first message changed under the second read")
	assert.Equal(t, second, b)
}
