package middleproxy

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"testing"

	"github.com/Arman2122/mtg-proxy/essentials"
	"github.com/stretchr/testify/require"
)

// The ad-tag leg's data path on a real loopback TCP pair: a middleConn on the
// proxy's side, and a peer speaking the same RPC framing and AES-CBC on the
// other. The proxy's socket counts its reads and writes, which is how many
// system calls the leg makes per MiB. allocs/op includes the peer's own
// framing, which uses this package's code too -- and so does the upload's
// throughput: the peer reads with the same code the proxy's download uses, so
// upload MB/s is bounded by whichever side is slower. writes/MiB is the
// proxy's alone.

// countingConn counts the calls made on the proxy's socket.
type countingConn struct {
	essentials.Conn

	reads, writes atomic.Int64
}

func (c *countingConn) Read(p []byte) (int, error) {
	c.reads.Add(1)

	return c.Conn.Read(p) //nolint: wrapcheck
}

func (c *countingConn) Write(p []byte) (int, error) {
	c.writes.Add(1)

	return c.Conn.Write(p) //nolint: wrapcheck
}

// benchLeg is a middleConn over one end of a loopback pair, and the peer's
// frame conn over the other.
func benchLeg(b *testing.B) (*middleConn, *countingConn, *frameConn) {
	b.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(b, err)

	defer listener.Close() //nolint: errcheck

	near, err := net.Dial("tcp", listener.Addr().String())
	require.NoError(b, err)

	far, err := listener.Accept()
	require.NoError(b, err)

	b.Cleanup(func() {
		near.Close() //nolint: errcheck
		far.Close()  //nolint: errcheck
	})

	proxyEnc, proxyDec, peerEnc, peerDec := fixedCiphers()
	counted := &countingConn{Conn: essentials.WrapNetConn(near)}

	m := goldenMiddleConn(counted, proxyEnc, proxyDec, true)
	peer := newFrameConn(newCBCConn(far, peerEnc, peerDec), 0)

	return m, counted, peer
}

func BenchmarkMiddleConn(b *testing.B) {
	for _, size := range []int{16 << 10, 256} {
		name := fmt.Sprintf("%dB", size)
		if size >= 1<<10 {
			name = fmt.Sprintf("%dKiB", size>>10)
		}

		b.Run("download/"+name, func(b *testing.B) { benchDownload(b, size) })
		b.Run("upload/"+name, func(b *testing.B) { benchUpload(b, size) })
	}
}

// benchDownload: the peer sends RPC_PROXY_ANS of size bytes as fast as the
// socket takes them; each iteration the client side reads one reframed packet.
func benchDownload(b *testing.B, size int) {
	b.Helper()

	m, counted, peer := benchLeg(b)

	ans := append(append(append([]byte{}, tagProxyAns...), 0, 0, 0, 0), goldenConnID[:]...)
	ans = append(ans, make([]byte, size)...)

	go func() {
		for peer.writePacket(ans) == nil {
		}
	}()

	packet := make([]byte, 4+size)

	b.SetBytes(int64(size))
	b.ReportAllocs()

	iterations := 0

	for b.Loop() {
		if _, err := io.ReadFull(m, packet); err != nil {
			b.Fatal(err)
		}

		iterations++
	}

	reportPerMiB(b, iterations*size, counted.reads.Load(), counted.writes.Load())
}

// benchUpload: each iteration the client writes one intermediate packet of
// size bytes; the peer reads RPC_PROXY_REQ frames as fast as they come.
func benchUpload(b *testing.B, size int) {
	b.Helper()

	m, counted, peer := benchLeg(b)

	go func() {
		for {
			if _, err := peer.readPacket(); err != nil {
				return
			}
		}
	}()

	packet := binary.LittleEndian.AppendUint32(nil, uint32(size)) //nolint: gosec // a benchmark constant
	packet = append(packet, make([]byte, size)...)
	packet[4] = 1 // not all-zero, so the encrypted flag stays off

	b.SetBytes(int64(size))
	b.ReportAllocs()

	iterations := 0

	for b.Loop() {
		if _, err := m.Write(packet); err != nil {
			b.Fatal(err)
		}

		iterations++
	}

	reportPerMiB(b, iterations*size, counted.reads.Load(), counted.writes.Load())
}

func reportPerMiB(b *testing.B, moved int, reads, writes int64) {
	b.Helper()

	if moved == 0 {
		return
	}

	mib := float64(moved) / (1 << 20)

	b.ReportMetric(float64(reads)/mib, "reads/MiB")
	b.ReportMetric(float64(writes)/mib, "writes/MiB")
}
