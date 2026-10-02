package middleproxy

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"encoding/hex"
	"io"
	"net"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/Arman2122/mtg-proxy/essentials"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The middle-proxy leg's bytes, pinned both ways: what middleConn puts on the
// wire for a client's upload, and what it hands the client from Telegram's
// answers. Captured from the code as it was before its rewrite for speed, so
// the rewrite is judged against what deployed proxies have always sent.
//
// REGENERATION
//
//	MTG_UPDATE_GOLDEN=1 go test ./mtglib/internal/middleproxy/ -run Golden
//
// NEVER regenerate to make a red test green. A diff here means the proxy
// speaks to Telegram's middle proxies, or to its clients, in bytes it never
// used before; regenerate only after deciding that deliberately, and say so in
// the commit.

const goldenUpdateEnv = "MTG_UPDATE_GOLDEN"

const goldenHeader = `# mtg-proxy -- middle-proxy leg, %s.
#
# Regenerate:  MTG_UPDATE_GOLDEN=1 go test ./mtglib/internal/middleproxy/ -run Golden
# Never regenerate to make a red test green. Lowercase hex, 32 bytes a line.
`

// fixedCiphers is AES-256-CBC from fixed keys and IVs, one pair per direction,
// mirrored so the peer decrypts what the proxy encrypts and the other way
// round. Each call starts the chains afresh.
func fixedCiphers() (proxyEnc, proxyDec, peerEnc, peerDec cipher.BlockMode) {
	up, err := aes.NewCipher(bytes.Repeat([]byte{0x41}, 32))
	if err != nil {
		panic(err)
	}

	down, err := aes.NewCipher(bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		panic(err)
	}

	upIV := bytes.Repeat([]byte{0x51}, aes.BlockSize)
	downIV := bytes.Repeat([]byte{0x52}, aes.BlockSize)

	return cipher.NewCBCEncrypter(up, upIV), cipher.NewCBCDecrypter(down, downIV),
		cipher.NewCBCEncrypter(down, downIV), cipher.NewCBCDecrypter(up, upIV)
}

// captureConn is an essentials.Conn that records writes and serves reads from
// a buffer. Anything else panics through the nil embedded interface.
type captureConn struct {
	essentials.Conn

	buf bytes.Buffer
}

func (c *captureConn) Write(p []byte) (int, error) { return c.buf.Write(p) }
func (c *captureConn) Read(p []byte) (int, error)  { return c.buf.Read(p) }

// tinyReadConn serves r a few bytes at a time, cycling through tinySteps, the
// way a TCP stream can arrive in arbitrarily small segments.
type tinyReadConn struct {
	essentials.Conn

	r    io.Reader
	step int
}

var tinySteps = []int{1, 2, 3, 16, 17}

func (c *tinyReadConn) Read(p []byte) (int, error) {
	size := min(len(p), tinySteps[c.step%len(tinySteps)])
	c.step++

	return c.r.Read(p[:size]) //nolint: wrapcheck
}

func (c *tinyReadConn) Write(p []byte) (int, error) { return len(p), nil }

var (
	goldenConnID = [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	goldenAdTag  = [adTagLength]byte{
		0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
		0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
	}
	goldenClient = &net.TCPAddr{IP: net.IPv4(198, 51, 100, 7), Port: 50123}
	goldenOurs   = &net.TCPAddr{IP: net.IPv4(203, 0, 113, 9), Port: 8443}
)

// goldenMiddleConn is a middleConn over raw with fixed identity, starting its
// RPC sequence at 0.
func goldenMiddleConn(raw essentials.Conn, enc, dec cipher.BlockMode, padded bool) *middleConn {
	frame := newFrameConn(newCBCConn(raw, enc, dec), 0)

	return newMiddleConn(raw, frame, goldenConnID, goldenAdTag, goldenClient, goldenOurs, padded)
}

// uploadStream is a client's intermediate stream: packets of 4, 16, 100,
// 1,024 (its first eight bytes zero, which sets the encrypted flag) and 16,384
// bytes, then an 8-byte quick-ack. Padded-intermediate adds 1-3 trailing
// bytes to each, inside the length, for middleConn to trim.
func uploadStream(padded bool) []byte {
	var out bytes.Buffer

	for i, size := range []int{4, 16, 100, 1024, 16384, 8} {
		payload := make([]byte, size)
		for j := range payload {
			payload[j] = byte(i*31 + j)
		}

		if size == 1024 {
			clear(payload[:8])
		}

		if padded {
			payload = slices.Concat(payload, bytes.Repeat([]byte{0xee}, 1+i%3))
		}

		length := uint32(len(payload)) //nolint: gosec // a few KiB built here
		if size == 8 {
			length |= quickAckLength
		}

		out.Write(binary.LittleEndian.AppendUint32(nil, length))
		out.Write(payload)
	}

	return out.Bytes()
}

// uploadWire writes stream into a fresh middleConn in pieces of chunk bytes
// and returns what it put on the wire.
func uploadWire(t *testing.T, stream []byte, chunk int, padded bool) []byte {
	t.Helper()

	capture := &captureConn{}
	enc, dec, _, _ := fixedCiphers()
	m := goldenMiddleConn(capture, enc, dec, padded)

	for rest := stream; len(rest) > 0; {
		piece := rest[:min(chunk, len(rest))]

		n, err := m.Write(piece)
		require.NoError(t, err)
		require.Equal(t, len(piece), n)

		rest = rest[len(piece):]
	}

	return capture.buf.Bytes()
}

func TestMiddleConnUploadGolden(t *testing.T) {
	t.Parallel()

	for _, padded := range []bool{true, false} {
		name := "intermediate"
		if padded {
			name = "padded"
		}

		t.Run(name, func(t *testing.T) {
			t.Parallel()

			stream := uploadStream(padded)
			wire := uploadWire(t, stream, 1, padded)

			for _, chunk := range []int{5, 4096} {
				assert.Equal(t, wire, uploadWire(t, stream, chunk, padded),
					"the bytes on the wire must not depend on how the client's stream was cut (chunk %d)", chunk)
			}

			checkGolden(t, "testdata/middle_upload_"+name+".golden", "upload, "+name, wire)
		})
	}
}

// downloadWire is what a middle proxy sends: RPC_PROXY_ANS with payloads of 4,
// 1,000, 16,384 and 70,000 bytes, an RPC_SIMPLE_ACK, then RPC_CLOSE_EXT,
// encrypted with the peer's chain.
func downloadWire(t *testing.T) []byte {
	t.Helper()

	buf := &bytes.Buffer{}
	_, _, peerEnc, _ := fixedCiphers()
	peer := newFrameConn(newCBCConn(buf, peerEnc, nil), 0)

	for i, size := range []int{4, 1000, 16384, 70000} {
		payload := make([]byte, size)
		for j := range payload {
			payload[j] = byte(i*17 + j*7)
		}

		ans := append(append(append([]byte{}, tagProxyAns...), 0, 0, 0, 0), goldenConnID[:]...)
		require.NoError(t, peer.writePacket(append(ans, payload...)))
	}

	ack := append(append([]byte{}, tagSimpleAck...), goldenConnID[:]...)
	require.NoError(t, peer.writePacket(append(ack, 0x01, 0x02, 0x03, 0x04)))
	require.NoError(t, peer.writePacket(tagCloseExt))

	return buf.Bytes()
}

// downloadThrough reads raw's middle-proxy stream through a fresh middleConn
// in reads of dstSize and returns what it handed the client. The stream must
// end in io.EOF, which RPC_CLOSE_EXT produces.
func downloadThrough(t *testing.T, raw essentials.Conn, dstSize int) []byte {
	t.Helper()

	enc, dec, _, _ := fixedCiphers()
	m := goldenMiddleConn(raw, enc, dec, true)

	var out bytes.Buffer

	dst := make([]byte, dstSize)

	for {
		n, err := m.Read(dst)
		out.Write(dst[:n])

		if err != nil {
			require.ErrorIs(t, err, io.EOF, "RPC_CLOSE_EXT must end the stream as EOF")

			return out.Bytes()
		}

		require.Positive(t, n, "a read with no error must carry bytes")
	}
}

func TestMiddleConnDownloadGolden(t *testing.T) {
	t.Parallel()

	wire := downloadWire(t)

	var first []byte

	for _, size := range []int{1, 7, 4096, 65536} {
		raw := &captureConn{}
		raw.buf.Write(wire)

		got := downloadThrough(t, raw, size)

		if first == nil {
			first = got

			continue
		}

		assert.Equal(t, first, got, "what the client receives must not depend on its read size (%d)", size)
	}

	checkGolden(t, "testdata/middle_download.golden", "download, client-bound stream", first)
}

func TestMiddleConnDownloadSurvivesTinySegments(t *testing.T) {
	t.Parallel()

	got := downloadThrough(t, &tinyReadConn{r: bytes.NewReader(downloadWire(t))}, 4096)

	assert.Equal(t, readGolden(t, "testdata/middle_download.golden"), got,
		"frames split at arbitrary TCP boundaries must reach the client unchanged")
}

// checkGolden compares got with the golden file at path, or rewrites the file
// when MTG_UPDATE_GOLDEN is set.
func checkGolden(t *testing.T, path, what string, got []byte) {
	t.Helper()

	if os.Getenv(goldenUpdateEnv) != "" {
		var b strings.Builder

		b.WriteString(strings.Replace(goldenHeader, "%s", what, 1))

		for line := hex.EncodeToString(got); line != ""; {
			n := min(64, len(line))
			b.WriteString(line[:n] + "\n")
			line = line[n:]
		}

		require.NoError(t, os.WriteFile(path, []byte(b.String()), 0o600))

		return
	}

	assert.Equal(t, readGolden(t, path), got, "the bytes differ from %s", path)
}

func readGolden(t *testing.T, path string) []byte {
	t.Helper()

	f, err := os.Open(path)
	require.NoError(t, err, "golden is missing; regenerate with %s=1", goldenUpdateEnv)

	defer f.Close() //nolint: errcheck

	var hexText strings.Builder

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		if line := strings.TrimSpace(scanner.Text()); line != "" && !strings.HasPrefix(line, "#") {
			hexText.WriteString(line)
		}
	}

	require.NoError(t, scanner.Err())

	data, err := hex.DecodeString(hexText.String())
	require.NoError(t, err)

	return data
}
