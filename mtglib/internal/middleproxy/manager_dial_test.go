package middleproxy

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"hash/crc32"
	"io"
	"net"
	"testing"
	"time"

	"github.com/Arman2122/mtg-proxy/essentials"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// addressedConn gives a net.Pipe end a real *net.TCPAddr pair. toTCPAddr falls
// back to a zero address for anything else, and both addresses feed the
// middle-proxy key schedule, so without this the derivation would run on inputs
// production never sees.
type addressedConn struct {
	net.Conn

	local  *net.TCPAddr
	remote *net.TCPAddr
}

func (c addressedConn) LocalAddr() net.Addr  { return c.local }
func (c addressedConn) RemoteAddr() net.Addr { return c.remote }

// fakeMiddleProxy is an in-process middle proxy. It speaks the real RPC nonce
// and handshake exchange using this package's own frame, CBC and key-schedule
// code -- so a dial only completes here if doHandshake genuinely completed --
// and then publishes every RPC_PROXY_REQ it receives on reqs.
type fakeMiddleProxy struct {
	t      *testing.T
	conn   net.Conn
	secret []byte
	local  *net.TCPAddr
	remote *net.TCPAddr
	reqs   chan<- []byte
	done   chan struct{}
}

func (f *fakeMiddleProxy) serve() {
	defer close(f.done)
	defer f.conn.Close() //nolint: errcheck

	msg, ok := f.readNonceRequest()
	if !ok {
		return
	}

	req := &nonceRequest{keySelector: msg[4:8], cryptoTS: msg[12:16], nonce: msg[16:32]}
	resp := &nonceResponse{nonce: bytes.Repeat([]byte{0x5a}, 16)}

	if !f.writeNonceResponse(req, resp) {
		return
	}

	rpc, ok := f.mirrorCiphers(req, resp)
	if !ok {
		return
	}

	hs, err := rpc.readPacket()
	if err != nil {
		f.t.Errorf("fake middle proxy: cannot read handshake request: %v", err)

		return
	}

	if len(hs) < 4 || !bytes.Equal(hs[:4], tagHandshake) {
		f.t.Errorf("fake middle proxy: malformed handshake request %x", hs)

		return
	}

	// validateHandshakeResponse wants 32 bytes with the tag first and the peer
	// PID in the last 12.
	ans := make([]byte, 32)
	copy(ans[:4], tagHandshake)
	copy(ans[20:], handshakePID)

	if err := rpc.writePacket(ans); err != nil {
		f.t.Errorf("fake middle proxy: cannot send handshake response: %v", err)

		return
	}

	for {
		packet, err := rpc.readPacket()
		if err != nil {
			return // the client hung up; that is how this loop ends
		}

		select {
		case f.reqs <- packet:
		default:
		}
	}
}

func (f *fakeMiddleProxy) readNonceRequest() ([]byte, bool) {
	msg, err := newFrameConn(f.conn, seqNoNonce).readPacket()
	if err != nil {
		f.t.Errorf("fake middle proxy: cannot read nonce request: %v", err)

		return nil, false
	}

	if len(msg) != 32 || !bytes.Equal(msg[:4], tagNonce) {
		f.t.Errorf("fake middle proxy: malformed nonce request %x", msg)

		return nil, false
	}

	// writePacket pads every frame up to a 16-byte multiple, but readPacket only
	// skips padding at the START of the next frame -- and the client's next
	// reader is cbcConn, pulling whole 16-byte blocks straight off the raw
	// stream. Leaving these bytes here would shift every block boundary.
	if pad := (aes.BlockSize - (12+len(msg))%aes.BlockSize) % aes.BlockSize; pad > 0 {
		if _, err := io.ReadFull(f.conn, make([]byte, pad)); err != nil {
			f.t.Errorf("fake middle proxy: cannot read nonce frame padding: %v", err)

			return nil, false
		}
	}

	return msg, true
}

// writeNonceResponse emits the nonce response frame WITHOUT writePacket's
// trailing alignment padding: the client's own reader does not consume a peer's
// trailing padding across the plaintext to CBC switch (the mirror image of the
// read above), so a padded response desynchronises its CBC stream. See the
// concern raised alongside this test.
func (f *fakeMiddleProxy) writeNonceResponse(req *nonceRequest, resp *nonceResponse) bool {
	msg := make([]byte, 0, 32)
	msg = append(msg, tagNonce...)
	msg = append(msg, req.keySelector...)
	msg = append(msg, nonceCryptoAES...)
	msg = append(msg, req.cryptoTS...)
	msg = append(msg, resp.nonce...)

	buf := &bytes.Buffer{}

	binary.Write(buf, binary.LittleEndian, uint32(4+4+len(msg)+4)) //nolint: errcheck
	binary.Write(buf, binary.LittleEndian, seqNoNonce)             //nolint: errcheck
	buf.Write(msg)
	binary.Write(buf, binary.LittleEndian, crc32.ChecksumIEEE(buf.Bytes())) //nolint: errcheck

	if _, err := f.conn.Write(buf.Bytes()); err != nil {
		f.t.Errorf("fake middle proxy: cannot send nonce response: %v", err)

		return false
	}

	return true
}

// mirrorCiphers builds the RPC channel from the server's side: the client
// encrypts with the CLIENT-purpose key and decrypts with the SERVER one, so we
// are that pair swapped.
func (f *fakeMiddleProxy) mirrorCiphers(req *nonceRequest, resp *nonceResponse) (*frameConn, bool) {
	clientKey, clientIV := deriveKey(purposeClient, req, resp, f.local, f.remote, f.secret)
	serverKey, serverIV := deriveKey(purposeServer, req, resp, f.local, f.remote, f.secret)

	clientBlock, err := aes.NewCipher(clientKey)
	if err != nil {
		f.t.Errorf("fake middle proxy: client cipher: %v", err)

		return nil, false
	}

	serverBlock, err := aes.NewCipher(serverKey)
	if err != nil {
		f.t.Errorf("fake middle proxy: server cipher: %v", err)

		return nil, false
	}

	return newFrameConn(newCBCConn(f.conn,
		cipher.NewCBCEncrypter(serverBlock, serverIV),
		cipher.NewCBCDecrypter(clientBlock, clientIV)), seqNoHandshake), true
}

// pipeDialer hands DialProxyStream one end of a net.Pipe and runs a
// fakeMiddleProxy on the other.
type pipeDialer struct {
	t      *testing.T
	secret []byte
	local  *net.TCPAddr
	remote *net.TCPAddr
	reqs   chan<- []byte
}

func (d pipeDialer) Dial(_, _ string) (essentials.Conn, error) {
	clientEnd, serverEnd := net.Pipe()

	// net.Pipe is unbuffered and synchronous, so a framing desync deadlocks.
	// A deadline turns that into a failure instead of a hung test.
	deadline := time.Now().Add(10 * time.Second)
	clientEnd.SetDeadline(deadline) //nolint: errcheck
	serverEnd.SetDeadline(deadline) //nolint: errcheck

	proxy := &fakeMiddleProxy{
		t:      d.t,
		conn:   serverEnd,
		secret: d.secret,
		local:  d.local,
		remote: d.remote,
		reqs:   d.reqs,
		done:   make(chan struct{}),
	}

	go proxy.serve()

	// Waiting for the goroutine keeps its t.Errorf calls inside the test.
	d.t.Cleanup(func() {
		serverEnd.Close() //nolint: errcheck
		<-proxy.done
	})

	return essentials.WrapNetConn(addressedConn{Conn: clientEnd, local: d.local, remote: d.remote}), nil
}

// TestDialProxyStreamThreadsPaddedIntermediate closes the manager to middleConn
// seam: DialParams.PaddedIntermediate must reach the RPC_PROXY_REQ actually put
// on the wire. Everything downstream of newMiddleConn is covered by the
// buildProxyReq tests, so replacing params.PaddedIntermediate with a constant in
// DialProxyStream is invisible to all of them -- and it would silently strip
// RPC_F_PAD from every dd client, or claim padding no intermediate client sends.
func TestDialProxyStreamThreadsPaddedIntermediate(t *testing.T) {
	t.Parallel()

	for name, tc := range map[string]struct {
		padded    bool
		wantFlags uint32
	}{
		"padded-intermediate": {
			padded:    true,
			wantFlags: flagHasAdTag | flagMagic | flagExtMode2 | flagIntermediate | flagPad,
		},
		"intermediate": {
			padded:    false,
			wantFlags: flagHasAdTag | flagMagic | flagExtMode2 | flagIntermediate,
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			secret := bytes.Repeat([]byte{0x3b}, 16)
			local := &net.TCPAddr{IP: net.IPv4(203, 0, 113, 7), Port: 40001}
			remote := &net.TCPAddr{IP: net.IPv4(149, 154, 175, 50), Port: 8888}
			reqs := make(chan []byte, 4)

			mgr := NewManager(context.Background(), nil, liveLogger{t}, "only-ipv4")

			// Seed what fetch() would have stored: Ready() short-circuits
			// ensureReady, so the dial never touches the network.
			mgr.ready = true
			mgr.secret = secret
			mgr.middleV4 = map[int][]string{2: {remote.String()}}

			stream, _, err := mgr.DialProxyStream(
				pipeDialer{t: t, secret: secret, local: local, remote: remote, reqs: reqs},
				DialParams{
					DC:                 2,
					ClientAddr:         &net.TCPAddr{IP: net.IPv4(198, 51, 100, 9), Port: 1234},
					PaddedIntermediate: tc.padded,
					AdvertisedPort:     443,
					AdTag:              [adTagLength]byte{0xaa, 0xbb, 0xcc, 0xdd},
				})
			require.NoError(t, err)

			defer stream.Close() //nolint: errcheck

			// One 4-aligned intermediate packet: the alignment trim is a no-op on
			// it, so the flags word is the only thing the two modes may differ in.
			_, err = stream.Write([]byte{4, 0, 0, 0, 0xde, 0xad, 0xbe, 0xef})
			require.NoError(t, err)

			var msg []byte

			select {
			case msg = <-reqs:
			case <-time.After(10 * time.Second):
				t.Fatal("the fake middle proxy received no RPC_PROXY_REQ")
			}

			require.True(t, bytes.HasPrefix(msg, tagProxyRequest),
				"precondition: the framed message must be an RPC_PROXY_REQ, got %x", msg)

			assert.Equal(t, tc.wantFlags, binary.LittleEndian.Uint32(msg[4:8]),
				"RPC_PROXY_REQ flags must follow DialParams.PaddedIntermediate")
		})
	}
}
