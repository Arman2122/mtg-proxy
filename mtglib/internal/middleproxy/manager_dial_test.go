package middleproxy

import (
	"bytes"
	"context"
	"encoding/binary"
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

// fakeMiddleProxy is an in-process middle proxy over a net.Pipe: ServePeer
// answers the real RPC nonce and handshake exchange with this package's own
// frame, CBC and key-schedule code -- so a dial only completes here if
// doHandshake genuinely completed -- and every RPC_PROXY_REQ it receives is
// published on reqs.
type fakeMiddleProxy struct {
	t      *testing.T
	conn   net.Conn
	secret []byte
	reqs   chan<- []byte
	done   chan struct{}
}

func (f *fakeMiddleProxy) serve() {
	defer close(f.done)
	defer f.conn.Close() //nolint: errcheck

	peer, err := ServePeer(f.conn, f.secret)
	if err != nil {
		f.t.Errorf("fake middle proxy: %v", err)

		return
	}

	for {
		packet, err := peer.ReadPacket()
		if err != nil {
			return // the client hung up; that is how this loop ends
		}

		select {
		case f.reqs <- packet:
		default:
		}
	}
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

	// The middle proxy's end sees the client as its remote and itself as local:
	// ServePeer keys the schedule from those, mirroring the client's view.
	proxy := &fakeMiddleProxy{
		t:      d.t,
		conn:   addressedConn{Conn: serverEnd, local: d.remote, remote: d.local},
		secret: d.secret,
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
				},
			)
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
