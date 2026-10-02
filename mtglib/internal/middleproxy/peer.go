package middleproxy

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"net"
)

// Peer is the middle-proxy end of an RPC channel: it answers the nonce and
// handshake exchange and then reads RPC_PROXY_REQ and writes RPC_PROXY_ANS,
// with this package's own frame, AES-CBC and key-schedule code.
//
// No production caller uses it. It is test support, exported so that tests
// outside this package -- mtglib's end-to-end ad-tag tests -- can put a real
// middle proxy behind a stream: a dial through it completes only if the
// client side genuinely completed the exchange. It lives here rather than in
// a separate package because it needs the unexported key schedule; a copy
// elsewhere could only drift from it.
type Peer struct {
	frame *frameConn
}

// PeerRequest is one RPC_PROXY_REQ as the middle proxy received it.
type PeerRequest struct {
	ConnID  [8]byte
	Flags   uint32
	AdTag   []byte
	Payload []byte
}

// peerNonce is the nonce every Peer answers with: tests need no secrecy, only
// a key schedule both sides compute the same way.
var peerNonce = bytes.Repeat([]byte{0x5a}, 16)

// ServePeer plays the middle proxy on conn: it answers the RPC nonce and
// handshake exchange with secret. The key schedule takes the client's address
// as conn's remote and the middle proxy's as conn's local, which is what a
// client that dialled conn without a public-IP override used.
func ServePeer(conn net.Conn, secret []byte) (*Peer, error) {
	msg, err := readNonceRequest(conn)
	if err != nil {
		return nil, err
	}

	req := &nonceRequest{keySelector: msg[4:8], cryptoTS: msg[12:16], nonce: msg[16:32]}
	resp := &nonceResponse{nonce: peerNonce}

	if err := writeNonceResponse(conn, req, resp); err != nil {
		return nil, err
	}

	client := toTCPAddr(conn.RemoteAddr())
	ours := toTCPAddr(conn.LocalAddr())

	// The client encrypts with the client-purpose key and decrypts with the
	// server one, so the middle proxy is that pair swapped.
	clientKey, clientIV := deriveKey(purposeClient, req, resp, client, ours, secret)
	serverKey, serverIV := deriveKey(purposeServer, req, resp, client, ours, secret)

	clientBlock, err := aes.NewCipher(clientKey)
	if err != nil {
		return nil, fmt.Errorf("client cipher: %w", err)
	}

	serverBlock, err := aes.NewCipher(serverKey)
	if err != nil {
		return nil, fmt.Errorf("server cipher: %w", err)
	}

	frame := newFrameConn(newCBCConn(conn,
		cipher.NewCBCEncrypter(serverBlock, serverIV),
		cipher.NewCBCDecrypter(clientBlock, clientIV)), seqNoHandshake)

	hs, err := frame.readPacket()
	if err != nil {
		return nil, fmt.Errorf("cannot read handshake request: %w", err)
	}

	if len(hs) < 4 || !bytes.Equal(hs[:4], tagHandshake) {
		return nil, fmt.Errorf("malformed handshake request %x", hs)
	}

	// validateHandshakeResponse wants 32 bytes with the tag first and the peer
	// PID in the last 12.
	ans := make([]byte, 32)
	copy(ans[:4], tagHandshake)
	copy(ans[20:], handshakePID)

	if err := frame.writePacket(ans); err != nil {
		return nil, fmt.Errorf("cannot send handshake response: %w", err)
	}

	return &Peer{frame: frame}, nil
}

// ReadPacket returns the next RPC message, whatever its kind.
func (p *Peer) ReadPacket() ([]byte, error) {
	return p.frame.readPacket()
}

// ReadRequest returns the next message, which must be an RPC_PROXY_REQ.
func (p *Peer) ReadRequest() (PeerRequest, error) {
	msg, err := p.frame.readPacket()
	if err != nil {
		return PeerRequest{}, err
	}

	return parsePeerRequest(msg)
}

// WriteAnswer sends payload to the client of connID as an RPC_PROXY_ANS.
func (p *Peer) WriteAnswer(connID [8]byte, payload []byte) error {
	msg := make([]byte, 0, 16+len(payload))
	msg = append(msg, tagProxyAns...)
	msg = append(msg, 0, 0, 0, 0)
	msg = append(msg, connID[:]...)
	msg = append(msg, payload...)

	return p.frame.writePacket(msg)
}

// parsePeerRequest reads buildProxyReq's layout back: tag, flags, connection
// id, two 20-byte addresses, the extra-block size and proxy-tag id, the ad
// tag's length and bytes, alignment to 4, then the client's packet.
func parsePeerRequest(msg []byte) (PeerRequest, error) {
	const adTagAt = 4 + 4 + 8 + 20 + 20 + 4 + 4

	if len(msg) < adTagAt+1 || !bytes.Equal(msg[:4], tagProxyRequest) {
		return PeerRequest{}, fmt.Errorf("not an RPC_PROXY_REQ: %x", msg[:min(len(msg), 16)])
	}

	adTagEnd := adTagAt + 1 + int(msg[adTagAt])
	payloadAt := (adTagEnd + 3) &^ 3

	if len(msg) < payloadAt {
		return PeerRequest{}, errors.New("RPC_PROXY_REQ shorter than its header")
	}

	req := PeerRequest{
		Flags:   binary.LittleEndian.Uint32(msg[4:8]),
		AdTag:   msg[adTagAt+1 : adTagEnd],
		Payload: msg[payloadAt:],
	}
	copy(req.ConnID[:], msg[8:16])

	return req, nil
}

func readNonceRequest(conn io.ReadWriter) ([]byte, error) {
	msg, err := newFrameConn(conn, seqNoNonce).readPacket()
	if err != nil {
		return nil, fmt.Errorf("cannot read nonce request: %w", err)
	}

	if len(msg) != 32 || !bytes.Equal(msg[:4], tagNonce) {
		return nil, fmt.Errorf("malformed nonce request %x", msg)
	}

	// writePacket pads every frame up to a 16-byte multiple, but readPacket only
	// skips padding at the START of the next frame -- and the client's next
	// reader is cbcConn, pulling whole 16-byte blocks straight off the raw
	// stream. Leaving these bytes here would shift every block boundary.
	if pad := (aes.BlockSize - (12+len(msg))%aes.BlockSize) % aes.BlockSize; pad > 0 {
		if _, err := io.ReadFull(conn, make([]byte, pad)); err != nil {
			return nil, fmt.Errorf("cannot read nonce frame padding: %w", err)
		}
	}

	return msg, nil
}

// writeNonceResponse emits the nonce response frame WITHOUT writePacket's
// trailing alignment padding: the client's own reader does not consume a
// peer's trailing padding across the plaintext to CBC switch (the mirror image
// of readNonceRequest), so a padded response desynchronises its CBC stream.
func writeNonceResponse(conn io.Writer, req *nonceRequest, resp *nonceResponse) error {
	msg := make([]byte, 0, 32)
	msg = append(msg, tagNonce...)
	msg = append(msg, req.keySelector...)
	msg = append(msg, nonceCryptoAES...)
	msg = append(msg, req.cryptoTS...)
	msg = append(msg, resp.nonce...)

	buf := &bytes.Buffer{}

	// G115: msg is the 32 bytes built just above, so this is 44.
	binary.Write(buf, binary.LittleEndian, uint32(4+4+len(msg)+4)) //nolint: errcheck,gosec
	binary.Write(buf, binary.LittleEndian, seqNoNonce)             //nolint: errcheck
	buf.Write(msg)
	binary.Write(buf, binary.LittleEndian, crc32.ChecksumIEEE(buf.Bytes())) //nolint: errcheck

	if _, err := conn.Write(buf.Bytes()); err != nil {
		return fmt.Errorf("cannot send nonce response: %w", err)
	}

	return nil
}
