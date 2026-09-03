package obfuscation

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"fmt"
	"hash"

	"github.com/Arman2122/mtg-proxy/essentials"
)

// Obfuscator implements the obfuscated2 handshake
// (https://core.telegram.org/mtproto/mtproto-transports#transport-obfuscation).
// Set Secret to the MTProxy secret for key-mixed handshakes; leave nil for
// direct DC connections.
type Obfuscator struct {
	Secret []byte
}

// ReadHandshake reads the 64-byte obfuscated2 client handshake from r,
// validates that its transport tag is one the caller honours, and returns the
// requested DC and that tag along with a transparent en/decrypting wrapper
// over r.
//
// It is the single-candidate case of MatchHandshake, so the cipher derivation
// lives in exactly one place and the two cannot drift.
func (o Obfuscator) ReadHandshake(r essentials.Conn, allowed TagSet) (int, ConnectionTag, essentials.Conn, error) {
	result, err := MatchHandshake(r, [][]byte{o.Secret}, allowed)
	if err != nil {
		return 0, ConnectionTag{}, nil, err
	}

	return result.DC, result.Tag, result.Conn, nil
}

// SendHandshake writes a fresh 64-byte obfuscated2 handshake for the given DC
// and transport tag to w and returns a transparent en/decrypting wrapper over
// w. The tag must be the client's own: the relay above is byte-transparent, so
// announcing a different transport to Telegram corrupts every packet.
func (o Obfuscator) SendHandshake(w essentials.Conn, dc int, tag ConnectionTag) (essentials.Conn, error) {
	frame := generateHandshake(dc, tag)
	copyFrame := frame
	hasher := sha256.New()

	sendCipher := o.getCipher(&frame, hasher)

	frame.revert()
	hasher.Reset()
	recvCipher := o.getCipher(&frame, hasher)

	// only the trailing 8 bytes (connection type + DC + noise) travel encrypted;
	// bytes 0..55 have to stay plaintext so that the rejections generateHandshake
	// makes on the leading bytes (0xef, HTTP verbs, transport magics) are the ones
	// actually observable on the wire.
	sendCipher.XORKeyStream(frame.data[:], frame.data[:])
	copy(frame.data[:hfOffsetConnectionType], copyFrame.data[:hfOffsetConnectionType])

	if _, err := w.Write(frame.data[:]); err != nil {
		return nil, fmt.Errorf("cannot send a handshake: %w", err)
	}

	return conn{
		Conn:       w,
		recvCipher: recvCipher,
		sendCipher: sendCipher,
	}, nil
}

func (o Obfuscator) getCipher(f *handshakeFrame, hasher hash.Hash) cipher.Stream {
	blockKey := f.key()

	if o.Secret != nil {
		hasher.Write(blockKey)
		hasher.Write(o.Secret)
		blockKey = hasher.Sum(nil)
	}

	block, _ := aes.NewCipher(blockKey)

	return cipher.NewCTR(block, f.iv())
}
