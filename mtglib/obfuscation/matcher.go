package obfuscation

import (
	"crypto/aes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"github.com/Arman2122/mtg-proxy/essentials"
)

// ErrNoMatchingSecret means no candidate key decrypts frame[56:60] to a tag the
// caller honours. It is returned with a zero MatchResult.
var ErrNoMatchingSecret = errors.New("no configured secret decrypts this handshake")

// replayKeyDomainObfuscated keeps obfuscated2 replay keys disjoint from the
// 32-byte FakeTLS session ids that share the same bloom filter.
const replayKeyDomainObfuscated = 0x01

// MatchResult is everything the caller needs to attribute and route a stream
// whose secret was unknown until it was decrypted.
type MatchResult struct {
	Index int // index into the keys slice that matched
	DC    int
	Tag   ConnectionTag
	Conn  essentials.Conn

	replayKey [1 + hfLenKey + hfLenIV]byte
}

// ReplayKey is the client-chosen AES key and IV (frame[8:56]) behind a one-byte
// domain tag. That 48 bytes is the COMPLETE identity of a replayed handshake:
// identical bytes derive identical ciphers. frame[0:8] and frame[60:64] feed
// nothing, so keying on the whole frame would let an on-path attacker evade the
// cache by flipping a byte he controls. hfOffset* are unexported, so this must
// be a method here, not a slice expression in mtglib.
func (m *MatchResult) ReplayKey() []byte {
	return m.replayKey[:]
}

// MatchHandshake reads one 64-byte obfuscated2 handshake from r and returns the
// first candidate key whose derived receive cipher decrypts the connection type
// at offset 56 to a tag in allowed.
//
// It is the multi-candidate form of Obfuscator.ReadHandshake and shares its
// cipher derivation, so the two cannot drift.
func MatchHandshake(r essentials.Conn, keys [][]byte, allowed TagSet) (MatchResult, error) {
	var raw [hfLen]byte

	if _, err := io.ReadFull(r, raw[:]); err != nil {
		return MatchResult{}, fmt.Errorf("cannot read frame: %w", err)
	}

	for idx, key := range keys {
		// Only the RECV key is needed to test a candidate: the send key costs a
		// revert plus a second SHA-256 and is derived once, after the match.
		tag := peekTag(&raw, key)
		if !allowed.Has(tag) {
			continue
		}

		obfs := Obfuscator{Secret: key}
		frame := handshakeFrame{data: raw}
		hasher := sha256.New()

		recvCipher := obfs.getCipher(&frame, hasher)

		frame.revert()
		hasher.Reset()

		sendCipher := obfs.getCipher(&frame, hasher)

		// peekTag's throwaway cipher sits at keystream block 3 and must never be
		// handed back: the returned conn has to start at stream offset 64,
		// exactly where ReadHandshake leaves it, or every subsequent byte
		// decrypts against the wrong keystream. Hence a fresh cipher over the
		// full 64 bytes.
		recvCipher.XORKeyStream(frame.data[:], frame.data[:])

		result := MatchResult{
			Index: idx,
			DC:    frame.dc(),
			Tag:   tag,
			Conn: conn{
				Conn:       r,
				recvCipher: recvCipher,
				sendCipher: sendCipher,
			},
		}

		// From raw, not frame.data: frame has been reverted and decrypted in
		// place, while the replay identity is the bytes as they arrived.
		result.replayKey[0] = replayKeyDomainObfuscated
		copy(result.replayKey[1:], raw[hfOffsetKey:hfOffsetConnectionType])

		return result, nil
	}

	return MatchResult{}, ErrNoMatchingSecret
}

// peekTag decrypts exactly the four connection-type bytes of frame under one
// candidate key. AES-CTR is seekable and offsets 56..59 lie inside counter block
// 3 (bytes 48..63) at intra-block indices 8..11, so testing a candidate costs one
// SHA-256 compression (48 bytes of input), one AES-256 key expansion and ONE AES
// block -- not a 64-byte keystream. That is a 4x saving in the one loop an
// unauthenticated peer can force us to run.
//
// The nil-secret branch mirrors Obfuscator.getCipher, so ReadHandshake keeps its
// exact behaviour when it is used without MTProxy secret mixing.
func peekTag(raw *[hfLen]byte, secret []byte) ConnectionTag {
	blockKey := raw[hfOffsetKey:hfOffsetIV]

	var sum [sha256.Size]byte

	if secret != nil {
		hasher := sha256.New()
		hasher.Write(blockKey)
		hasher.Write(secret)
		blockKey = hasher.Sum(sum[:0])
	}

	block, _ := aes.NewCipher(blockKey)

	// cipher.NewCTR copies its IV, so the throwaway state here cannot disturb
	// the real ciphers built afterwards.
	var ctr [aes.BlockSize]byte

	copy(ctr[:], raw[hfOffsetIV:hfOffsetConnectionType])
	incrCounterBE(&ctr, 3)

	var keystream [aes.BlockSize]byte

	block.Encrypt(keystream[:], ctr[:])

	var tag ConnectionTag

	for i := range tag {
		tag[i] = raw[hfOffsetConnectionType+i] ^ keystream[hfOffsetConnectionType-3*aes.BlockSize+i]
	}

	return tag
}

// incrCounterBE adds n to a big-endian counter block, wrapping at 2^128. Go's
// cipher.NewCTR increments the IV big-endian, so keystream block k is E(IV+k).
func incrCounterBE(ctr *[aes.BlockSize]byte, n uint64) {
	for i := len(ctr) - 1; i >= 0 && n > 0; i-- {
		sum := uint64(ctr[i]) + n&0xff
		ctr[i] = byte(sum) //nolint:gosec // the low byte is the digit; the carry is kept in n below
		n = n>>8 + sum>>8
	}
}
