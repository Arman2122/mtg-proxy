package obfuscation

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"testing"

	"github.com/Arman2122/mtg-proxy/essentials"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// memConn is an essentials.Conn over two buffers. The embedded interface is nil
// on purpose: MatchHandshake and the conn it returns only ever Read and Write,
// so anything else must panic loudly rather than quietly do nothing.
type memConn struct {
	essentials.Conn

	read  *bytes.Reader
	wrote bytes.Buffer
}

func (m *memConn) Read(p []byte) (int, error) {
	return m.read.Read(p) //nolint: wrapcheck
}

func (m *memConn) Write(p []byte) (int, error) {
	return m.wrote.Write(p) //nolint: wrapcheck
}

func testKey(tb testing.TB) []byte {
	tb.Helper()

	key := make([]byte, 16)
	_, err := rand.Read(key)
	require.NoError(tb, err)

	return key
}

// clientHandshake produces the exact bytes a client sends: a 64-byte frame for
// tag/dc under secret, followed by payload encrypted with the client's send
// cipher (which is the server's recv cipher).
func clientHandshake(tb testing.TB, secret []byte, tag ConnectionTag, dc int, payload []byte) []byte {
	tb.Helper()

	sink := &memConn{}

	cn, err := Obfuscator{Secret: secret}.SendHandshake(sink, dc, tag)
	require.NoError(tb, err)

	if len(payload) > 0 {
		// conn.Write encrypts in place, so hand it a copy.
		_, err = cn.Write(bytes.Clone(payload))
		require.NoError(tb, err)
	}

	return sink.wrote.Bytes()
}

// fullKeystreamTag is peekTag's reference implementation: derive the receive
// cipher exactly as ReadHandshake does and decrypt all 64 bytes.
func fullKeystreamTag(raw [hfLen]byte, secret []byte) ConnectionTag {
	frame := handshakeFrame{data: raw}
	stream := Obfuscator{Secret: secret}.getCipher(&frame, sha256.New())
	stream.XORKeyStream(frame.data[:], frame.data[:])

	return ConnectionTag(frame.connectionType())
}

// peekTag reads four bytes out of counter block 3 instead of running the whole
// 64-byte keystream. If that shortcut is ever off by a block or an index, this
// is the test that says so.
func TestPeekTagAgreesWithFullKeystream(t *testing.T) {
	t.Parallel()

	tags := []ConnectionTag{TagPaddedIntermediate, TagIntermediate, TagAbridged}

	for i := range 1000 {
		tag := tags[i%len(tags)]
		secret := testKey(t)

		wire := clientHandshake(t, secret, tag, 1+i%5, nil)
		require.Len(t, wire, hfLen)

		raw := [hfLen]byte(wire)

		assert.Equal(t, tag, fullKeystreamTag(raw, secret), "frame %d", i)
		assert.Equal(t, tag, peekTag(&raw, secret), "frame %d", i)
	}
}

// Random frames decrypt to garbage tags; peekTag must still agree with the full
// keystream there, which is the case an attacker actually drives.
func TestPeekTagAgreesOnGarbage(t *testing.T) {
	t.Parallel()

	for i := range 1000 {
		var raw [hfLen]byte

		_, err := rand.Read(raw[:])
		require.NoError(t, err)

		secret := testKey(t)

		assert.Equal(t, fullKeystreamTag(raw, secret), peekTag(&raw, secret), "frame %d", i)
	}
}

// Randomised frames hit the counter carry only when the IV's low byte is >= 0xfd,
// i.e. ~1% of the time and never across all 16 bytes. Pin the full carry.
func TestPeekTagCounterCarry(t *testing.T) {
	t.Parallel()

	var raw [hfLen]byte

	_, err := rand.Read(raw[:hfOffsetIV])
	require.NoError(t, err)

	for i := hfOffsetIV; i < hfOffsetConnectionType; i++ {
		raw[i] = 0xff
	}

	secret := testKey(t)

	assert.Equal(t, fullKeystreamTag(raw, secret), peekTag(&raw, secret))
}

// The nil secret is the direct-to-DC case: getCipher skips the SHA-256 mix, and
// peekTag has to skip it too or ReadHandshake changes behaviour for dcprobe.
func TestPeekTagNilSecret(t *testing.T) {
	t.Parallel()

	wire := clientHandshake(t, nil, TagPaddedIntermediate, 2, nil)
	raw := [hfLen]byte(wire)

	assert.Equal(t, TagPaddedIntermediate, peekTag(&raw, nil))
	assert.Equal(t, fullKeystreamTag(raw, nil), peekTag(&raw, nil))
}

func TestIncrCounterBE(t *testing.T) {
	t.Parallel()

	var ctr [aes.BlockSize]byte

	incrCounterBE(&ctr, 3)
	assert.Equal(t, byte(3), ctr[15])
	assert.Equal(t, byte(0), ctr[14])

	// Carry out of the low byte.
	ctr = [aes.BlockSize]byte{}
	ctr[15] = 0xff
	incrCounterBE(&ctr, 3)
	assert.Equal(t, byte(0x02), ctr[15])
	assert.Equal(t, byte(0x01), ctr[14])

	// Carry across every byte, wrapping at 2^128.
	for i := range ctr {
		ctr[i] = 0xff
	}

	incrCounterBE(&ctr, 3)
	assert.Equal(t, byte(0x02), ctr[15])

	for i := range 15 {
		assert.Equal(t, byte(0), ctr[i], "byte %d", i)
	}
}

func TestMatchHandshakeFindsTheRightCandidate(t *testing.T) {
	t.Parallel()

	const total = 8

	keys := make([][]byte, total)
	for i := range keys {
		keys[i] = testKey(t)
	}

	for want := range total {
		wire := clientHandshake(t, keys[want], TagIntermediate, 3, nil)

		result, err := MatchHandshake(
			&memConn{read: bytes.NewReader(wire)}, keys, allTagsInternal)
		require.NoError(t, err)

		assert.Equal(t, want, result.Index)
		assert.Equal(t, 3, result.DC)
		assert.Equal(t, TagIntermediate, result.Tag)
	}
}

// THE bug this design exists to avoid: peekTag leaves a cipher at keystream
// block 3, and handing that back would decrypt every subsequent byte at the
// wrong offset. The returned conn must sit at offset 64, exactly where
// ReadHandshake leaves it.
func TestMatchHandshakeConnStartsAtKeystreamOffset64(t *testing.T) {
	t.Parallel()

	payload := make([]byte, 512)
	_, err := rand.Read(payload)
	require.NoError(t, err)

	for _, tag := range []ConnectionTag{TagPaddedIntermediate, TagIntermediate, TagAbridged} {
		key := testKey(t)
		decoys := [][]byte{testKey(t), testKey(t), key, testKey(t)}

		wire := clientHandshake(t, key, tag, 2, payload)
		require.Len(t, wire, hfLen+len(payload))

		result, err := MatchHandshake(
			&memConn{read: bytes.NewReader(wire)}, decoys, allTagsInternal)
		require.NoError(t, err)
		require.Equal(t, 2, result.Index)

		got := make([]byte, len(payload))
		_, err = io.ReadFull(result.Conn, got)
		require.NoError(t, err)

		assert.Equal(t, payload, got, "tag %s", tag)
	}
}

// The reply direction has to be usable too: the send cipher is derived from the
// reverted frame, so a match must produce the same pair ReadHandshake does.
func TestMatchHandshakeRoundTripsWithReadHandshake(t *testing.T) {
	t.Parallel()

	key := testKey(t)
	wire := clientHandshake(t, key, TagAbridged, 4, nil)

	matched, err := MatchHandshake(
		&memConn{read: bytes.NewReader(wire)}, [][]byte{key}, allTagsInternal)
	require.NoError(t, err)

	dc, tag, _, err := Obfuscator{Secret: key}.ReadHandshake(
		&memConn{read: bytes.NewReader(wire)}, allTagsInternal)
	require.NoError(t, err)

	assert.Equal(t, matched.DC, dc)
	assert.Equal(t, matched.Tag, tag)
	assert.Equal(t, 4, dc)
	assert.Equal(t, TagAbridged, tag)
}

// The replay identity is the client-chosen key and IV as they ARRIVED. The frame
// is reverted and decrypted in place during the match, so reading it back out of
// the frame instead of the raw bytes would key the anti-replay cache on the
// wrong 48 bytes.
func TestMatchResultReplayKey(t *testing.T) {
	t.Parallel()

	key := testKey(t)
	wire := clientHandshake(t, key, TagPaddedIntermediate, 2, nil)

	result, err := MatchHandshake(
		&memConn{read: bytes.NewReader(wire)}, [][]byte{key}, allTagsInternal)
	require.NoError(t, err)

	replayKey := result.ReplayKey()
	require.Len(t, replayKey, 1+hfLenKey+hfLenIV)

	assert.Equal(t, byte(0x01), replayKey[0])
	assert.Equal(t, wire[hfOffsetKey:hfOffsetConnectionType], replayKey[1:])

	// Identical frames must produce identical keys, or the cache never fires.
	again, err := MatchHandshake(
		&memConn{read: bytes.NewReader(wire)}, [][]byte{key}, allTagsInternal)
	require.NoError(t, err)
	assert.Equal(t, replayKey, again.ReplayKey())
}

func TestMatchHandshakeRejectsUnhonouredTag(t *testing.T) {
	t.Parallel()

	key := testKey(t)

	for _, tag := range []ConnectionTag{TagIntermediate, TagAbridged} {
		wire := clientHandshake(t, key, tag, 2, nil)

		_, err := MatchHandshake(
			&memConn{read: bytes.NewReader(wire)},
			[][]byte{key},
			TagSetOf(TagPaddedIntermediate))

		require.ErrorIs(t, err, ErrNoMatchingSecret)
	}

	// The same frame under the same key is accepted once the tag is honoured.
	wire := clientHandshake(t, key, TagAbridged, 2, nil)
	_, err := MatchHandshake(
		&memConn{read: bytes.NewReader(wire)}, [][]byte{key}, TagSetOf(TagAbridged))
	require.NoError(t, err)
}

func TestMatchHandshakeNoKeys(t *testing.T) {
	t.Parallel()

	wire := clientHandshake(t, testKey(t), TagPaddedIntermediate, 2, nil)

	_, err := MatchHandshake(&memConn{read: bytes.NewReader(wire)}, nil, allTagsInternal)
	require.ErrorIs(t, err, ErrNoMatchingSecret)
}

// A truncated frame is a transport failure, not an authentication failure. The
// caller has to be able to tell them apart: only the latter is a refusal that
// should be counted against a peer.
func TestMatchHandshakeShortRead(t *testing.T) {
	t.Parallel()

	wire := clientHandshake(t, testKey(t), TagPaddedIntermediate, 2, nil)

	_, err := MatchHandshake(
		&memConn{read: bytes.NewReader(wire[:hfLen-1])}, [][]byte{testKey(t)}, allTagsInternal)

	require.Error(t, err)
	assert.False(t, errors.Is(err, ErrNoMatchingSecret))
	assert.ErrorIs(t, err, io.ErrUnexpectedEOF)
}

var allTagsInternal = TagSetOf(TagPaddedIntermediate, TagIntermediate, TagAbridged)

// Random bytes must not authenticate against a large key set. A false positive
// costs ~|allowed|/2^32 per candidate, so 256 keys and every tag honoured is the
// worst case the design permits.
func FuzzMatchHandshakeNoFalseMatch(f *testing.F) {
	f.Add(make([]byte, hfLen))
	f.Add(bytes.Repeat([]byte{0xdd}, hfLen))

	keys := make([][]byte, 256)
	for i := range keys {
		keys[i] = make([]byte, 16)
		binary.LittleEndian.PutUint64(keys[i], uint64(i)) // deterministic, so a hit reproduces
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		var raw [hfLen]byte

		copy(raw[:], data)

		_, err := MatchHandshake(
			&memConn{read: bytes.NewReader(raw[:])}, keys, allTagsInternal)

		require.ErrorIs(t, err, ErrNoMatchingSecret)
	})
}
