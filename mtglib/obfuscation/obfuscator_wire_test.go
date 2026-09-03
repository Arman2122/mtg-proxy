package obfuscation_test

import (
	"encoding/binary"
	"testing"

	"github.com/Arman2122/mtg-proxy/internal/testlib"
	"github.com/Arman2122/mtg-proxy/mtglib"
	"github.com/Arman2122/mtg-proxy/mtglib/obfuscation"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// generateHandshake rejects a candidate frame whose leading bytes would look
// like another transport; sample enough frames that a defect leaking ciphertext
// into byte 0 (bad for ~1/256 of frames) is seen with overwhelming probability.
const wireHandshakeSamples = 20000

// Magics generateHandshake refuses to emit as the first four wire bytes.
var wireForbiddenPrefixes = []uint32{
	0x44414548, // HEAD
	0x54534f50, // POST
	0x20544547, // GET
	0x4954504f, // OPTI
	0x02010316,
	0xdddddddd, // PaddedIntermediate header
	0xeeeeeeee, // Intermediate header
}

// Per https://core.telegram.org/mtproto/mtproto-transports only the last 8 bytes
// of the handshake frame go out encrypted: the wire form is
// plaintext[0:56] || ciphertext[56:64]. Anything else voids the fingerprint
// rejections generateHandshake makes, because the bytes it inspected are not the
// bytes that reach the wire.
//
// FuzzClientServerHandshakes cannot catch this. ReadHandshake only ever reads
// bytes 8..56 (key/IV) and 56..62 (connection type/DC) - it never inspects bytes
// 0..7 - so a frame whose prefix went out as ciphertext still round-trips
// perfectly. The damage is only visible to a passive observer, hence this test
// asserts on the captured wire bytes.
func TestSendHandshakeWirePrefixIsPlaintext(t *testing.T) {
	t.Parallel()

	secret := mtglib.GenerateSecret("hostname.com")
	obfs := obfuscation.Obfuscator{Secret: secret.Key[:]}

	frames := make([][]byte, 0, wireHandshakeSamples)

	connMock := &testlib.EssentialsConnMock{}
	connMock.
		On("Write", mock.AnythingOfType("[]uint8")).
		Return(64, nil).
		Run(func(args mock.Arguments) {
			arg := args.Get(0).([]byte)
			frames = append(frames, append([]byte(nil), arg...))
		})

	for range wireHandshakeSamples {
		_, err := obfs.SendHandshake(connMock, 2)
		require.NoError(t, err)
	}

	require.Len(t, frames, wireHandshakeSamples)

	// Count rather than fail fast, so a regression reports how badly it leaks.
	abridged, forbidden, zeroNoise := 0, 0, 0

	for _, wire := range frames {
		require.Len(t, wire, 64)

		if wire[0] == 0xef {
			abridged++
		}

		prefix := binary.LittleEndian.Uint32(wire[:4])
		for _, forbiddenPrefix := range wireForbiddenPrefixes {
			if prefix == forbiddenPrefix {
				forbidden++

				break
			}
		}

		if wire[4]|wire[5]|wire[6]|wire[7] == 0 {
			zeroNoise++
		}
	}

	assert.Zerof(t, abridged,
		"%d of %d frames lead with 0xef (abridged transport marker)", abridged, wireHandshakeSamples)
	assert.Zerof(t, forbidden,
		"%d of %d frames lead with a forbidden transport/HTTP magic", forbidden, wireHandshakeSamples)
	assert.Zerof(t, zeroNoise,
		"%d of %d frames have all-zero noise in bytes 4..7", zeroNoise, wireHandshakeSamples)
}

// The plaintext prefix must not cost the round trip: the server still has to
// recover the DC from a frame produced by SendHandshake.
func TestSendHandshakeRoundTripsAfterPlaintextPrefix(t *testing.T) {
	t.Parallel()

	secret := mtglib.GenerateSecret("hostname.com")
	obfs := obfuscation.Obfuscator{Secret: secret.Key[:]}

	for dc := 1; dc <= 5; dc++ {
		wire := make([]byte, 0, 64)

		writeMock := &testlib.EssentialsConnMock{}
		writeMock.
			On("Write", mock.AnythingOfType("[]uint8")).
			Once().
			Return(64, nil).
			Run(func(args mock.Arguments) {
				wire = append(wire, args.Get(0).([]byte)...)
			})

		_, err := obfs.SendHandshake(writeMock, dc)
		require.NoError(t, err)

		readMock := &testlib.EssentialsConnMock{}
		readMock.
			On("Read", mock.AnythingOfType("[]uint8")).
			Once().
			Return(64, nil).
			Run(func(args mock.Arguments) {
				copy(args.Get(0).([]byte), wire)
			})

		readDC, _, err := obfs.ReadHandshake(readMock)
		require.NoError(t, err)
		assert.Equal(t, dc, readDC)

		writeMock.AssertExpectations(t)
		readMock.AssertExpectations(t)
	}
}
