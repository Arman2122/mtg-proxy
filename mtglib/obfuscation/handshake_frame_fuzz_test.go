package obfuscation

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
)

func FuzzGenerateHandshakeFrame(f *testing.F) {
	f.Fuzz(func(t *testing.T, arg int16) {
		// The leading-noise rejections must hold for every transport: they
		// concern bytes 0..7 and are orthogonal to the tag at offset 56.
		for _, tag := range []ConnectionTag{TagPaddedIntermediate, TagIntermediate, TagAbridged} {
			frame := generateHandshake(int(arg), tag)

			assert.NotEqualValues(t, 0xef, frame.data[0])

			firstBytes := binary.LittleEndian.Uint32(frame.data[:4])
			assert.NotEqualValues(t, 0x44414548, firstBytes)
			assert.NotEqualValues(t, 0x54534f50, firstBytes)
			assert.NotEqualValues(t, 0x20544547, firstBytes)
			assert.NotEqualValues(t, 0x4954504f, firstBytes)
			assert.NotEqualValues(t, 0x02010316, firstBytes)
			assert.NotEqualValues(t, 0xeeeeeeee, firstBytes)
			assert.NotEqualValues(t, 0xdddddddd, firstBytes)

			assert.NotEqualValues(
				t,
				0,
				frame.data[4]|frame.data[5]|frame.data[6]|frame.data[7],
			)

			assert.Equal(t, tag[:], frame.connectionType())

			dc := arg
			if dc < 0 {
				dc = -dc
			} else if dc == 0 {
				dc = defaultDC
			}

			assert.EqualValues(t, dc, frame.dc())
		}
	})
}
