package obfuscation_test

import (
	"bytes"
	"io"
	"testing"

	"github.com/Arman2122/mtg-proxy/mtglib/obfuscation"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type MatcherGoldenTestSuite struct {
	SnapshotTestSuite
}

func (s *MatcherGoldenTestSuite) SetupSuite() {
	s.Setup("", "client-handshake")
}

// The checked-in snapshots are real captured handshakes plus the plaintext they
// decrypt to. Matching against them proves the returned conn is positioned at
// keystream offset 64 independently of SendHandshake -- a synthetic round trip
// where both sides share the same offset bug would pass regardless.
func (s *MatcherGoldenTestSuite) TestSnapshot() {
	for name, snapshot := range s.snapshots {
		s.T().Run(name, func(t *testing.T) {
			wire := bytes.NewBuffer(nil)
			wire.Write(snapshot.Frame.data)
			wire.Write(snapshot.Decrypted.Cipher.data)

			// The real key sits behind decoys so a matcher that ignores Index,
			// or always commits to keys[0], fails here.
			keys := [][]byte{randomKey(), randomKey(), snapshot.Secret.data, randomKey()}

			transport := &memConn{read: bytes.NewReader(wire.Bytes())}

			result, err := obfuscation.MatchHandshake(transport, keys, allTagsSet)
			require.NoError(t, err)

			assert.Equal(t, 2, result.Index)
			assert.EqualValues(t, 2, result.DC)
			assert.Equal(t, obfuscation.TagPaddedIntermediate, result.Tag)

			assert.Equal(t, byte(0x01), result.ReplayKey()[0])
			assert.Equal(t, snapshot.Frame.data[8:56], result.ReplayKey()[1:])

			got := make([]byte, len(snapshot.Decrypted.Text.data))
			_, err = io.ReadFull(result.Conn, got)
			require.NoError(t, err)

			assert.Equal(t, snapshot.Decrypted.Text.data, got)

			// And the reply direction, from the same match: the send cipher is
			// derived from the reverted frame and is never advanced by the
			// handshake, so it must start at keystream offset 0.
			_, err = result.Conn.Write(bytes.Clone(snapshot.Encrypted.Text.data))
			require.NoError(t, err)
			assert.Equal(t, snapshot.Encrypted.Cipher.data, transport.wrote.Bytes())
		})
	}
}

func TestMatcherGolden(t *testing.T) {
	t.Parallel()
	suite.Run(t, &MatcherGoldenTestSuite{})
}
