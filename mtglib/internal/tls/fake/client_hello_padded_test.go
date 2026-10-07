package fake_test

import (
	"bytes"
	"testing"
	"time"

	"github.com/Arman2122/mtg-proxy/internal/testclient"
	"github.com/Arman2122/mtg-proxy/mtglib/internal/tls/fake"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testclient cannot import this package -- mtglib/internal is closed to it --
// so the proof that a padded hello is one the FakeTLS reader accepts, and not
// merely one that has the right length, lives here.
//
// 517 to 16,389 are one record. Above that the reader gets the same message cut
// across records and puts it back together: 16,390 is the first size that needs
// two, 40,000 needs three, and 65,540 is the largest hello it takes at all.
func TestClientHelloPaddedIsStillAValidHello(t *testing.T) {
	t.Parallel()

	const sni = "cover.example.com"

	key := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	decoy := [16]byte{16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1}

	for _, size := range []int{517, 600, 4096, 16000, 16389, 16390, 40000, 65540} {
		hello, err := testclient.ClientHelloWith(key, sni, make([]byte, 32), testclient.HelloOptions{PadTo: size})
		require.NoError(t, err, "size %d", size)

		wire := bytes.NewBuffer(hello)

		result, err := fake.ReadClientHelloMulti(
			&parseClientHelloConnMock{readBuf: wire}, [][]byte{key[:]}, []string{sni}, TolerateTime)
		require.NoError(t, err, "size %d", size)

		assert.Equal(t, 0, result.MatchedIndex)
		assert.Equal(t, sni, result.MatchedHost)
		assert.Zero(t, wire.Len(), "size %d: the reader took the hello and nothing is left over", size)

		// The digest is what picks the key, so the same hello among decoys is
		// found at its own place, and under no other key it is refused.
		wire = bytes.NewBuffer(hello)

		result, err = fake.ReadClientHelloMulti(
			&parseClientHelloConnMock{readBuf: wire}, [][]byte{decoy[:], key[:]}, []string{sni}, TolerateTime)
		require.NoError(t, err, "size %d", size)
		assert.Equal(t, 1, result.MatchedIndex)

		wire = bytes.NewBuffer(hello)

		result, err = fake.ReadClientHelloMulti(
			&parseClientHelloConnMock{readBuf: wire}, [][]byte{decoy[:]}, []string{sni}, TolerateTime)
		require.ErrorIs(t, err, fake.ErrBadDigest, "size %d", size)
		assert.Equal(t, -1, result.MatchedIndex)
	}
}

// The reader's clock check, driven from the client: a hello stamped ten seconds
// ago is refused by a reader that tolerates three, and taken by one that
// tolerates thirty. A stamp ten seconds ahead is no different.
func TestClientHelloWithCanBeSkewed(t *testing.T) {
	t.Parallel()

	const sni = "cover.example.com"

	key := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}

	for _, size := range []int{0, 517, 40000} {
		for name, at := range map[string]time.Time{
			"ten seconds late":  time.Now().Add(-10 * time.Second),
			"ten seconds early": time.Now().Add(10 * time.Second),
		} {
			hello, err := testclient.ClientHelloWith(key, sni, make([]byte, 32), testclient.HelloOptions{PadTo: size, At: at})
			require.NoError(t, err, "size %d, %s", size, name)

			result, err := fake.ReadClientHelloMulti(
				&parseClientHelloConnMock{readBuf: bytes.NewBuffer(hello)}, [][]byte{key[:]}, []string{sni}, 3*time.Second)
			require.ErrorIs(t, err, fake.ErrBadDigest, "size %d, %s, 3s tolerated", size, name)
			assert.Equal(t, -1, result.MatchedIndex)

			result, err = fake.ReadClientHelloMulti(
				&parseClientHelloConnMock{readBuf: bytes.NewBuffer(hello)}, [][]byte{key[:]}, []string{sni}, 30*time.Second)
			require.NoError(t, err, "size %d, %s, 30s tolerated", size, name)
			assert.Equal(t, 0, result.MatchedIndex)
		}
	}
}
