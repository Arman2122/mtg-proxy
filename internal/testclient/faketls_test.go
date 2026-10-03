package testclient

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The ClientHello's random is the HMAC of the whole message under the key,
// computed with the random zeroed, XORed with a little-endian timestamp in its
// last four bytes -- exactly what the proxy's FakeTLS reader checks.
func TestClientHelloCarriesTheDigest(t *testing.T) {
	t.Parallel()

	key := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}

	hello, err := ClientHello(key, "cover.example.com", make([]byte, 32))
	require.NoError(t, err)

	random := append([]byte(nil), hello[randomOffset:randomOffset+randomLen]...)

	zeroed := append([]byte(nil), hello...)
	clear(zeroed[randomOffset : randomOffset+randomLen])

	mac := hmac.New(sha256.New, key[:])
	mac.Write(zeroed)
	digest := mac.Sum(nil)

	for i := range random {
		random[i] ^= digest[i]
	}

	assert.Equal(t, make([]byte, randomLen-4), random[:randomLen-4], "the random must be the digest")

	stamp := time.Unix(int64(binary.LittleEndian.Uint32(random[randomLen-4:])), 0)
	assert.WithinDuration(t, time.Now(), stamp, 5*time.Second, "its last four bytes carry the time")
	assert.Contains(t, string(hello), "cover.example.com", "the SNI is the cover host")
}

func TestClientHelloRefusesWhatTLSCannotCarry(t *testing.T) {
	t.Parallel()

	_, err := ClientHello([16]byte{}, "", nil)
	require.Error(t, err, "an empty SNI")

	_, err = ClientHello([16]byte{}, "cover.example.com", make([]byte, 33))
	require.Error(t, err, "a session ID longer than 32 bytes")
}
