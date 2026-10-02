package mtglib

import (
	"io"
	"net"
	"testing"
	"time"

	"github.com/Arman2122/mtg-proxy/mtglib/internal/tls"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Telegram answers and hangs up, on each public door, through ServeConn, with
// the doppelganger pacing exactly as it does in production. The whole answer
// reaches the client before its EOF. On ee most of that answer is still in the
// pacing buffer at the moment Telegram hangs up, so this is the test that fails
// if ending the stream throws that buffer away.
func TestStreamEndDeliversTheWholeAnswer(t *testing.T) {
	t.Parallel()

	const answer = 512 << 10

	for _, entry := range govEntryCases()[:2] {
		t.Run(entry.name, func(t *testing.T) {
			t.Parallel()

			secret := entry.secret(t)

			// Not entry.harness: that one unpaces the doppelganger, and the pacing
			// is the point here.
			h := pacedHarness(t, map[string]Secret{"alice": secret}, nil)

			client, done := h.dialProxy(t, entry.policy)
			upstream := connectThrough(t, entry, h, client, "alice", secret.Key)

			defer endStream(client, upstream, done)

			go func() {
				upstream.Write(make([]byte, answer)) //nolint: errcheck
				upstream.(*net.TCPConn).CloseWrite() //nolint: errcheck,forcetypeassert
			}()

			assert.Equal(t, answer, answerBytesToEOF(t, entry, client),
				"every byte of Telegram's answer must reach the client before its EOF")
		})
	}
}

// answerBytesToEOF reads what the proxy sends the client after the handshake,
// up to EOF, and returns how many bytes of Telegram's answer it carried.
func answerBytesToEOF(t *testing.T, entry govEntryCase, client net.Conn) int {
	t.Helper()

	require.NoError(t, client.SetReadDeadline(time.Now().Add(10*time.Second)))

	if entry.mode != SecretModeFakeTLS {
		got, err := io.ReadAll(client)
		require.NoError(t, err, "the client must see a clean EOF, not a reset or a timeout")

		return len(got)
	}

	skipServerFlight(t, client)

	total := 0

	for {
		_, n, err := tls.ReadRecord(client, io.Discard)
		if err == io.EOF { //nolint: errorlint // io.ReadFull's bare EOF at a record boundary
			return total
		}

		require.NoError(t, err, "the client must see whole records and then a clean EOF")

		total += int(n)
	}
}
