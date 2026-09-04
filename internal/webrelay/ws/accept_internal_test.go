package ws

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// The handshake's one externally-fixed value, checked against the vector printed
// in RFC 6455 itself rather than against anything this package computes.
//
// This test exists because its absence cost a working deployment. The accept
// GUID was wrong by one rotated character, and every other test still passed:
// they built the expected answer from the same constant the server used, so the
// two agreed with each other and disagreed with the world. A real browser
// recomputes the hash and refuses the socket before onopen -- a client that
// connects and instantly disconnects, with a valid-looking 101 in the server's
// log and nothing anywhere naming the cause.
//
// The key and its answer are copied from RFC 6455 section 1.3. Never derive
// either of them from this package.
func TestAcceptKeyMatchesTheRFCVector(t *testing.T) {
	t.Parallel()

	const (
		rfcKey    = "dGhlIHNhbXBsZSBub25jZQ=="
		rfcAccept = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
	)

	require.Equal(t, rfcAccept, acceptKey(rfcKey),
		"the accept key disagrees with RFC 6455: every browser will refuse this handshake")
}
