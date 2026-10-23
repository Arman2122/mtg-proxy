package mtglib

import (
	"io"
	"net"
	"testing"

	"github.com/Arman2122/mtg-proxy/internal/testclient"
	"github.com/Arman2122/mtg-proxy/mtglib/obfuscation"
	"github.com/stretchr/testify/require"
)

// The client side of every door lives in internal/testclient, shared with the
// load tool. These are the names this package's tests have always called it
// by, failing the test instead of returning an error.

func fakeTLSClientHello(t testing.TB, key [SecretKeyLength]byte, sni string, sessionID []byte) []byte {
	t.Helper()

	hello, err := testclient.ClientHello(key, sni, sessionID)
	require.NoError(t, err)

	return hello
}

// fakeTLSClientHelloPadded is fakeTLSClientHello for a hello whose whole record
// is exactly size bytes, which is what a real client's 517 looks like.
func fakeTLSClientHelloPadded(t testing.TB, key [SecretKeyLength]byte, sni string, sessionID []byte, size int) []byte {
	t.Helper()

	hello, err := testclient.ClientHelloPadded(key, sni, sessionID, size)
	require.NoError(t, err)

	return hello
}

func obfuscatedFrame(t testing.TB, key [SecretKeyLength]byte, tag obfuscation.ConnectionTag, dcID int) []byte {
	t.Helper()

	frame, err := testclient.ObfuscatedFrame(key, tag, dcID)
	require.NoError(t, err)

	return frame
}

func tlsApplicationRecord(payload []byte) []byte {
	return testclient.ApplicationRecord(payload)
}

func resetOnClose(tb testing.TB, conn net.Conn) {
	tb.Helper()

	require.NoError(tb, testclient.ResetOnClose(conn), "the harness hands out TCP connections")
}

// goldenRecord is one TLS record as it arrived, kept whole because the
// ServerHello digest is computed over the concatenation of all three.
type goldenRecord struct {
	recordType byte
	version    [2]byte
	payload    []byte
	raw        []byte
}

func goldenRecordOf(r testclient.Record) goldenRecord {
	return goldenRecord{recordType: r.Type, version: r.Version, payload: r.Payload, raw: r.Raw}
}

// goldenReadRecord reads exactly one TLS record. A header declaring more than a
// record may carry fails by name, which is what turns "the doppelganger wrap was
// removed" into a named failure instead of a hang.
func goldenReadRecord(t *testing.T, r io.Reader) goldenRecord {
	t.Helper()

	record, err := testclient.ReadRecord(r)
	require.NoError(t, err)

	return goldenRecordOf(record)
}

// goldenReadFlight reads the whole server flight: exactly three records --
// ServerHello, ChangeCipherSpec and ONE fake ApplicationData. The client HMACs
// over all three, so a fourth record, or a missing one, breaks every real
// client. The concatenation is returned because that is what the HMAC covers.
func goldenReadFlight(t *testing.T, r io.Reader) ([]goldenRecord, []byte) {
	t.Helper()

	records, flight, err := testclient.ReadServerFlight(r)
	require.NoError(t, err)

	golden := make([]goldenRecord, len(records))
	for i, record := range records {
		golden[i] = goldenRecordOf(record)
	}

	return golden, flight
}
