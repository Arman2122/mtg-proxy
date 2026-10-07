package fake_test

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"testing"

	"github.com/Arman2122/mtg-proxy/internal/testclient"
	"github.com/Arman2122/mtg-proxy/mtglib/internal/tls/fake"
	"github.com/stretchr/testify/require"
)

// helloConn is the client's flight, replayed from memory: ReadClientHelloMulti
// only ever reads from its conn, so everything else is the nil embedded
// interface and would panic if that ever changed.
type helloConn struct {
	net.Conn

	flight bytes.Reader
}

func (c *helloConn) Read(p []byte) (int, error) {
	return c.flight.Read(p) //nolint: wrapcheck
}

// BenchmarkReadClientHelloMulti is the cost of the FakeTLS scan itself: one
// hello read against N secrets, with no network, no doppelganger and no
// governance around it. The names are
//
//	plain/N=<secrets>/<target>/hello=<bytes>
//
// where plain is ReadClientHelloMulti as it stands (a variant gets its own
// first element so a before/after comparison lines up row for row), and target
// is where the hello's key sits in the list: first, last, or miss (not in it).
//
// Setup stays outside the timed loop and the iterations are checked: a hello
// that landed on the wrong index, or a miss that matched, fails the benchmark
// instead of timing the wrong scan. ns/candidate is ns/op over the secrets
// tried -- 1 for first, N for last and miss -- so the figure compares across N.
func BenchmarkReadClientHelloMulti(b *testing.B) {
	const sni = "cover.example.com"

	for _, n := range []int{1, 10, 100, 1000, 5000} {
		for _, target := range []string{"first", "last", "miss"} {
			for _, size := range []int{517, 4096} {
				b.Run(fmt.Sprintf("plain/N=%d/%s/hello=%d", n, target, size), func(b *testing.B) {
					benchReadClientHelloMulti(b, sni, n, target, size)
				})
			}
		}
	}
}

func benchReadClientHelloMulti(b *testing.B, sni string, n int, target string, size int) {
	b.Helper()

	// The keys live in one backing array each, so the secrets the scan walks are
	// separate 16-byte slices, as the proxy's are.
	keys := make([][16]byte, n)
	secrets := make([][]byte, n)

	for i := range keys {
		_, err := rand.Read(keys[i][:])
		require.NoError(b, err)

		secrets[i] = keys[i][:]
	}

	var (
		helloKey   [16]byte
		wantIndex  = -1
		candidates = n
	)

	switch target {
	case "first":
		helloKey, wantIndex, candidates = keys[0], 0, 1
	case "last":
		helloKey, wantIndex = keys[n-1], n-1
	case "miss":
		_, err := rand.Read(helloKey[:])
		require.NoError(b, err)
	default:
		b.Fatalf("no such target %q", target)
	}

	sessionID := make([]byte, 32)
	_, err := rand.Read(sessionID)
	require.NoError(b, err)

	hello, err := testclient.ClientHelloPadded(helloKey, sni, sessionID, size)
	require.NoError(b, err)

	conn := &helloConn{}
	hostnames := []string{sni}

	// Once before the timer, in full: whichever index or error this hello
	// really produces is named here, not guessed from a number.
	conn.flight.Reset(hello)

	result, err := fake.ReadClientHelloMulti(conn, secrets, hostnames, TolerateTime)
	if wantIndex >= 0 {
		require.NoError(b, err, "the hello's key is at index %d of %d", wantIndex, n)
	} else {
		require.ErrorIs(b, err, fake.ErrBadDigest, "the hello's key is in none of the %d secrets", n)
	}

	require.Equal(b, wantIndex, result.MatchedIndex)
	require.Equal(b, sni, result.MatchedHost)

	b.ReportAllocs()

	for b.Loop() {
		conn.flight.Reset(hello)

		result, err = fake.ReadClientHelloMulti(conn, secrets, hostnames, TolerateTime)

		// Cheap enough to stay in the loop, and what makes a wrong target loud.
		if result == nil || result.MatchedIndex != wantIndex || (err == nil) != (wantIndex >= 0) ||
			(err != nil && !errors.Is(err, fake.ErrBadDigest)) {
			b.Fatalf("result %+v, error %v: want matched index %d", result, err, wantIndex)
		}
	}

	b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N)/float64(candidates), "ns/candidate")
}
