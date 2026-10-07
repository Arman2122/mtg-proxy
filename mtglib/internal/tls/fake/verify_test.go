package fake

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"math"
	"math/rand/v2"
	"net"
	"slices"
	"testing"
	"time"

	"github.com/Arman2122/mtg-proxy/internal/testclient"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	coverSNI = "cover.example.com"
	otherSNI = "other.example.org"
)

// referenceMatch is ReadClientHelloMulti exactly as it stood at ba44784, before
// parse and verify were split: parse, SNI gate, then one hmac.New per secret.
// It is the oracle the split is held to, so it is never edited to follow the
// code under test.
func referenceMatch(
	conn net.Conn,
	secrets [][]byte,
	hostnames []string,
	tolerateTimeSkewness time.Duration,
) (*ReadClientHelloResult, error) {
	clientHelloCopy, handshakeReader, err := parseClientHello(conn)
	if err != nil {
		return nil, fmt.Errorf("cannot read client hello: %w", err)
	}

	hello, err := parseHandshake(handshakeReader)
	if err != nil {
		return nil, fmt.Errorf("cannot parse handshake: %w", err)
	}

	sniHostnames, err := parseSNI(handshakeReader)
	if err != nil {
		return nil, fmt.Errorf("cannot parse SNI: %w", err)
	}

	var matchedHost string

	for _, h := range hostnames {
		if slices.Contains(sniHostnames, h) {
			matchedHost = h

			break
		}
	}

	if matchedHost == "" {
		return nil, fmt.Errorf("cannot find any of %v in %v", hostnames, sniHostnames)
	}

	// Save the full client hello bytes so we can replay them for each secret.
	handshakeBytes := clientHelloCopy.Bytes()

	for idx, secret := range secrets {
		digest := hmac.New(sha256.New, secret)

		// Write the handshake with client random all nullified.
		digest.Write(handshakeBytes[:RandomOffset])
		digest.Write(emptyRandom[:])
		digest.Write(handshakeBytes[RandomOffset+RandomLen:])

		computed := digest.Sum(nil)

		for i := range RandomLen {
			computed[i] ^= hello.Random[i]
		}

		if subtle.ConstantTimeCompare(emptyRandom[:RandomLen-4], computed[:RandomLen-4]) != 1 {
			continue
		}

		timestamp := int64(binary.LittleEndian.Uint32(computed[RandomLen-4:]))
		createdAt := time.Unix(timestamp, 0)

		if tdiff := time.Since(createdAt).Abs(); tdiff > tolerateTimeSkewness {
			continue
		}

		return &ReadClientHelloResult{
			Hello:        hello,
			MatchedIndex: idx,
			MatchedHost:  matchedHost,
		}, nil
	}

	// Return a partial result so the caller can use matchedHost for domain
	// fronting even when no secret matched the HMAC (e.g. a DPI probe with
	// a valid SNI but garbage payload).
	return &ReadClientHelloResult{
		MatchedIndex: -1,
		MatchedHost:  matchedHost,
	}, ErrBadDigest
}

// wireConn replays a client's flight from memory. The parser only reads, so
// everything else is the nil embedded interface.
type wireConn struct {
	net.Conn

	r *bytes.Reader
}

func (c *wireConn) Read(p []byte) (int, error) {
	return c.r.Read(p)
}

func connOf(wire []byte) net.Conn {
	return &wireConn{r: bytes.NewReader(wire)}
}

type outcome struct {
	result *ReadClientHelloResult
	err    error
}

// builders are the two ways to make a Candidate. Both must give the same
// answer as the reference on every hello.
var builders = []struct {
	name  string
	build func([]byte) *Candidate
}{
	{"pads", NewCandidate},
	{"plain", NewPlainCandidate},
}

// scan is the loop mtglib runs on these primitives: candidates built once,
// one parse, then Verify in order. Its result is shaped like
// ReadClientHelloMulti's so the two compare field for field.
func scan(build func([]byte) *Candidate, wire []byte, secrets [][]byte, hostnames []string, skew time.Duration) outcome {
	candidates := make([]*Candidate, len(secrets))
	for i, secret := range secrets {
		candidates[i] = build(secret)
	}

	parsed, err := ParseClientHelloFor(connOf(wire), hostnames)
	if err != nil {
		return outcome{nil, err}
	}

	for idx, candidate := range candidates {
		if parsed.Verify(candidate, skew) {
			return outcome{&ReadClientHelloResult{
				Hello:        parsed.Hello,
				MatchedIndex: idx,
				MatchedHost:  parsed.MatchedHost,
			}, nil}
		}
	}

	return outcome{&ReadClientHelloResult{MatchedIndex: -1, MatchedHost: parsed.MatchedHost}, ErrBadDigest}
}

func requireSameOutcome(t testing.TB, want, got outcome, msgAndArgs ...any) {
	t.Helper()

	require.Equal(t, want.result, got.result, msgAndArgs...)

	if want.err == nil {
		require.NoError(t, got.err, msgAndArgs...)

		return
	}

	require.EqualError(t, got.err, want.err.Error(), msgAndArgs...)
	require.Equal(t, errors.Is(want.err, ErrBadDigest), errors.Is(got.err, ErrBadDigest), msgAndArgs...)
}

// agreeWithReference runs one flight through the reference, the
// ReadClientHelloMulti wrapper and the scan with each builder, and fails unless
// all four say the same; label names the flight in a failure. The reference
// runs again at the end: if it changed its own answer, a timestamp crossed the
// skew bound between the runs, and stable is false (nothing was compared).
func agreeWithReference(
	t testing.TB,
	wire []byte,
	secrets [][]byte,
	hostnames []string,
	skew time.Duration,
	label string,
) (outcome, bool) {
	t.Helper()

	var want outcome

	want.result, want.err = referenceMatch(connOf(wire), secrets, hostnames, skew)

	var wrapper outcome

	wrapper.result, wrapper.err = ReadClientHelloMulti(connOf(wire), secrets, hostnames, skew)

	pads := scan(NewCandidate, wire, secrets, hostnames, skew)
	plain := scan(NewPlainCandidate, wire, secrets, hostnames, skew)

	var again outcome

	again.result, again.err = referenceMatch(connOf(wire), secrets, hostnames, skew)

	if (want.err == nil) != (again.err == nil) || want.result != nil && again.result != nil &&
		want.result.MatchedIndex != again.result.MatchedIndex {
		return want, false
	}

	requireSameOutcome(t, want, wrapper, "ReadClientHelloMulti: %s", label)
	requireSameOutcome(t, want, pads, "NewCandidate: %s", label)
	requireSameOutcome(t, want, plain, "NewPlainCandidate: %s", label)

	return want, true
}

func randomBytes(rng *rand.Rand, b []byte) {
	for i := range b {
		b[i] = byte(rng.Uint32())
	}
}

// TestVerifyAgreesWithTheReferenceMatcher holds the split to the matcher it
// replaces over 10,000 seeded hellos: 1 to 20 secrets with the hello's key at
// any position, twice in the list, or absent; fresh stamps and stamps ten
// seconds off under a 3 s and a 30 s tolerance; one bit of the client random
// flipped, at every position in turn; SNIs the gate refuses; and sizes from
// about 80 bytes to 64 KiB, the large ones cut across records. The generator
// also predicts each answer itself, and the classes are counted at the end, so
// a generator that only ever made misses cannot pass.
func TestVerifyAgreesWithTheReferenceMatcher(t *testing.T) {
	t.Parallel()

	const scenarios = 10_000

	// The large hellos: the last single record, the first that needs two, three
	// records, the largest taken, and 0 for a random size above one record.
	largeSizes := []int{16389, 16390, 40000, 65540, 0}

	var counts struct {
		matched, matchedDuplicate, wrongKey, skewRejected, skewAccepted int
		tampered, gateRefused, fragmented, unstable                     int
		tamperedAt                                                      [RandomLen]int
	}

	// Seeded, so a failing scenario number names the same hello on every run.
	rng := rand.New(rand.NewPCG(20261007, 3))

	for scenario := range scenarios {
		large := scenario%100 == 0

		n := 1 + rng.IntN(20)
		if large {
			n = 1 + rng.IntN(3)
		}

		// One backing array per key, so secrets[k] is keys[k] and a duplicate
		// written into keys shows in secrets.
		keys := make([][16]byte, n)
		secrets := make([][]byte, n)

		for k := range keys {
			randomBytes(rng, keys[k][:])
			secrets[k] = keys[k][:]
		}

		var helloKey [16]byte

		want, duplicate, wrongKey := -1, false, false

		if rng.IntN(5) == 0 {
			randomBytes(rng, helloKey[:])

			wrongKey = true
		} else {
			k := rng.IntN(n)
			helloKey, want = keys[k], k

			if n > 1 && rng.IntN(5) == 0 {
				j := rng.IntN(n - 1)
				if j >= k {
					j++
				}

				keys[j] = helloKey
				want, duplicate = min(j, k), j < k
			}
		}

		var at time.Time

		skewed := false

		switch rng.IntN(10) {
		case 0:
			at, skewed = time.Now().Add(-10*time.Second), true
		case 1:
			at, skewed = time.Now().Add(10*time.Second), true
		}

		skew := 3 * time.Second
		if rng.IntN(5) == 0 {
			skew = 30 * time.Second
		}

		padTo := 0

		switch {
		case large:
			padTo = largeSizes[(scenario/100)%len(largeSizes)]
			if padTo == 0 {
				padTo = 16390 + rng.IntN(65540-16390+1)
			}
		case rng.IntN(3) > 0:
			// An unpadded hello here is at most 110 bytes, so 114 always leaves
			// room for the 4-byte padding extension header.
			padTo = 114 + rng.IntN(4096-114+1)
		}

		sni, hostnames := coverSNI, []string{coverSNI}

		switch rng.IntN(8) {
		case 0:
			sni, hostnames = otherSNI, []string{coverSNI, otherSNI}
		case 1:
			hostnames = []string{otherSNI, coverSNI}
		}

		gateRefused := rng.IntN(50) == 0
		if gateRefused {
			hostnames = []string{"absent.example.net"}
		}

		sessionID := make([]byte, rng.IntN(33))
		randomBytes(rng, sessionID)

		wire, err := testclient.ClientHelloWith(helloKey, sni, sessionID, testclient.HelloOptions{PadTo: padTo, At: at})
		require.NoError(t, err, "scenario %d", scenario)

		if skewed && skew < 10*time.Second {
			want = -1
		}

		tamperAt := -1

		if want >= 0 && rng.IntN(20) == 0 {
			// Every position in turn, so byte 27 (the last one compared) is
			// certain to be hit. The first 28 bytes are digest; in the last 4 (the
			// timestamp) only flips worth 64 s or more are made, so the result is
			// a refusal under either tolerance and never near its edge.
			tamperAt = counts.tampered % RandomLen
			bit := rng.IntN(8)

			if tamperAt == RandomLen-4 {
				bit = 6 + rng.IntN(2)
			}

			// The random is at the same offset in a fragmented hello: the first
			// record carries the start of the message.
			wire[RandomOffset+tamperAt] ^= 1 << bit
			want = -1
		}

		ref, stable := agreeWithReference(t, wire, secrets, hostnames, skew, fmt.Sprintf(
			"scenario %d: %d secrets, want %d, padTo %d, skewed %v/%v, tamper %d",
			scenario, n, want, padTo, skewed, skew, tamperAt))
		if !stable {
			counts.unstable++

			continue
		}

		// The generator's own prediction, so the reference is checked too.
		if gateRefused {
			require.Nil(t, ref.result, "scenario %d", scenario)
			require.ErrorContains(t, ref.err, "cannot find any of", "scenario %d", scenario)

			counts.gateRefused++

			continue
		}

		require.Equal(t, want, ref.result.MatchedIndex, "scenario %d", scenario)
		require.Equal(t, sni, ref.result.MatchedHost, "scenario %d", scenario)

		switch {
		case tamperAt >= 0:
			counts.tampered++
			counts.tamperedAt[tamperAt]++
		case wrongKey:
			counts.wrongKey++
		case skewed && want < 0:
			counts.skewRejected++
		case skewed:
			counts.skewAccepted++
		}

		if want >= 0 {
			counts.matched++

			if duplicate {
				counts.matchedDuplicate++
			}
		}

		if padTo > 16389 {
			counts.fragmented++
		}
	}

	t.Logf("%+v", counts)

	assert.Zero(t, counts.unstable, "no stamp in the generator is near its tolerance")
	assert.Greater(t, counts.matched, 3000)
	assert.Greater(t, counts.matchedDuplicate, 50)
	assert.Greater(t, counts.wrongKey, 500)
	assert.Greater(t, counts.skewRejected, 200)
	assert.Greater(t, counts.skewAccepted, 50)
	assert.Greater(t, counts.gateRefused, 50)
	assert.Greater(t, counts.fragmented, 50)

	for at, tampered := range counts.tamperedAt {
		assert.Positive(t, tampered, "a flip at byte %d of the random", at)
	}
}

// FuzzParseVerifyAgainstReference throws arbitrary flights and one or two
// arbitrary keys (any length, a long one included) at the split and at the
// reference. The seeds are valid hellos, a hello ten seconds late, one with
// byte 27 of its random flipped and a 16 MiB length, all under a 3 s skew, so
// the plain `go test` seed run already tells a match from each kind of miss.
func FuzzParseVerifyAgainstReference(f *testing.F) {
	key := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	decoy := [16]byte{16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1}
	sessionID := bytes.Repeat([]byte{7}, 32)

	hello := func(opts testclient.HelloOptions) []byte {
		wire, err := testclient.ClientHelloWith(key, coverSNI, sessionID, opts)
		require.NoError(f, err)

		return wire
	}

	fresh := hello(testclient.HelloOptions{})
	tampered := slices.Clone(fresh)
	tampered[RandomOffset+RandomLen-5] ^= 1

	f.Add(fresh, key[:], decoy[:], false)
	f.Add(fresh, decoy[:], key[:], true)
	f.Add(hello(testclient.HelloOptions{PadTo: 517}), key[:], key[:], true)
	f.Add(hello(testclient.HelloOptions{PadTo: 2048}), decoy[:], key[:], true)
	f.Add(hello(testclient.HelloOptions{At: time.Now().Add(-10 * time.Second)}), key[:], decoy[:], false)
	f.Add(tampered, key[:], decoy[:], false)
	f.Add(fresh, bytes.Repeat([]byte{0xaa}, 100), key[:], true)
	f.Add([]byte{0x16, 3, 1, 0, 4, 0x01, 0xFF, 0xFF, 0xFF}, key[:], decoy[:], false)

	f.Fuzz(func(t *testing.T, wire, key1, key2 []byte, two bool) {
		secrets := [][]byte{key1}
		if two {
			secrets = append(secrets, key2)
		}

		if _, stable := agreeWithReference(t, wire, secrets, []string{coverSNI}, 3*time.Second, "fuzz"); !stable {
			t.Skip("a timestamp crossed the tolerance between two runs of the reference")
		}
	})
}

// RFC 4231 section 4.2 to 4.5 (test cases 1 to 4, the keys shorter than the
// 64-byte block), copied verbatim from https://www.rfc-editor.org/rfc/rfc4231.txt.
// They are the check on the pad arithmetic from outside this code base: they
// must never be computed locally, here or anywhere in this tree, or a mistake
// in the code would be copied into its own test.
var rfc4231 = []struct {
	name, key, data, hmacSHA256 string
}{
	{
		"4.2 test case 1",
		"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b" + "0b0b0b0b",
		"4869205468657265",
		"b0344c61d8db38535ca8afceaf0bf12b" + "881dc200c9833da726e9376c2e32cff7",
	},
	{
		"4.3 test case 2",
		"4a656665",
		"7768617420646f2079612077616e7420" + "666f72206e6f7468696e673f",
		"5bdcc146bf60754e6a042426089575c7" + "5a003f089d2739839dec58b964ec3843",
	},
	{
		"4.4 test case 3",
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" + "aaaaaaaa",
		"dddddddddddddddddddddddddddddddd" +
			"dddddddddddddddddddddddddddddddd" +
			"dddddddddddddddddddddddddddddddd" +
			"dddd",
		"773ea91e36800e46854db8ebd09181a7" + "2959098b3ef8c122d9635514ced565fe",
	},
	{
		"4.5 test case 4",
		"0102030405060708090a0b0c0d0e0f10" + "111213141516171819",
		"cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd" +
			"cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd" +
			"cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd" +
			"cdcd",
		"82558a389a443c0ea4cc819899f2083a" + "85f0faa3e578f8077a2e3ff46729665b",
	},
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()

	b, err := hex.DecodeString(s)
	require.NoError(t, err)

	return b
}

// TestHMACMatchesRFC4231 drives mac, the code Verify runs, over the published
// vectors on both paths. One scratch serves every case, so a state left over
// from the case before would show.
func TestHMACMatchesRFC4231(t *testing.T) {
	t.Parallel()

	var work scratch

	for _, tc := range rfc4231 {
		key := mustHex(t, tc.key)
		data := mustHex(t, tc.data)
		want := mustHex(t, tc.hmacSHA256)

		for _, b := range builders {
			candidate := b.build(key)
			require.Equal(t, b.name == "pads", candidate.precomputed(), "%s, %s", tc.name, b.name)

			var got [sha256.Size]byte

			candidate.mac(&work, &got, data)
			assert.Equal(t, want, got[:], "%s, %s", tc.name, b.name)

			// The same message in pieces, as Verify writes it.
			got = [sha256.Size]byte{}
			candidate.mac(&work, &got, data[:1], nil, data[1:3], data[3:])
			assert.Equal(t, want, got[:], "%s, %s, in pieces", tc.name, b.name)
		}
	}
}

// failExportOnCall makes the n-th export of a digest state fail, until the
// test ends. Not for parallel tests: it swaps a package-level hook.
func failExportOnCall(t *testing.T, n int) {
	t.Helper()

	saved := exportDigestState

	t.Cleanup(func() { exportDigestState = saved })

	calls := 0

	exportDigestState = func(h hash.Hash) ([]byte, error) {
		calls++
		if calls == n {
			return nil, errors.New("refused by the test")
		}

		return saved(h)
	}
}

func hmacSHA256(key []byte, parts ...[]byte) []byte {
	digest := hmac.New(sha256.New, key)
	for _, part := range parts {
		digest.Write(part)
	}

	return digest.Sum(nil)
}

// verifyWire parses a flight naming coverSNI and verifies one candidate.
func verifyWire(t *testing.T, wire []byte, candidate *Candidate, skew time.Duration) bool {
	t.Helper()

	parsed, err := ParseClientHelloFor(connOf(wire), []string{coverSNI})
	require.NoError(t, err)

	return parsed.Verify(candidate, skew)
}

// TestPlainFallbackWhenStateCannotBeExported: a key whose pad states will not
// export, inner or outer, is a plain candidate, and a correct one. Not parallel:
// it swaps the export hook.
func TestPlainFallbackWhenStateCannotBeExported(t *testing.T) {
	key := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	decoy := [16]byte{16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1}
	data := []byte("the export fails, the answer does not")

	// Without the hook the same key is precomputed, so what follows is the
	// hook's doing.
	require.True(t, NewCandidate(key[:]).precomputed())

	wire, err := testclient.ClientHelloWith(key, coverSNI, make([]byte, 32), testclient.HelloOptions{PadTo: 517})
	require.NoError(t, err)

	for _, failOn := range []int{1, 2} {
		t.Run(fmt.Sprintf("export %d fails", failOn), func(t *testing.T) {
			failExportOnCall(t, failOn)

			candidate := NewCandidate(key[:])
			assert.False(t, candidate.precomputed())
			assert.Nil(t, candidate.innerState)
			assert.Nil(t, candidate.outerState)

			var (
				work scratch
				got  [sha256.Size]byte
			)

			candidate.mac(&work, &got, data)
			assert.Equal(t, hmacSHA256(key[:], data), got[:])

			assert.True(t, verifyWire(t, wire, candidate, 3*time.Second))
			assert.False(t, verifyWire(t, wire, NewCandidate(decoy[:]), 3*time.Second))
		})
	}
}

// TestNewCandidateFallsBackForAKeyLongerThanTheBlock: HMAC hashes a key longer
// than the 64-byte block before padding it, which the pad path does not do, so
// such a key is a plain candidate. 64 bytes is still a pad. The MAC is held to
// crypto/hmac, so a long key padded as if it were short is caught by value.
func TestNewCandidateFallsBackForAKeyLongerThanTheBlock(t *testing.T) {
	t.Parallel()

	data := []byte("a key of any length gets the HMAC of that key")

	var work scratch

	for _, size := range []int{16, 63, 64, 65, 100, 200} {
		key := make([]byte, size)
		for i := range key {
			key[i] = byte(i*7 + size)
		}

		candidate := NewCandidate(key)
		assert.Equal(t, size <= sha256.BlockSize, candidate.precomputed(), "a %d-byte key", size)

		var got [sha256.Size]byte

		candidate.mac(&work, &got, data)
		assert.Equal(t, hmacSHA256(key, data), got[:], "a %d-byte key", size)
	}
}

// TestVerifyFallsBackWhenTheStateWillNotLoad: a state that will not unmarshal
// sends that Verify down the plain path; a valid hello is never refused by the
// defensive branch.
func TestVerifyFallsBackWhenTheStateWillNotLoad(t *testing.T) {
	t.Parallel()

	key := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}

	wire, err := testclient.ClientHelloWith(key, coverSNI, make([]byte, 32), testclient.HelloOptions{PadTo: 517})
	require.NoError(t, err)

	for _, broken := range []string{"inner", "outer"} {
		candidate := NewCandidate(key[:])
		require.True(t, candidate.precomputed())

		if broken == "inner" {
			candidate.innerState = []byte("not a digest state")
		} else {
			candidate.outerState = []byte("not a digest state")
		}

		assert.True(t, verifyWire(t, wire, candidate, 3*time.Second), "the %s state is broken", broken)
	}
}

// TestVerifyRejectsAFlipInTheDigestPart: the first 28 bytes of the random are
// digest and every bit of them is checked, the 28th byte included; the last 4
// are the timestamp, so a one-second flip there is still taken under an hour's
// tolerance.
func TestVerifyRejectsAFlipInTheDigestPart(t *testing.T) {
	t.Parallel()

	key := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}

	wire, err := testclient.ClientHelloWith(key, coverSNI, make([]byte, 32), testclient.HelloOptions{PadTo: 517})
	require.NoError(t, err)

	for _, b := range builders {
		candidate := b.build(key[:])
		require.True(t, verifyWire(t, wire, candidate, time.Hour), b.name)

		for at := range RandomLen - 4 {
			for bit := range 8 {
				tampered := slices.Clone(wire)
				tampered[RandomOffset+at] ^= 1 << bit

				assert.False(t, verifyWire(t, tampered, candidate, time.Hour),
					"%s: bit %d of byte %d of the random flipped", b.name, bit, at)
			}
		}

		late := slices.Clone(wire)
		late[RandomOffset+RandomLen-4] ^= 1

		assert.True(t, verifyWire(t, late, candidate, time.Hour), "%s: the timestamp is a second out", b.name)
	}
}

// TestVerifyDoesNotAllocateOnThePrecomputedPath: one hit and one miss per run,
// nothing on the heap. Not parallel: AllocsPerRun counts the whole process.
func TestVerifyDoesNotAllocateOnThePrecomputedPath(t *testing.T) {
	key := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	decoy := [16]byte{16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1}

	wire, err := testclient.ClientHelloWith(key, coverSNI, make([]byte, 32), testclient.HelloOptions{PadTo: 517})
	require.NoError(t, err)

	parsed, err := ParseClientHelloFor(connOf(wire), []string{coverSNI})
	require.NoError(t, err)

	hit, miss := NewCandidate(key[:]), NewCandidate(decoy[:])
	require.True(t, hit.precomputed())
	require.True(t, miss.precomputed())

	var hits, misses int

	allocs := testing.AllocsPerRun(1000, func() {
		if parsed.Verify(hit, time.Hour) {
			hits++
		}

		if parsed.Verify(miss, time.Hour) {
			misses++
		}
	})

	assert.Zero(t, allocs)
	assert.Equal(t, 1001, hits, "AllocsPerRun runs once more to warm up")
	assert.Zero(t, misses)
}

// TestBlocksCountsTheHMACBlocks: one plain HMAC-SHA256 candidate costs
// 3 + ceil((L+9)/64) SHA-256 blocks, L the length of the hello as one record
// (5-byte record header + 4-byte handshake header + body): the inner hash is
// the key pad block plus the message with SHA-256's padding (the 0x80 byte and
// an 8-byte length, so L+9 bytes), the outer hash is the pad block plus the
// 32-byte inner digest, padded into one more. 183 and 184 straddle a block edge
// (183+9 = 192 = 3 blocks); 65,540 is the largest hello taken, sent across
// five records.
func TestBlocksCountsTheHMACBlocks(t *testing.T) {
	t.Parallel()

	key := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}

	for size, want := range map[int]int{517: 12, 65540: 1028, 183: 6, 184: 7, 4096: 68} {
		wire, err := testclient.ClientHelloWith(key, coverSNI, make([]byte, 32), testclient.HelloOptions{PadTo: size})
		require.NoError(t, err)

		parsed, err := ParseClientHelloFor(connOf(wire), []string{coverSNI})
		require.NoError(t, err)

		require.Len(t, parsed.handshake, size, "L is the hello as one record")
		assert.Equal(t, want, parsed.Blocks(), "a %d-byte hello", size)
		assert.Equal(t, 3+int(math.Ceil(float64(size+9)/64)), parsed.Blocks(), "a %d-byte hello", size)
	}
}

// TestParseClientHelloForKeepsTheErrors: the parse failures and the SNI gate
// fail as ReadClientHelloMulti always did, word for word, with no result.
func TestParseClientHelloForKeepsTheErrors(t *testing.T) {
	t.Parallel()

	key := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}

	wire, err := testclient.ClientHelloWith(key, coverSNI, make([]byte, 32), testclient.HelloOptions{})
	require.NoError(t, err)

	// An unpadded hello with a 32-byte session ID ends in the SNI extension, so
	// its name type is 20 bytes from the end (type, 2-byte length, 17-byte
	// name); its one cipher suite is at 78, after the 5+4+2+32+1+32+2 bytes
	// before it.
	badNameType := slices.Clone(wire)
	badNameType[len(badNameType)-len(coverSNI)-3] = 0x01

	onlyGrease := slices.Clone(wire)
	onlyGrease[78], onlyGrease[79] = 0x0a, 0x0a

	flights := map[string][]byte{
		"empty":           nil,
		"a record header": wire[:5],
		"cut short":       wire[:len(wire)-10],
		"16 MiB":          {0x16, 3, 1, 0, 4, 0x01, 0xFF, 0xFF, 0xFF},
		"not a handshake": append([]byte{0x17}, wire[1:]...),
		"bad SNI":         badNameType,
		"only GREASE":     onlyGrease,
	}

	for name, want := range map[string]string{
		"bad SNI":     "cannot parse SNI: incorrect SNI list type 0x1",
		"only GREASE": "cannot parse handshake: " + ErrCannotFindCipher.Error(),
	} {
		_, err := referenceMatch(connOf(flights[name]), nil, []string{coverSNI}, time.Hour)
		require.EqualError(t, err, want, "the %q flight is what it says", name)
	}

	for name, flight := range flights {
		for _, hostnames := range [][]string{{coverSNI}, {otherSNI}} {
			_, wantErr := referenceMatch(connOf(flight), nil, hostnames, time.Hour)
			require.Error(t, wantErr, name)

			parsed, err := ParseClientHelloFor(connOf(flight), hostnames)
			require.Nil(t, parsed, name)
			require.EqualError(t, err, wantErr.Error(), name)
		}
	}

	_, wantErr := referenceMatch(connOf(wire), nil, []string{otherSNI}, time.Hour)
	require.ErrorContains(t, wantErr, "cannot find any of")

	parsed, err := ParseClientHelloFor(connOf(wire), []string{otherSNI})
	require.Nil(t, parsed)
	require.EqualError(t, err, wantErr.Error())
}
