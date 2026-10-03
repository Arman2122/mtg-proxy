package mtglib

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Arman2122/mtg-proxy/essentials"
	"github.com/Arman2122/mtg-proxy/mtglib/internal/tls"
	"github.com/Arman2122/mtg-proxy/mtglib/internal/tls/fake"
	"github.com/Arman2122/mtg-proxy/mtglib/obfuscation"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// This file is the no-regression gate for the public :443 port. Every existing
// deployment runs the ee / FakeTLS entry and nothing else, and Phase 1
// restructured ServeConn underneath it, so what follows records what that entry
// puts on the wire and fails when it changes.
//
// WHY A STRUCTURAL GOLDEN AND NOT A BYTE-EXACT ONE (design section 10, option b)
//
// A byte-for-byte golden is not achievable here without cutting production
// seams that would exist only for this test. Four independent entropy sources
// feed the ee flight, and none of them is reachable from a test:
//
//  1. fake.generateServerHelloHandshakePayload draws the 32-byte X25519 scalar
//     straight from crypto/rand, and writes the derived curve point.
//  2. fake.generateNoise sizes its record from the package-global math/rand/v2
//     and fills it from crypto/rand.
//  3. fakeTLSClientHello (proxy_fronting_test.go, not owned here) stamps
//     time.Now() into the client random, and the client random is an input to
//     the ServerHello digest -- so even the deterministic-looking parts of the
//     server flight move once a second.
//  4. doppel.Stats.Delay and Stats.Size drive when the write loop wakes, and
//     therefore how relayed traffic is segmented into records.
//
// Injecting a clock, a rand source and a fixed scalar into three production
// packages to freeze those would be four new seams that no production caller
// uses -- exactly what the brief says not to add silently. So the golden is
// structural, and the rule is: EVERY byte that is not one of those four sources
// is pinned literally, and the two masked fields are verified by code
// assertions in this same test rather than left unchecked.
//
// Masked, and what checks them instead:
//   - the ServerHello random is HMAC-SHA256(secret, clientRandom || flight with
//     that field zeroed). assertFakeTLSDigest recomputes it exactly the way a
//     real Telegram client does. (fake's TestSendServerHello/TestHMAC does the
//     same recomputation at the package level; what is unique here is that it
//     runs on the flight this ENTRY actually put on the wire, under the key the
//     secret-set lookup picked.)
//   - the 32-byte key share is a curve point from crypto/rand. Its LENGTH is
//     pinned by the ServerHello record length; its VALUE is checked by
//     TestGoldenFakeTLSEntropyVariesPerConnection, which requires two
//     connections to differ. A structural golden cannot pin an entropy VALUE,
//     and a constant one is exactly the permanent passive fingerprint the ee
//     port exists to avoid -- so "differs across connections" is the assertion
//     that stands in for a literal.
//
// REGENERATION
//
//	MTG_UPDATE_GOLDEN=1 go test ./mtglib/ -run Golden
//
// rewrites mtglib/testdata/faketls-public-port.golden from the live run. The
// code assertions (the digest recomputation, the Telegram frame decode, the
// probe checks) run REGARDLESS of that variable, so a regeneration cannot
// paper over a broken digest.
//
// NEVER regenerate the golden to make a red test green. A diff here means the
// public port emits something different from what every deployed client and
// every censor has seen so far; regenerate only after deciding, deliberately,
// that the new bytes are the ones you want to ship, and say so in the commit.

const (
	goldenUpdateEnv  = "MTG_UPDATE_GOLDEN"
	goldenFakeTLSPth = "testdata/faketls-public-port.golden"
)

// goldenHeader is rewritten verbatim on regeneration. Comment lines and blank
// lines are ignored when the golden is read back.
const goldenHeader = `# mtg-proxy -- ee / FakeTLS public-port wire trace.
#
# Regenerate:  MTG_UPDATE_GOLDEN=1 go test ./mtglib/ -run Golden
# Never regenerate to make a red test green: a diff here means the public :443
# port emits something different from what deployed clients have always seen.
#
# <masked> fields are the ones no test can freeze without a production seam.
# random:    recomputed per run as HMAC-SHA256(secret, client random || flight)
#            by assertFakeTLSDigest.
# key-share: length pinned by the flight.1.length line; the value is entropy, so
#            it is asserted to differ across two connections (and to be non-zero)
#            by TestGoldenFakeTLSEntropyVariesPerConnection instead.
`

// goldenFrameSource is a read-only essentials.Conn over a byte slice, so the 64
// bytes the proxy sent Telegram can be run back through the real obfuscated2
// reader. The embedded interface is nil on purpose: any other call panics.
type goldenFrameSource struct {
	essentials.Conn

	r *bytes.Reader
}

func (g goldenFrameSource) Read(p []byte) (int, error) {
	return g.r.Read(p) //nolint: wrapcheck
}

// assertFakeTLSDigest is the client-side check of the server flight, done the
// way a real Telegram client does it: HMAC-SHA256 under the matched secret over
// the client's own random followed by the whole three-record flight with the
// server random nullified.
//
// It catches a refactor that drops the client-random binding, hashes only the
// ServerHello record instead of the flight, writes the digest at the wrong
// offset, or signs with the wrong user's key.
func assertFakeTLSDigest(t *testing.T, key [SecretKeyLength]byte, clientRandom, flight []byte) {
	t.Helper()

	require.GreaterOrEqual(t, len(flight), fake.RandomOffset+fake.RandomLen)

	masked := slices.Clone(flight)
	for i := fake.RandomOffset; i < fake.RandomOffset+fake.RandomLen; i++ {
		masked[i] = 0
	}

	digest := hmac.New(sha256.New, key[:])
	digest.Write(clientRandom)
	digest.Write(masked)

	assert.Equal(t, digest.Sum(nil), flight[fake.RandomOffset:fake.RandomOffset+fake.RandomLen],
		"the server random must be the FakeTLS digest over client random || flight")
}

// assertGoldenTrace compares the recorded trace against the checked-in golden,
// or rewrites it when MTG_UPDATE_GOLDEN is set. Comparison is line-by-line so
// testify prints which line of the flight moved.
func assertGoldenTrace(t *testing.T, path string, got []string) {
	t.Helper()

	if os.Getenv(goldenUpdateEnv) != "" {
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o750))
		require.NoError(t, os.WriteFile(path,
			[]byte(goldenHeader+strings.Join(got, "\n")+"\n"), 0o600))
		t.Logf("%s regenerated from this run because %s is set", path, goldenUpdateEnv)

		return
	}

	raw, err := os.ReadFile(path) //nolint: gosec
	require.NoErrorf(t, err, "golden is missing; regenerate with %s=1", goldenUpdateEnv)

	var want []string

	// eol=lf is set in .gitattributes, but a checkout can still hand back CRLF.
	for _, line := range strings.Split(strings.ReplaceAll(string(raw), "\r\n", "\n"), "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		want = append(want, line)
	}

	assert.Equal(t, want, got,
		"the public FakeTLS port emits a different trace; regenerate with %s=1 ONLY if this change is intended",
		goldenUpdateEnv)
}

// TestGoldenFakeTLSPublicPortTrace records the whole observable ee flight on a
// default-config listener (no [[listener]] stanza, so DefaultListenerPolicy)
// and asserts it against a checked-in golden.
//
// Two connections, because the public port has two observable behaviours and a
// censor can run both:
//
//   - a garbage probe, which must be relayed verbatim to the cover site with
//     the proxy contributing not one byte of its own;
//   - a valid client, whose whole flight -- ServerHello, ChangeCipherSpec, the
//     one noise record, the obfuscated2 frame handed to Telegram and the record
//     framing of relayed traffic -- is recorded record by record.
func TestGoldenFakeTLSPublicPortTrace(t *testing.T) {
	t.Parallel()

	// A fixed key and session id so the echoed fields in the golden are literal
	// bytes rather than another mask.
	var key [SecretKeyLength]byte
	for i := range key {
		key[i] = byte(0xa0 + i)
	}

	const coverHost = "cover.example.com"

	secret := Secret{Key: key, Host: coverHost}

	// "aaa-decoy" sorts BEFORE "public" and is dd, so it is not hosted:
	// hosted == [1] while ReadClientHelloMulti reports MatchedIndex 0. Every
	// lookup keyed by the candidate index instead of the remapped one now reads
	// the decoy -- and with a dd decoy the wrongly-read KEY signs the flight, so
	// assertFakeTLSDigest sees it. A hostless-looking Secret{Key: ...} literal
	// would NOT do: Secret.Hosted keys off Mode, whose zero value is
	// SecretModeFakeTLS, so such a decoy is hosted and the two indices agree.
	decoy := hostlessSecret(t, SecretModeDD)

	// "bbb-other" is a SECOND ee secret, so hosted == [1, 2] and the matched
	// secret is not hosted[0] either. The dd decoy alone only pins the
	// hosted-vs-full remap; without another ee entry a lookup that picked the
	// first hosted secret rather than the matched one -- the shape a plain
	// multi-ee deployment hits -- would still sign the flight correctly by
	// accident. It fronts a different host so it can never match this SNI.
	other := Secret{Host: "other.example.com"}
	for i := range other.Key {
		other.Key[i] = byte(0x50 + i)
	}

	h := newEntryHarness(t, map[string]Secret{
		"aaa-decoy": decoy,
		"bbb-other": other,
		"public":    secret,
	}, nil)

	// Ganger.NewConn is a channel round-trip with the run loop, so the ee path
	// cannot get past the doppelganger wrap unless the ganger is running.
	h.proxy.doppelGanger.Run()
	t.Cleanup(h.proxy.doppelGanger.Shutdown)

	trace := make([]string, 0, 32)
	trace = append(trace, goldenProbePhase(t, h)...)
	trace = append(trace, goldenFlightPhase(t, h, key)...)

	assertGoldenTrace(t, goldenFakeTLSPth, trace)
}

// goldenProbePhase runs the garbage probe and returns its trace lines.
func goldenProbePhase(t *testing.T, h *entryHarness) []string {
	t.Helper()

	garbage := []byte("not a client hello at all")
	banner := []byte("HTTP/1.1 200 OK\r\n\r\ncover site\n")

	cover, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	t.Cleanup(func() { cover.Close() }) //nolint: errcheck

	h.proxy.domainFrontingHost = "127.0.0.1"
	h.proxy.domainFrontingPort = cover.Addr().(*net.TCPAddr).Port

	covered := make(chan []byte, 1)

	go func() {
		conn, err := cover.Accept()
		if err != nil {
			covered <- nil

			return
		}

		defer conn.Close() //nolint: errcheck

		got := make([]byte, len(garbage))

		// ReadFull, not ReadAll: the client has not closed, so the cover site
		// must answer on exactly the bytes it was handed.
		if _, err := io.ReadFull(conn, got); err != nil {
			covered <- nil

			return
		}

		conn.Write(banner) //nolint: errcheck
		covered <- got
	}()

	client, done := h.dialProxy(t, nil)

	_, err = client.Write(garbage)
	require.NoError(t, err)

	require.NoError(t, client.SetReadDeadline(time.Now().Add(10*time.Second)))

	// Exactly as many bytes as the cover site wrote, and no half-close first:
	// relay's client -> cover pump closes the READ half of the fronting socket
	// when it finishes, so a client that shuts down its write side never sees
	// the answer at all. Reading a fixed length is also what makes a byte the
	// proxy prepends -- a TLS alert, a ServerHello -- show up as a changed
	// golden line rather than as trailing noise nobody looks at.
	fromProxy := make([]byte, len(banner))

	_, err = io.ReadFull(client, fromProxy)
	require.NoError(t, err, "the cover site's answer must reach the client")

	client.Close() //nolint: errcheck
	<-done

	toCover := <-covered
	require.NotNil(t, toCover, "the cover site must receive the probe")

	return []string{
		// The rewind: a probe the proxy already consumed while parsing must
		// reach the cover site byte for byte, or the cover site answers a
		// truncated request and the fronting is a distinguisher.
		"probe.cover-received " + hex.EncodeToString(toCover),
		// Nothing of ours may precede or follow the cover site's own answer: a
		// TLS alert, a ServerHello or a close-notify here is exactly the
		// fingerprint fronting exists to avoid.
		"probe.client-received " + hex.EncodeToString(fromProxy),
		fmt.Sprintf("probe.fronting-events %d", h.events.frontings()),
	}
}

// goldenFlightPhase drives one valid ee client end to end and returns its trace
// lines.
func goldenFlightPhase(t *testing.T, h *entryHarness, key [SecretKeyLength]byte) []string {
	t.Helper()

	// dc 4, not the default 2: a DC that is not defaultDC is the only way to see
	// that the client's own DC survives to the Telegram leg rather than being
	// re-derived from a zeroed field.
	const clientDC = 4

	sessionID := bytes.Repeat([]byte{0x11}, 32)

	client, done := h.dialProxy(t, nil)

	hello := fakeTLSClientHello(t, key, "cover.example.com", sessionID)
	clientRandom := slices.Clone(hello[fake.RandomOffset : fake.RandomOffset+fake.RandomLen])

	_, err := client.Write(hello)
	require.NoError(t, err)

	require.NoError(t, client.SetReadDeadline(time.Now().Add(10*time.Second)))

	records, flight := goldenReadFlight(t, client)

	assertFakeTLSDigest(t, key, clientRandom, flight)

	lines := goldenFlightLines(t, records, sessionID)

	// The client's obfuscated2 frame arrives inside an application-data record,
	// which is where it lands once the read side is wrapped by tls.New.
	frame := obfuscatedFrame(t, key, obfuscation.TagPaddedIntermediate, clientDC)

	_, err = client.Write(tlsApplicationRecord(frame))
	require.NoError(t, err)

	upstream, err := h.upstream.Accept()
	require.NoError(t, err, "the ee path must dial Telegram")

	defer upstream.Close() //nolint: errcheck

	require.NoError(t, upstream.SetReadDeadline(time.Now().Add(10*time.Second)))

	var telegramFrame [64]byte

	_, err = io.ReadFull(upstream, telegramFrame[:])
	require.NoError(t, err)

	lines = append(lines, goldenTelegramLines(t, telegramFrame[:])...)

	// Relayed traffic. It reaches the client through the obfuscation cipher, so
	// with the doppelganger wrap dropped what arrives is pseudorandom bytes that
	// goldenReadRecord rejects by name as an impossible record length rather
	// than by hanging.
	const relayed = 128

	_, err = upstream.Write(bytes.Repeat([]byte{0x5a}, relayed))
	require.NoError(t, err)

	lines = append(lines, goldenRelayLines(t, client, relayed)...)

	// There is deliberately no "a valid ClientHello was not fronted" assertion
	// here: a fronted hello never produces a ServerHello at all, so every line
	// above already fails first. It would be a line no mutation can make red.

	client.Close() //nolint: errcheck
	<-done

	return lines
}

// goldenFlightLines renders the three server records. Everything except the two
// masked fields is a literal byte.
func goldenFlightLines(t *testing.T, records []goldenRecord, sessionID []byte) []string {
	t.Helper()

	var lines []string

	for i, record := range records {
		prefix := fmt.Sprintf("flight.%d", i+1)
		lines = append(lines,
			fmt.Sprintf("%s.type %02x", prefix, record.recordType),
			fmt.Sprintf("%s.version %s", prefix, hex.EncodeToString(record.version[:])),
		)

		switch i {
		case 0:
			lines = append(lines, goldenServerHelloLines(t, prefix, record, sessionID)...)
		case 1:
			// ChangeCipherSpec is six bytes and every one of them is a constant.
			lines = append(lines,
				fmt.Sprintf("%s.length %d", prefix, len(record.payload)),
				fmt.Sprintf("%s.payload %s", prefix, hex.EncodeToString(record.payload)))
		case 2:
			// The one field of the flight whose size is genuinely random. The
			// bound is the legacy fallback range in fake.generateNoise, which is
			// what a proxy with no calibrated cert measurement emits -- i.e.
			// every proxy in its first minutes and every proxy whose scout is
			// unreachable. A record outside it is either a changed distribution
			// or a calibration that leaked into a path that must not have one.
			assert.GreaterOrEqual(t, len(record.payload), 2500, "noise record too short")
			assert.LessOrEqual(t, len(record.payload), 4699, "noise record too long")
			lines = append(lines, fmt.Sprintf("%s.length-range 2500..4699", prefix))
		}
	}

	return lines
}

// goldenServerHelloLines pins every deterministic byte of the ServerHello.
func goldenServerHelloLines(t *testing.T, prefix string, record goldenRecord, sessionID []byte) []string {
	t.Helper()

	payload := record.payload
	// Compared as an int, not with require.Len: a record that is not a
	// ServerHello at all would otherwise dump kilobytes of noise into the log.
	require.Equal(t, 4+2+fake.RandomLen+1+len(sessionID)+2+17+fake.EllipticCurveLen, len(payload),
		"ServerHello payload length")

	sessionOffset := 4 + 2 + fake.RandomLen
	suiteOffset := sessionOffset + 1 + len(sessionID)
	suffixOffset := suiteOffset + 2

	return []string{
		fmt.Sprintf("%s.length %d", prefix, len(payload)),
		fmt.Sprintf("%s.handshake-type %02x", prefix, payload[0]),
		fmt.Sprintf("%s.handshake-length %s", prefix, hex.EncodeToString(payload[1:4])),
		fmt.Sprintf("%s.server-version %s", prefix, hex.EncodeToString(payload[4:6])),
		// Masked: verified by assertFakeTLSDigest.
		fmt.Sprintf("%s.random <masked:%d> faketls-digest", prefix, fake.RandomLen),
		// Echoed from the ClientHello. A ServerHello that does not echo the
		// session id is rejected by every real client.
		fmt.Sprintf("%s.session-id-length %d", prefix, payload[sessionOffset]),
		fmt.Sprintf("%s.session-id %s", prefix,
			hex.EncodeToString(payload[sessionOffset+1:sessionOffset+1+len(sessionID)])),
		fmt.Sprintf("%s.cipher-suite %s", prefix,
			hex.EncodeToString(payload[suiteOffset:suiteOffset+2])),
		// 17 production constant bytes: compression, extensions length,
		// supported_versions = TLS 1.3, key_share = x25519, 32 bytes.
		fmt.Sprintf("%s.suffix %s", prefix,
			hex.EncodeToString(payload[suffixOffset:suffixOffset+17])),
		// Masked: an X25519 point from crypto/rand. Only its length is pinned,
		// and the record length above pins that.
		fmt.Sprintf("%s.key-share <masked:%d> x25519", prefix, fake.EllipticCurveLen),
	}
}

// goldenTelegramLines decodes the 64-byte obfuscated2 frame the proxy hands
// Telegram, using the same reader a Telegram front end would.
func goldenTelegramLines(t *testing.T, frame []byte) []string {
	t.Helper()

	// Default DC addresses carry a nil obfuscator secret, so this is exactly the
	// derivation the far end performs.
	src := goldenFrameSource{r: bytes.NewReader(slices.Clone(frame))}

	dcID, tag, _, err := obfuscation.Obfuscator{}.ReadHandshake(
		src, obfuscation.TagSetOf(obfuscation.TagPaddedIntermediate),
	)
	require.NoError(t, err, "the frame handed to Telegram must be a readable obfuscated2 handshake")

	return []string{
		// The client's own DC and transport tag, not ours: the relay above is a
		// byte pump, so announcing a different transport corrupts every packet.
		fmt.Sprintf("telegram.frame.dc %d", dcID),
		fmt.Sprintf("telegram.frame.tag %s", hex.EncodeToString(tag[:])),
	}
}

// goldenRelayLines reads relayed server-to-client traffic and renders the
// record shape the doppelganger gives it.
func goldenRelayLines(t *testing.T, r io.Reader, want int) []string {
	t.Helper()

	var (
		types    []string
		versions []string
		total    int
	)

	for total < want {
		record := goldenReadRecord(t, r)
		total += len(record.payload)

		if typ := fmt.Sprintf("%02x", record.recordType); !slices.Contains(types, typ) {
			types = append(types, typ)
		}

		if ver := hex.EncodeToString(record.version[:]); !slices.Contains(versions, ver) {
			versions = append(versions, ver)
		}
	}

	// The distinct sets, not the per-record sequence: how many records the
	// relayed bytes are cut into depends on doppel.Stats.Delay racing the relay,
	// and is deliberately not pinned. What every record must be is the same.
	return []string{
		"relay.record-types " + strings.Join(types, ","),
		"relay.record-versions " + strings.Join(versions, ","),
		fmt.Sprintf("relay.total-payload-bytes %d", total),
	}
}

// goldenHandshakeFlight runs one ee handshake straight through
// doFakeTLSHandshake -- no doppelganger and no Telegram leg, because the server
// flight is written before either exists -- and returns the three records the
// server put on the wire.
func goldenHandshakeFlight(
	t *testing.T, h *entryHarness, key [SecretKeyLength]byte, sessionID []byte,
) []goldenRecord {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	defer listener.Close() //nolint: errcheck

	client, err := net.Dial("tcp", listener.Addr().String())
	require.NoError(t, err)

	t.Cleanup(func() { client.Close() }) //nolint: errcheck

	server, err := listener.Accept()
	require.NoError(t, err)

	t.Cleanup(func() { server.Close() }) //nolint: errcheck

	// Deadlines on both ends so a handshake that stops answering fails this test
	// by name instead of hanging the package.
	require.NoError(t, server.SetDeadline(time.Now().Add(10*time.Second)))
	require.NoError(t, client.SetDeadline(time.Now().Add(10*time.Second)))

	_, err = client.Write(fakeTLSClientHello(t, key, "cover.example.com", sessionID))
	require.NoError(t, err)

	ctx := newStreamContext(h.proxy.ctx, h.proxy.logger, essentials.WrapNetConn(server))
	t.Cleanup(ctx.Close)

	require.True(t, h.proxy.doFakeTLSHandshake(ctx), "the ee handshake must be admitted")

	records, _ := goldenReadFlight(t, client)

	return records
}

// goldenKeyShare returns the x25519 point, which is the last field of the
// ServerHello handshake payload and therefore its trailing 32 bytes.
func goldenKeyShare(t *testing.T, record goldenRecord) []byte {
	t.Helper()

	require.Equal(t, byte(tls.TypeHandshake), record.recordType, "the first record must be the ServerHello")
	require.Greater(t, len(record.payload), fake.EllipticCurveLen)

	return record.payload[len(record.payload)-fake.EllipticCurveLen:]
}

// TestGoldenFakeTLSEntropyVariesPerConnection covers what a structural golden
// structurally cannot: the VALUE of the two entropy-sourced fields of the
// flight. A constant key share is a permanent passive fingerprint -- one
// observer sees the identical X25519 point on every connection, forever, and
// the proxy is identified -- and an all-zero noise body is instantly
// distinguishable from the encrypted certificate chain it imitates. Neither
// shows up in a trace that pins types, versions and lengths, so what is asserted
// instead is that two connections differ.
func TestGoldenFakeTLSEntropyVariesPerConnection(t *testing.T) {
	t.Parallel()

	var key [SecretKeyLength]byte
	for i := range key {
		key[i] = byte(0xa0 + i)
	}

	h := newEntryHarness(t, map[string]Secret{"public": {Key: key, Host: "cover.example.com"}}, nil)

	// Distinct session ids: the anti-replay cache keys off it, so a reused one
	// would front the second connection instead of answering it.
	first := goldenHandshakeFlight(t, h, key, bytes.Repeat([]byte{0x11}, 32))
	second := goldenHandshakeFlight(t, h, key, bytes.Repeat([]byte{0x22}, 32))

	firstShare := goldenKeyShare(t, first[0])

	assert.NotEqual(t, firstShare, goldenKeyShare(t, second[0]),
		"the x25519 key share must be freshly drawn per connection")
	assert.NotEqual(t, make([]byte, fake.EllipticCurveLen), firstShare,
		"the x25519 key share must not be a degenerate all-zero point")

	// A fixed PREFIX, not the whole payload: the noise record's length is random
	// too, so two all-zero bodies of different sizes compare unequal and the
	// assertion would pass on exactly the regression it exists to catch. 2500 is
	// the shortest record generateNoise can emit, and flight.3.length-range
	// above is what holds that floor.
	const noisePrefix = 2500

	require.GreaterOrEqual(t, len(first[2].payload), noisePrefix)
	require.GreaterOrEqual(t, len(second[2].payload), noisePrefix)

	assert.NotEqual(t, first[2].payload[:noisePrefix], second[2].payload[:noisePrefix],
		"the noise record must carry fresh bytes per connection")
	assert.NotEqual(t, make([]byte, noisePrefix), first[2].payload[:noisePrefix],
		"the noise record must not be an all-zero body")
}

// TestGoldenFakeTLSDoorRefusesOtherTags pins the accepted transport tag set of
// the FakeTLS door. doObfuscatedHandshake's comment states that the ee entry
// "honours padded-intermediate and nothing else, exactly as it always has", and
// until this test nothing enforced it: widening the set on the public port is a
// silent protocol loosening that changes what every deployed client may send.
func TestGoldenFakeTLSDoorRefusesOtherTags(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		tag  obfuscation.ConnectionTag
	}{
		{"abridged", obfuscation.TagAbridged},
		{"intermediate", obfuscation.TagIntermediate},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var key [SecretKeyLength]byte
			for i := range key {
				key[i] = byte(0xa0 + i)
			}

			h := newEntryHarness(t, map[string]Secret{"public": {Key: key, Host: "cover.example.com"}}, nil)

			h.proxy.doppelGanger.Run()
			t.Cleanup(h.proxy.doppelGanger.Shutdown)

			client, done := h.dialProxy(t, nil)

			_, err := client.Write(fakeTLSClientHello(t, key, "cover.example.com", bytes.Repeat([]byte{0x11}, 32)))
			require.NoError(t, err)

			require.NoError(t, client.SetReadDeadline(time.Now().Add(10*time.Second)))
			goldenReadFlight(t, client)

			// Everything else about this client is correct -- same secret, same
			// DC, a well-formed obfuscated2 frame inside a proper application
			// data record. Only the transport tag differs.
			_, err = client.Write(tlsApplicationRecord(obfuscatedFrame(t, key, tc.tag, 4)))
			require.NoError(t, err)

			select {
			case <-done:
			case <-time.After(20 * time.Second):
				t.Fatal("ServeConn did not return after a refused transport tag")
			}

			// Read only after ServeConn returned, or the check races the dial.
			assert.Zero(t, h.network.telegramDials(),
				"a frame tagged %s must not reach Telegram through the ee door", tc.name)
		})
	}
}
