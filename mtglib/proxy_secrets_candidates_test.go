package mtglib

import (
	"bytes"
	"errors"
	"net"
	"slices"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/Arman2122/mtg-proxy/internal/testclient"
	"github.com/Arman2122/mtg-proxy/mtglib/internal/tls/fake"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The candidates a secret set carries for the FakeTLS door, and the scan that
// walks them.

const candidatesCover = "cover.example.com"

// helloReaderConn serves a client's flight from memory. ParseClientHelloFor
// only reads, so everything else is the nil embedded interface.
type helloReaderConn struct {
	net.Conn

	r *bytes.Reader
}

func (c *helloReaderConn) Read(b []byte) (int, error) {
	return c.r.Read(b)
}

// parsedHello puts a flight through the SNI gate for the given hostnames.
func parsedHello(t testing.TB, wire []byte, hostnames ...string) *fake.Parsed {
	t.Helper()

	parsed, err := fake.ParseClientHelloFor(&helloReaderConn{r: bytes.NewReader(wire)}, hostnames)
	require.NoError(t, err)

	return parsed
}

// keyFilledFrom is a valid key (never the empty one) that differs for each
// first byte, so a test names its secrets' keys by a small number.
func keyFilledFrom(first byte) [SecretKeyLength]byte {
	var key [SecretKeyLength]byte

	for i := range key {
		key[i] = first + byte(i)
	}

	return key
}

func eeSecretOf(key [SecretKeyLength]byte, host string) Secret {
	return Secret{Key: key, Host: host, Mode: SecretModeFakeTLS}
}

func ddSecretOf(key [SecretKeyLength]byte) Secret {
	return Secret{Key: key, Mode: SecretModeDD}
}

func plainSecretOf(key [SecretKeyLength]byte) Secret {
	return Secret{Key: key, Mode: SecretModePlain}
}

// scanFor makes a hello with key, naming the cover host, and scans set with it.
func scanFor(t testing.TB, p *Proxy, set *secretSet, key [SecretKeyLength]byte) (pos, tried int) {
	t.Helper()

	wire := fakeTLSClientHello(t, key, candidatesCover, bytes.Repeat([]byte{0x33}, 32))

	return p.scanCandidates(parsedHello(t, wire, candidatesCover), set, nil)
}

func TestCandidatesAreTheHostedSecretsInNameOrder(t *testing.T) {
	t.Parallel()

	secrets := map[string]Secret{
		"zzz": eeSecretOf(keyFilledFrom(1), candidatesCover),
		"aaa": ddSecretOf(keyFilledFrom(20)),
		"mmm": eeSecretOf(keyFilledFrom(40), candidatesCover),
		"bbb": plainSecretOf(keyFilledFrom(60)),
		"ccc": eeSecretOf(keyFilledFrom(80), candidatesCover),
	}

	set := buildSecretSet(secrets, nil, nil, nil)

	require.Equal(t, []string{"aaa", "bbb", "ccc", "mmm", "zzz"}, set.names)
	require.Equal(t, []int{2, 3, 4}, set.hosted, "set.hosted is exactly as it was")
	require.Len(t, set.cands, 3, "a candidate for each ee secret and for nothing else")
	assert.Equal(t, []int{2, 3, 4}, set.candIdx, "ccc, mmm, zzz: name order, indices into secrets")

	p := &Proxy{tolerateTimeSkewness: time.Hour}

	// Each candidate is the key of the secret candIdx says it is, at the position
	// it is in: the scan finds it there after trying every one before it.
	for pos, idx := range set.candIdx {
		got, tried := scanFor(t, p, set, set.secrets[idx].Key)

		assert.Equal(t, pos, got, "the hello of %s", set.names[idx])
		assert.Equal(t, pos+1, tried, "the hello of %s is found in order", set.names[idx])
	}

	// A hostless secret's key is no candidate, whatever host the hello names.
	for _, name := range []string{"aaa", "bbb"} {
		got, tried := scanFor(t, p, set, secrets[name].Key)

		assert.Equal(t, -1, got, "the key of %s", name)
		assert.Equal(t, 3, tried, "every candidate was tried and none matched")
	}
}

func TestLaterDuplicateKeysAreDroppedFromTheCandidates(t *testing.T) {
	t.Parallel()

	shared := keyFilledFrom(5)

	t.Run("two names, one key", func(t *testing.T) {
		t.Parallel()

		set := buildSecretSet(map[string]Secret{
			"alice": eeSecretOf(shared, candidatesCover),
			"bob":   eeSecretOf(shared, "other.example.org"),
		}, nil, nil, nil)

		require.Len(t, set.cands, 1, "the same key twice is one candidate")
		assert.Equal(t, []int{0}, set.candIdx, "the earlier name stays")
		assert.Equal(t, map[string]int{"alice": 0}, set.candByName)
		assert.Equal(t, []int{0, 1}, set.hosted, "set.hosted still lists both")

		pos, tried := scanFor(t, &Proxy{tolerateTimeSkewness: time.Hour}, set, shared)
		assert.Equal(t, 0, pos)
		assert.Equal(t, 1, tried)
		assert.Equal(t, "alice", set.names[set.candIdx[pos]], "the earlier name wins, as it did")
	})

	t.Run("a repeat among other keys", func(t *testing.T) {
		t.Parallel()

		// a and d share a key, with b and c between them.
		set := buildSecretSet(map[string]Secret{
			"a": eeSecretOf(shared, candidatesCover),
			"b": eeSecretOf(keyFilledFrom(50), candidatesCover),
			"c": eeSecretOf(keyFilledFrom(90), candidatesCover),
			"d": eeSecretOf(shared, candidatesCover),
		}, nil, nil, nil)

		assert.Len(t, set.cands, 3)
		assert.Equal(t, []int{0, 1, 2}, set.candIdx, "d is gone, the others keep their order")
		assert.Equal(t, map[string]int{"a": 0, "b": 1, "c": 2}, set.candByName)
	})

	t.Run("a hostless secret does not shadow an ee secret with its key", func(t *testing.T) {
		t.Parallel()

		// aaa sorts first and is not hosted, so its key was never a candidate:
		// the ee secret that shares it is the first, and the only, one.
		set := buildSecretSet(map[string]Secret{
			"aaa": ddSecretOf(shared),
			"zzz": eeSecretOf(shared, candidatesCover),
		}, nil, nil, nil)

		require.Len(t, set.cands, 1)
		assert.Equal(t, []int{1}, set.candIdx)
		assert.Equal(t, map[string]int{"zzz": 0}, set.candByName)

		pos, _ := scanFor(t, &Proxy{tolerateTimeSkewness: time.Hour}, set, shared)
		assert.Equal(t, 0, pos)
	})

	t.Run("at the door", func(t *testing.T) {
		t.Parallel()

		// aaa (dd) is the one that makes the candidate position (0) differ from
		// the index into secrets (1); ccc repeats bbb's key.
		secrets := map[string]Secret{
			"aaa": ddSecretOf(keyFilledFrom(100)),
			"bbb": eeSecretOf(shared, candidatesCover),
			"ccc": eeSecretOf(shared, candidatesCover),
		}

		h := newEntryHarness(t, secrets, nil)

		admitted, ok := h.fakeTLSAttempt(t, fakeTLSClientHello(t, shared, candidatesCover, bytes.Repeat([]byte{0x41}, 32)))
		require.True(t, ok)
		assert.Equal(t, "bbb", admitted.secretName, "the earlier of the two names, and not the secret at the match position")
		assert.Equal(t, shared[:], admitted.matchedSecretKey)

		refused, ok := h.fakeTLSAttempt(t, fakeTLSClientHello(t, secrets["aaa"].Key, candidatesCover, bytes.Repeat([]byte{0x42}, 32)))
		assert.False(t, ok, "a dd key does not authenticate on the FakeTLS door")
		assert.Empty(t, refused.secretName)
		assert.Equal(t, 1, h.events.frontings())
	})
}

func TestCandByNameMapsNamesToPositions(t *testing.T) {
	t.Parallel()

	shared := keyFilledFrom(7)

	set := buildSecretSet(map[string]Secret{
		"aaa": ddSecretOf(keyFilledFrom(30)),
		"bbb": eeSecretOf(shared, candidatesCover),
		"ccc": eeSecretOf(shared, "other.example.org"),
		"ddd": plainSecretOf(keyFilledFrom(60)),
		"eee": eeSecretOf(keyFilledFrom(90), candidatesCover),
		"fff": eeSecretOf(keyFilledFrom(120), candidatesCover),
	}, nil, nil, nil)

	require.Equal(t, []int{1, 4, 5}, set.candIdx)
	require.Len(t, set.candByName, len(set.cands))

	for pos, idx := range set.candIdx {
		got, ok := set.candByName[set.names[idx]]
		require.True(t, ok, "%s is a candidate", set.names[idx])
		assert.Equal(t, pos, got, "the position of %s", set.names[idx])
	}

	for _, name := range []string{"aaa", "ccc", "ddd"} {
		_, ok := set.candByName[name]
		assert.False(t, ok, "%s is a dd or plain secret or a repeat: no candidate", name)
	}
}

// TestNoHostedSecretsMeansNoCandidatesAndFronting: a set with no ee secret has
// nothing to verify a hello against, and what the door does is what it always
// did -- front with the set's own front host, which is empty.
func TestNoHostedSecretsMeansNoCandidatesAndFronting(t *testing.T) {
	t.Parallel()

	dd, plain := keyFilledFrom(3), keyFilledFrom(33)
	secrets := map[string]Secret{"aaa": ddSecretOf(dd), "bbb": plainSecretOf(plain)}

	set := buildSecretSet(secrets, nil, nil, nil)

	require.Empty(t, set.hosted)
	assert.Empty(t, set.cands)
	assert.Empty(t, set.candIdx)
	assert.Empty(t, set.candByName)
	assert.Empty(t, set.hostnames)
	assert.Empty(t, set.frontHost, "no ee secret, no front host")

	// Nothing is scanned: the hello names a host (so it is past the SNI gate)
	// and carries a key the set holds, and still no verification is made.
	forbidden := func(pos int) bool {
		t.Errorf("skip asked about position %d of an empty candidate list", pos)

		return false
	}

	p := &Proxy{tolerateTimeSkewness: time.Hour}
	parsed := parsedHello(t, fakeTLSClientHello(t, dd, candidatesCover, bytes.Repeat([]byte{0x33}, 32)), candidatesCover)

	pos, tried := p.scanCandidates(parsed, set, forbidden)
	assert.Equal(t, -1, pos)
	assert.Zero(t, tried)

	// The set a test builds by hand has none of the three fields set at all.
	pos, tried = p.scanCandidates(parsed, &secretSet{}, forbidden)
	assert.Equal(t, -1, pos)
	assert.Zero(t, tried)

	t.Run("fronted with the empty front host", func(t *testing.T) {
		t.Parallel()

		h := newEntryHarness(t, secrets, nil)
		// The harness's own fronting host would stand in for whatever the door
		// asks for, so the door's choice could not be told. With none configured
		// an empty host is "no target": the connection is closed, nothing dialled.
		h.proxy.domainFrontingHost = ""

		ctx, ok := h.fakeTLSAttempt(t, fakeTLSClientHello(t, dd, candidatesCover, bytes.Repeat([]byte{0x51}, 32)))
		assert.False(t, ok)
		assert.Empty(t, ctx.secretName)
		assert.Zero(t, h.events.frontings(), "an empty front host is not dialled")
		assert.Zero(t, h.network.frontingDials())
	})

	t.Run("past the SNI gate with no candidate", func(t *testing.T) {
		t.Parallel()

		// A dd secret that carries a host names it for the SNI gate (hostnames
		// follow Host, not Hosted) but is no candidate: the hello passes the gate,
		// meets an empty list and is refused, and its own key does not get it in.
		carrying := ddSecretOf(dd)
		carrying.Host = candidatesCover

		h := newEntryHarness(t, map[string]Secret{"aaa": carrying}, nil)

		require.Equal(t, []string{candidatesCover}, h.proxy.secrets.Load().hostnames)
		require.Empty(t, h.proxy.secrets.Load().cands)

		ctx, ok := h.fakeTLSAttempt(t, fakeTLSClientHello(t, dd, candidatesCover, bytes.Repeat([]byte{0x52}, 32)))
		assert.False(t, ok)
		assert.Empty(t, ctx.secretName)
		assert.Equal(t, 1, h.events.frontings(), "fronted, as any refused hello is")
	})
}

// dialRecorder is the harness network with a native dialer that notes where
// fronting would dial and refuses to dial there, so a test can tell which cover
// host the door asked for without any connection being made.
type dialRecorder struct {
	*fakeNetwork

	mu    sync.Mutex
	addrs []string
}

func (d *dialRecorder) NativeDialer() *net.Dialer {
	return &net.Dialer{
		Control: func(_, address string, _ syscall.RawConn) error {
			d.mu.Lock()
			defer d.mu.Unlock()

			d.addrs = append(d.addrs, address)

			return errors.New("the test does not dial")
		},
	}
}

func (d *dialRecorder) dialed() []string {
	d.mu.Lock()
	defer d.mu.Unlock()

	return slices.Clone(d.addrs)
}

// TestRefusedHelloIsFrontedWithTheHostItNamed pins the cover site each exit of
// the FakeTLS door fronts with, which is what a prober sees: a hello that got
// past the SNI gate goes to the host it named, a hello that did not (or did not
// parse) goes to the set's front host.
func TestRefusedHelloIsFrontedWithTheHostItNamed(t *testing.T) {
	t.Parallel()

	// Both names are IP literals, so nothing is resolved. "aaa" sorts first, so
	// its host is the set's front host; "bbb" is the host the hellos name.
	const frontHost, namedHost = "127.0.0.2", "127.0.0.1"

	aaa, bbb := keyFilledFrom(15), keyFilledFrom(75)

	newHarness := func(t *testing.T, limits map[string]SecretLimits) (*entryHarness, *dialRecorder) {
		t.Helper()

		h := newEntryHarness(t, map[string]Secret{
			"aaa": eeSecretOf(aaa, frontHost),
			"bbb": eeSecretOf(bbb, namedHost),
		}, limits)

		require.Equal(t, frontHost, h.proxy.secrets.Load().frontHost)

		recorder := &dialRecorder{fakeNetwork: h.network}

		h.proxy.network = recorder
		h.proxy.domainFrontingHost = "" // the host asked for is the host dialled
		h.proxy.domainFrontingPort = 443

		return h, recorder
	}

	hello := func(key [SecretKeyLength]byte, sni string, id byte) []byte {
		return fakeTLSClientHello(t, key, sni, bytes.Repeat([]byte{id}, 32))
	}

	t.Run("no candidate matches", func(t *testing.T) {
		t.Parallel()

		h, recorder := newHarness(t, nil)

		_, ok := h.fakeTLSAttempt(t, hello(keyFilledFrom(200), namedHost, 0x61))
		assert.False(t, ok)
		assert.Equal(t, []string{namedHost + ":443"}, recorder.dialed())
	})

	t.Run("the SNI gate refuses", func(t *testing.T) {
		t.Parallel()

		h, recorder := newHarness(t, nil)

		_, ok := h.fakeTLSAttempt(t, hello(bbb, "elsewhere.example.org", 0x62))
		assert.False(t, ok)
		assert.Equal(t, []string{frontHost + ":443"}, recorder.dialed())
	})

	t.Run("not a hello", func(t *testing.T) {
		t.Parallel()

		h, recorder := newHarness(t, nil)

		_, ok := h.fakeTLSAttempt(t, []byte("GET / HTTP/1.1\r\nHost: example.org\r\n\r\n"))
		assert.False(t, ok)
		assert.Equal(t, []string{frontHost + ":443"}, recorder.dialed())
	})

	t.Run("a replay", func(t *testing.T) {
		t.Parallel()

		h, recorder := newHarness(t, nil)

		captured := hello(bbb, namedHost, 0x63)

		_, ok := h.fakeTLSAttempt(t, captured)
		require.True(t, ok)
		require.Empty(t, recorder.dialed())

		_, ok = h.fakeTLSAttempt(t, captured)
		assert.False(t, ok)
		assert.Equal(t, 1, h.events.replays())
		assert.Equal(t, []string{namedHost + ":443"}, recorder.dialed())
	})

	t.Run("a user over a limit", func(t *testing.T) {
		t.Parallel()

		h, recorder := newHarness(t, map[string]SecretLimits{"bbb": {Disabled: true}})

		ctx, ok := h.fakeTLSAttempt(t, hello(bbb, namedHost, 0x64))
		assert.False(t, ok)
		assert.Equal(t, "bbb", ctx.secretName, "the match was made before the limit refused it")
		assert.Equal(t, []string{namedHost + ":443"}, recorder.dialed())
	})
}

func TestScanCandidatesSkipsAndCounts(t *testing.T) {
	t.Parallel()

	keys := [][SecretKeyLength]byte{keyFilledFrom(10), keyFilledFrom(50), keyFilledFrom(90), keyFilledFrom(130)}

	set := buildSecretSet(map[string]Secret{
		"a": eeSecretOf(keys[0], candidatesCover),
		"b": eeSecretOf(keys[1], candidatesCover),
		"c": eeSecretOf(keys[2], candidatesCover),
		"d": eeSecretOf(keys[3], candidatesCover),
	}, nil, nil, nil)

	require.Len(t, set.cands, 4)

	p := &Proxy{tolerateTimeSkewness: time.Hour}
	wire := fakeTLSClientHello(t, keys[2], candidatesCover, bytes.Repeat([]byte{0x33}, 32))
	parsed := parsedHello(t, wire, candidatesCover)

	// asked records the positions skip is called with, in order.
	run := func(skipAt func(pos int) bool) (pos, tried int, asked []int) {
		pos, tried = p.scanCandidates(parsed, set, func(at int) bool {
			asked = append(asked, at)

			return skipAt(at)
		})

		return pos, tried, asked
	}

	pos, tried := p.scanCandidates(parsed, set, nil)
	assert.Equal(t, 2, pos, "no skip: c is the third")
	assert.Equal(t, 3, tried)

	pos, tried, asked := run(func(int) bool { return false })
	assert.Equal(t, 2, pos)
	assert.Equal(t, 3, tried)
	assert.Equal(t, []int{0, 1, 2}, asked, "the scan stops at the match")

	pos, tried, asked = run(func(at int) bool { return at == 0 })
	assert.Equal(t, 2, pos)
	assert.Equal(t, 2, tried, "a skipped position is not verified, so not counted")
	assert.Equal(t, []int{0, 1, 2}, asked)

	pos, tried, asked = run(func(at int) bool { return at == 2 })
	assert.Equal(t, -1, pos, "the one candidate that would match is skipped")
	assert.Equal(t, 3, tried)
	assert.Equal(t, []int{0, 1, 2, 3}, asked)

	pos, tried, _ = run(func(int) bool { return true })
	assert.Equal(t, -1, pos)
	assert.Zero(t, tried)

	// A hello no candidate matches is verified against all of them.
	stranger := parsedHello(t, fakeTLSClientHello(t, keyFilledFrom(200), candidatesCover, bytes.Repeat([]byte{0x34}, 32)), candidatesCover)

	pos, tried = p.scanCandidates(stranger, set, nil)
	assert.Equal(t, -1, pos)
	assert.Equal(t, 4, tried)
}

// TestScanCandidatesUsesTheProxysSkew: a hello stamped ten seconds ago is the
// right key at the wrong time, and the proxy's tolerance is what decides.
func TestScanCandidatesUsesTheProxysSkew(t *testing.T) {
	t.Parallel()

	key := keyFilledFrom(11)
	set := buildSecretSet(map[string]Secret{"a": eeSecretOf(key, candidatesCover)}, nil, nil, nil)

	wire, err := testclient.ClientHelloWith(key, candidatesCover, bytes.Repeat([]byte{0x33}, 32),
		testclient.HelloOptions{At: time.Now().Add(-10 * time.Second)})
	require.NoError(t, err)

	parsed := parsedHello(t, wire, candidatesCover)

	pos, tried := (&Proxy{tolerateTimeSkewness: 3 * time.Second}).scanCandidates(parsed, set, nil)
	assert.Equal(t, -1, pos, "ten seconds late under a 3 s tolerance")
	assert.Equal(t, 1, tried)

	pos, tried = (&Proxy{tolerateTimeSkewness: time.Hour}).scanCandidates(parsed, set, nil)
	assert.Equal(t, 0, pos, "the same hello under an hour")
	assert.Equal(t, 1, tried)
}
