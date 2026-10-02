package mtglib

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/Arman2122/mtg-proxy/essentials"
	"github.com/Arman2122/mtg-proxy/mtglib/internal/tls/fake"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func hostlessSecret(t *testing.T, mode SecretMode) Secret {
	t.Helper()

	secret, err := GenerateSecretMode(mode, "")
	require.NoError(t, err)

	return secret
}

func TestSecretsCanFront(t *testing.T) {
	t.Parallel()

	hosted := GenerateSecret("front.example.com")
	dd := hostlessSecret(t, SecretModeDD)
	plain := hostlessSecret(t, SecretModePlain)

	cases := []struct {
		name       string
		secrets    map[string]Secret
		frontHost  string
		wantCanFro bool
	}{
		{"one ee secret", map[string]Secret{"a": hosted}, "", true},
		{"ee among hostless", map[string]Secret{"a": dd, "b": hosted}, "", true},
		{"all hostless, no cover host", map[string]Secret{"a": dd, "b": plain}, "", false},
		{"all hostless, explicit cover host", map[string]Secret{"a": dd}, "cover.example.com", true},
		{"no secrets at all", nil, "", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tc.wantCanFro, SecretsCanFront(tc.secrets, tc.frontHost))
		})
	}
}

// TestSwapRejectsAllHostlessSecrets is the invariant that closes the
// PUT /secrets route into a state where the always-present FakeTLS listener has
// no cover site. The previous set must stay active.
func TestSwapRejectsAllHostlessSecrets(t *testing.T) {
	t.Parallel()

	hosted := GenerateSecret("front.example.com")
	dd := hostlessSecret(t, SecretModeDD)

	p := newLimitTestProxy(map[string]Secret{"alice": hosted}, nil)

	err := p.ReplaceSecrets(SecretConfig{Secrets: map[string]Secret{"bob": dd}})
	require.ErrorIs(t, err, ErrSecretInvalid)

	assert.Equal(t, []string{"alice"}, p.secrets.Load().names, "the previous set must stay active")

	// With an explicit cover host the very same swap is legal.
	p.domainFrontingHost = "cover.example.com"
	require.NoError(t, p.ReplaceSecrets(SecretConfig{Secrets: map[string]Secret{"bob": dd}}))
	assert.Equal(t, []string{"bob"}, p.secrets.Load().names)
}

// TestSecretSetFrontHostSkipsHostless pins the replacement for secrets[0].Host,
// which under a management panel was whichever client name sorted first and is
// now possibly hostless.
func TestSecretSetFrontHostSkipsHostless(t *testing.T) {
	t.Parallel()

	// "aaa" sorts first and carries no hostname; "zzz" is the only ee secret.
	set := buildSecretSet(map[string]Secret{
		"aaa": hostlessSecret(t, SecretModePlain),
		"mmm": hostlessSecret(t, SecretModeDD),
		"zzz": GenerateSecret("cover.example.com"),
	}, nil, nil, nil)

	assert.Equal(t, "cover.example.com", set.frontHost)
	assert.Equal(t, []int{2}, set.hosted, "only ee secrets are FakeTLS HMAC candidates")

	// The empty string must never become a matchable SNI: a hostless secret
	// would otherwise answer a ClientHello carrying no server_name at all.
	assert.Equal(t, []string{"cover.example.com"}, set.hostnames)
	assert.NotContains(t, set.hostnames, "")
}

func TestSecretSetHostedIndicesMapBackToNames(t *testing.T) {
	t.Parallel()

	set := buildSecretSet(map[string]Secret{
		"aaa": hostlessSecret(t, SecretModeDD),
		"bbb": GenerateSecret("b.example.com"),
		"ccc": hostlessSecret(t, SecretModePlain),
		"ddd": GenerateSecret("d.example.com"),
	}, nil, nil, nil)

	require.Equal(t, []int{1, 3}, set.hosted)

	// A FakeTLS match reports its index into the HOSTED candidate list, so this
	// mapping is what stands between a client and another client's quota.
	assert.Equal(t, "bbb", set.names[set.hosted[0]])
	assert.Equal(t, "ddd", set.names[set.hosted[1]])
}

func TestDomainFrontingAddressWithoutTarget(t *testing.T) {
	t.Parallel()

	p := &Proxy{domainFrontingPort: 443}
	p.secrets.Store(buildSecretSet(map[string]Secret{"a": hostlessSecret(t, SecretModeDD)}, nil, nil, nil))

	// JoinHostPort("", "443") is ":443", which net.Dial reads as the local
	// system -- i.e. our own bind-to.
	assert.Empty(t, p.DomainFrontingAddress())

	p.domainFrontingHost = "cover.example.com"
	assert.Equal(t, "cover.example.com:443", p.DomainFrontingAddress())
}

// TestDomainFrontingWithNoTargetClosesWithoutDialling is the last guard: every
// probe would otherwise recurse into a fresh self-connection.
func TestDomainFrontingWithNoTargetClosesWithoutDialling(t *testing.T) {
	t.Parallel()

	h := newEntryHarness(t, map[string]Secret{"alice": GenerateSecret("front.example.com")}, nil)
	h.proxy.domainFrontingHost = ""
	h.proxy.domainFrontingPort = 443
	h.proxy.secrets.Store(buildSecretSet(
		map[string]Secret{"alice": hostlessSecret(t, SecretModeDD)}, nil, nil, nil,
	))

	client, done := h.dialProxy(t, nil)

	// Garbage on the FakeTLS door: the fronting path is what it takes.
	_, err := client.Write([]byte("not a client hello at all"))
	require.NoError(t, err)

	client.Close() //nolint: errcheck
	<-done

	assert.Equal(t, 0, h.events.frontings(), "fronting must be abandoned before it starts")
	assert.Equal(t, 0, h.network.frontingDials(), "and no dial may be attempted")
}

// fakeTLSClientHello forges the exact bytes an mtg client sends: a TLS 1.0
// record carrying a TLS 1.2 ClientHello with sni, whose client random is the
// HMAC-SHA256 of the whole message under key (computed with the random
// nullified) XORed with a little-endian timestamp. It is the inverse of
// fake.ReadClientHelloMulti, and it is what makes the ee entry testable without
// a live client.
func fakeTLSClientHello(t testing.TB, key [SecretKeyLength]byte, sni string, sessionID []byte) []byte {
	t.Helper()

	var extensions bytes.Buffer

	extensions.Write([]byte{0x00, 0x00})                                // extension type: server_name
	binary.Write(&extensions, binary.BigEndian, uint16(2+1+2+len(sni))) //nolint: errcheck
	binary.Write(&extensions, binary.BigEndian, uint16(1+2+len(sni)))   //nolint: errcheck
	extensions.WriteByte(0x00)                                          // name type: DNS hostname
	binary.Write(&extensions, binary.BigEndian, uint16(len(sni)))       //nolint: errcheck
	extensions.WriteString(sni)

	var body bytes.Buffer

	body.Write([]byte{0x03, 0x03})           // client version: TLS 1.2
	body.Write(make([]byte, fake.RandomLen)) // random, filled in below
	body.WriteByte(byte(len(sessionID)))
	body.Write(sessionID)
	body.Write([]byte{0x00, 0x02, 0x13, 0x01})                      // one cipher suite, not GREASE
	body.Write([]byte{0x01, 0x00})                                  // one compression method: null
	binary.Write(&body, binary.BigEndian, uint16(extensions.Len())) //nolint: errcheck
	body.Write(extensions.Bytes())

	var record bytes.Buffer

	// The record layer version has to be 3,1: that is what the reader demands
	// and what it reconstructs before HMACing, so the bytes on the wire and the
	// bytes under the HMAC are the same.
	record.Write([]byte{0x16, 0x03, 0x01})
	binary.Write(&record, binary.BigEndian, uint16(1+3+body.Len())) //nolint: errcheck
	record.WriteByte(0x01)                                          // handshake type: ClientHello
	record.Write([]byte{
		byte(body.Len() >> 16), byte(body.Len() >> 8), byte(body.Len()),
	})
	record.Write(body.Bytes())

	raw := record.Bytes()

	digest := hmac.New(sha256.New, key[:])
	digest.Write(raw)

	computed := digest.Sum(nil)

	var timestamp [4]byte

	binary.LittleEndian.PutUint32(timestamp[:], uint32(time.Now().Unix()))

	// random = digest XOR (28 zero bytes || timestamp), so the reader's
	// digest^random recovers exactly that.
	random := raw[fake.RandomOffset : fake.RandomOffset+fake.RandomLen]
	copy(random, computed)

	for i := range timestamp {
		random[fake.RandomLen-4+i] ^= timestamp[i]
	}

	return raw
}

// fakeTLSAttempt runs one ClientHello through the FakeTLS entry and reports
// whether it was admitted, and under which name. doFakeTLSHandshake is called
// directly so the test does not need a doppelganger, which the ee path builds
// only afterwards.
func (h *entryHarness) fakeTLSAttempt(t *testing.T, hello []byte) (*streamContext, bool) {
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

	_, err = client.Write(hello)
	require.NoError(t, err)

	ctx := newStreamContext(h.proxy.ctx, h.proxy.logger, essentials.WrapNetConn(server))
	t.Cleanup(ctx.Close)

	return ctx, h.proxy.doFakeTLSHandshake(ctx)
}

// TestFakeTLSAdmitsOnlyHostedSecrets is the reason secretSet.hosted exists.
// ReadClientHelloMulti matches SNI against the GLOBAL hostname list and then
// HMACs against every key it is handed, so a hostless key left in that list
// would let its owner authenticate under somebody else's hostname -- and, since
// the match reports an index into the candidate list, would bill the stream to
// whichever name happened to sit at that position.
func TestFakeTLSAdmitsOnlyHostedSecrets(t *testing.T) {
	t.Parallel()

	// "aaa" sorts first and is hostless; "zzz" is the only ee secret.
	hostless := hostlessSecret(t, SecretModePlain)
	hosted := GenerateSecret("cover.example.com")

	h := newEntryHarness(t, map[string]Secret{"aaa": hostless, "zzz": hosted}, nil)

	sessionID := bytes.Repeat([]byte{0x11}, 32)

	borrowed, ok := h.fakeTLSAttempt(t, fakeTLSClientHello(t, hostless.Key, "cover.example.com", sessionID))
	assert.False(t, ok, "a hostless secret's key must not authenticate on the FakeTLS door")
	assert.Empty(t, borrowed.secretName)
	assert.Equal(t, 1, h.events.frontings(), "a refused ClientHello is fronted, as always")

	sessionID = bytes.Repeat([]byte{0x22}, 32)

	admitted, ok := h.fakeTLSAttempt(t, fakeTLSClientHello(t, hosted.Key, "cover.example.com", sessionID))
	require.True(t, ok, "the ee secret must still be admitted")
	assert.Equal(t, "zzz", admitted.secretName,
		"the matched index is into the hosted list and must be mapped back")
	assert.Equal(t, entryFakeTLS, admitted.entry)
}
