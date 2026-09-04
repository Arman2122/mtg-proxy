package mtglib

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Arman2122/mtg-proxy/essentials"
	"github.com/Arman2122/mtg-proxy/mtglib/internal/middleproxy"
	"github.com/Arman2122/mtg-proxy/mtglib/obfuscation"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEffectiveAdTag(t *testing.T) {
	t.Parallel()

	alice := GenerateSecret("alice.example.com")
	bob := GenerateSecret("bob.example.com")

	global := [AdTagLength]byte{0xff}
	perBob := [AdTagLength]byte{0xbb}

	set := buildSecretSet(
		map[string]Secret{"alice": alice, "bob": bob},
		map[string][AdTagLength]byte{"bob": perBob},
		&global,
		nil,
	)

	// names are sorted: alice=0, bob=1.
	require.Equal(t, []string{"alice", "bob"}, set.names)

	// alice has no override -> falls back to the global tag.
	require.NotNil(t, set.effectiveAdTag(0))
	assert.Equal(t, global, *set.effectiveAdTag(0))

	// bob has an override -> its own tag wins.
	require.NotNil(t, set.effectiveAdTag(1))
	assert.Equal(t, perBob, *set.effectiveAdTag(1))
}

func TestEffectiveAdTagNoGlobal(t *testing.T) {
	t.Parallel()

	alice := GenerateSecret("alice.example.com")

	set := buildSecretSet(map[string]Secret{"alice": alice}, nil, nil, nil)

	// No override and no global tag -> nil (the direct-DC path).
	assert.Nil(t, set.effectiveAdTag(0))
}

func TestReloadKeepsAdTags(t *testing.T) {
	t.Parallel()

	alice := GenerateSecret("alice.example.com")
	global := [AdTagLength]byte{0x11}

	p := newReloadTestProxy(map[string]Secret{"alice": alice})
	p.reloader = func() (SecretConfig, error) {
		return SecretConfig{
			Secrets:     map[string]Secret{"alice": alice},
			GlobalAdTag: &global,
		}, nil
	}

	require.NoError(t, p.ReloadSecrets())
	require.NotNil(t, p.secrets.Load().globalAdTag)
	assert.Equal(t, global, *p.secrets.Load().globalAdTag)
}

// testMiddleProxyAddr is the middle-proxy address advertised for one DC.
// Nothing else in the proxy can produce these addresses, so seeing one in
// fakeNetwork.dialed is unambiguous proof that doTelegramCall took the
// advertising path. They differ PER DC on purpose: with a single shared address
// the dial string would be identical whatever DC the manager was asked for, and
// a stream routed to the wrong middle proxy would look exactly like a correct
// one.
func testMiddleProxyAddr(dcID int) string {
	return fmt.Sprintf("10.0.0.%d:8888", dcID)
}

// middleConfigTransport answers the three core.telegram.org fetches
// middleproxy.Manager makes on first use, so DialProxyStream becomes ready
// without touching the network. The advertised address is never really dialled:
// fakeNetwork routes every dial to the harness upstream and only records the
// address it was asked for.
type middleConfigTransport struct{}

func (middleConfigTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	var body string

	switch req.URL.Path {
	case "/getProxySecret":
		body = "0123456789abcdef"
	case "/getProxyConfig":
		// Every DC the tests use: without an entry the manager would refuse
		// before dialling, and a gate regression would then hide behind
		// "no middle proxy address for dc N".
		body = "proxy_for 2 " + testMiddleProxyAddr(2) + ";\n" +
			"proxy_for 4 " + testMiddleProxyAddr(4) + ";\n" +
			"proxy_for 5 " + testMiddleProxyAddr(5) + ";\n"
	}

	// An empty v6 config parses to an empty map, which is a success: the manager
	// is ready on v4 alone.
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{},
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    req,
	}, nil
}

// newAdTagHarness is an entryHarness with the given advertising configuration
// and a ready middle proxy. A global tag makes the routing decision depend on
// the client's transport alone; per-secret tags with no global one make it
// depend on WHICH user connected.
func newAdTagHarness(
	t *testing.T,
	secrets map[string]Secret,
	perSecret map[string][AdTagLength]byte,
	global *[AdTagLength]byte,
) (*entryHarness, <-chan net.Conn) {
	t.Helper()

	h := newEntryHarness(t, secrets, nil)

	h.proxy.secrets.Store(buildSecretSet(secrets, perSecret, global, nil))

	h.proxy.middleProxy = middleproxy.NewManager(
		h.proxy.ctx,
		&http.Client{Transport: middleConfigTransport{}},
		testLogger(),
		DefaultPreferIP,
	)

	accepted := make(chan net.Conn, 4)

	go func() {
		defer close(accepted)

		for {
			conn, err := h.upstream.Accept()
			if err != nil {
				return
			}

			accepted <- conn
		}
	}()

	return h, accepted
}

// nextUpstream returns the next connection the proxy opened towards Telegram,
// deadlined so a routing regression fails rather than hangs.
func nextUpstream(t *testing.T, accepted <-chan net.Conn) net.Conn {
	t.Helper()

	select {
	case conn := <-accepted:
		require.NotNil(t, conn, "the harness upstream stopped accepting")
		require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
		t.Cleanup(func() { conn.Close() }) //nolint: errcheck

		return conn
	case <-time.After(10 * time.Second):
		require.FailNow(t, "the proxy never dialled out")

		return nil
	}
}

// dialedAddresses copies what fakeNetwork was asked to dial, in order.
func dialedAddresses(n *fakeNetwork) []string {
	n.mu.Lock()
	defer n.mu.Unlock()

	return slices.Clone(n.dialed)
}

// userStatsJSON returns one user's object from /stats as raw fields, so a test
// can assert on key PRESENCE and not merely on a decoded zero.
func userStatsJSON(t *testing.T, stats *ProxyStats, name string) map[string]json.RawMessage {
	t.Helper()

	rec := httptest.NewRecorder()
	stats.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/stats", nil))

	var raw map[string]json.RawMessage

	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &raw))

	var users map[string]json.RawMessage

	require.NoError(t, json.Unmarshal(raw["users"], &users))
	require.Contains(t, users, name)

	var user map[string]json.RawMessage

	require.NoError(t, json.Unmarshal(users[name], &user))

	return user
}

// TestAdTagIntermediateModesAreOfferedToMiddleProxy is the assertion that
// matters most here. The abridged arm of doTelegramCall is a narrowing of the
// advertising path, and a gate one case too wide silently disables advertising
// for a whole client population -- a revenue bug that logs nothing and breaks
// no connection. The observable is the dial: the middle proxy lives at a
// config-supplied address no other code path can produce.
//
// BOTH intermediate tags are driven because they are separate populations:
// tdlib sends 0xeeeeeeee (plain intermediate) for a bare 16-byte key, which is
// exactly the plain mode here, so a gate that skipped only padded-intermediate
// would still be one case too wide.
//
// What this does NOT prove: that a single byte ever travels the advertised
// path. It proves the stream is OFFERED to the middle proxy and then falls
// through to the direct DC when the offer fails. Nothing in mtglib observes the
// success tail of doMiddleProxyCall -- that needs an RPC-speaking fake, which
// today lives unexported in the middleproxy package.
func TestAdTagIntermediateModesAreOfferedToMiddleProxy(t *testing.T) {
	t.Parallel()

	for _, tag := range []obfuscation.ConnectionTag{
		obfuscation.TagPaddedIntermediate,
		obfuscation.TagIntermediate,
	} {
		t.Run(tag.String(), func(t *testing.T) {
			t.Parallel()

			alice, err := GenerateSecretMode(SecretModePlain, "")
			require.NoError(t, err)

			adTag := [AdTagLength]byte{0xad}
			h, accepted := newAdTagHarness(t, map[string]Secret{"alice": alice}, nil, &adTag)

			client, done := h.dialProxy(t, obfuscatedPolicy(ModeSetOf(SecretModePlain), UnknownSecretClose))
			require.NoError(t, client.SetDeadline(time.Now().Add(10*time.Second)))

			// DC 4, not the default 2: only a non-default DC can show that both
			// the middle-proxy dial and the fall-through use the DC the CLIENT
			// asked for rather than a hardcoded default.
			_, err = client.Write(obfuscatedFrame(t, alice.Key, tag, 4))
			require.NoError(t, err)

			middle := nextUpstream(t, accepted)

			// Asserted BEFORE the Close below on purpose: with the gate inverted
			// this first connection is the direct leg, and closing it would kill
			// the stream and leave the second Accept to time out instead of
			// failing here.
			require.Equal(t, []string{testMiddleProxyAddr(4)}, dialedAddresses(h.network),
				"an ad-tagged intermediate stream must be offered to DC 4's middle proxy first")

			// Drop the middle-proxy leg so its RPC handshake fails and
			// doTelegramCall falls through to the direct DC. That fall-through is
			// what keeps an ad-tagged client online when advertising cannot be
			// delivered.
			middle.Close() //nolint: errcheck

			nextUpstream(t, accepted)

			assert.Equal(t,
				[]string{testMiddleProxyAddr(4), h.proxy.telegram.GetAddresses(4)[0].Address},
				dialedAddresses(h.network),
				"the middle proxy is tried first, then the client's own DC -- and nothing else")

			// ad_tag_skipped names the transport that has no reframer. Counting a
			// stream the middle proxy handles natively would make the field
			// useless for diagnosing lost advertising.
			assert.NotContains(t, userStatsJSON(t, h.proxy.stats, "alice"), "ad_tag_skipped")

			client.Close() //nolint: errcheck
			<-done
		})
	}
}

// TestAdTagPerSecretRoutesOnlyTheTaggedUser covers the WIRING of
// secretSet.effectiveAdTag into the stream, which TestEffectiveAdTag (a lookup
// in isolation) cannot. With per-secret tags and no global tag, whether a
// stream is advertised at all depends on which user connected; a fixed-index
// read would bill every user to the first-sorted secret's operator and route
// untagged users through a middle proxy they should never touch.
func TestAdTagPerSecretRoutesOnlyTheTaggedUser(t *testing.T) {
	t.Parallel()

	alice, err := GenerateSecretMode(SecretModePlain, "")
	require.NoError(t, err)

	bob, err := GenerateSecretMode(SecretModePlain, "")
	require.NoError(t, err)

	// alice (sorted index 0) is tagged, bob (index 1) is not, and there is no
	// global tag: bob's only route to a middle proxy is a misattributed lookup.
	h, accepted := newAdTagHarness(t,
		map[string]Secret{"alice": alice, "bob": bob},
		map[string][AdTagLength]byte{"alice": {0xa1}},
		nil,
	)

	// bob first and alone, so the dial order below is unambiguous.
	bobClient, bobDone := h.dialProxy(t, obfuscatedPolicy(ModeSetOf(SecretModePlain), UnknownSecretClose))
	require.NoError(t, bobClient.SetDeadline(time.Now().Add(10*time.Second)))

	_, err = bobClient.Write(obfuscatedFrame(t, bob.Key, obfuscation.TagPaddedIntermediate, 2))
	require.NoError(t, err)

	nextUpstream(t, accepted)

	require.Equal(t,
		[]string{h.proxy.telegram.GetAddresses(2)[0].Address},
		dialedAddresses(h.network),
		"an untagged user must go straight to the DC, never to a middle proxy")

	bobClient.Close() //nolint: errcheck
	<-bobDone

	// alice, the control: the same transport and the same harness, so the only
	// difference left is whose ad tag the lookup returned.
	aliceClient, aliceDone := h.dialProxy(t, obfuscatedPolicy(ModeSetOf(SecretModePlain), UnknownSecretClose))
	require.NoError(t, aliceClient.SetDeadline(time.Now().Add(10*time.Second)))

	// DC 5, where every other middle-proxy assertion uses DC 4: the address has
	// to be looked up per DC, and with both tests on one DC a hardcoded lookup
	// would satisfy them both.
	_, err = aliceClient.Write(obfuscatedFrame(t, alice.Key, obfuscation.TagPaddedIntermediate, 5))
	require.NoError(t, err)

	middle := nextUpstream(t, accepted)

	require.Equal(t,
		[]string{h.proxy.telegram.GetAddresses(2)[0].Address, testMiddleProxyAddr(5)},
		dialedAddresses(h.network),
		"the tagged user must be offered to the middle proxy for its own DC")

	// Fall through so ServeConn finishes rather than sitting in the RPC
	// handshake while the test waits on aliceDone.
	middle.Close() //nolint: errcheck
	nextUpstream(t, accepted)

	aliceClient.Close() //nolint: errcheck
	<-aliceDone
}

// TestAdTagAbridgedTakesDirectPath pins the skip itself: abridged has no
// middle-proxy reframer, so the stream must lose the sponsored channel and
// nothing else. It relays real bytes both ways because "did not crash" is not
// the same claim as "stayed online".
func TestAdTagAbridgedTakesDirectPath(t *testing.T) {
	t.Parallel()

	alice, err := GenerateSecretMode(SecretModePlain, "")
	require.NoError(t, err)

	// bob never connects: he is the untouched-user control for the omitempty
	// assertion at the end.
	bob, err := GenerateSecretMode(SecretModePlain, "")
	require.NoError(t, err)

	// A global tag, so both users are advertised alike and the routing decision
	// under test can only depend on the client's transport.
	adTag := [AdTagLength]byte{0xad}
	h, accepted := newAdTagHarness(t, map[string]Secret{"alice": alice, "bob": bob}, nil, &adTag)

	client, done := h.dialProxy(t, obfuscatedPolicy(ModeSetOf(SecretModePlain), UnknownSecretClose))
	require.NoError(t, client.SetDeadline(time.Now().Add(10*time.Second)))

	// A real client conn rather than a bare frame: the claim is that this stream
	// keeps working, and only relaying through it can show that. DC 5, not the
	// default 2, so the DC the client asked for is visible downstream.
	clientConn, err := obfuscation.Obfuscator{Secret: alice.Key[:]}.
		SendHandshake(essentials.WrapNetConn(client), 5, obfuscation.TagAbridged)
	require.NoError(t, err)

	upstream := nextUpstream(t, accepted)

	// Asserted before any read on upstream: with the gate removed this is the
	// middle proxy, already blocked reading its RPC nonce reply, and the
	// ReadHandshake below would block rather than fail.
	require.Equal(t,
		[]string{h.proxy.telegram.GetAddresses(5)[0].Address},
		dialedAddresses(h.network),
		"an ad-tagged abridged stream must go straight to the DC")

	// Nil secret: the default DC addresses carry no MTProxy secret. Demanding
	// TagAbridged here pins that the direct leg announces the CLIENT's
	// transport -- hardcoding a tag on that SendHandshake corrupts every packet.
	dcID, _, tgConn, err := obfuscation.Obfuscator{}.
		ReadHandshake(essentials.WrapNetConn(upstream), obfuscation.TagSetOf(obfuscation.TagAbridged))
	require.NoError(t, err)
	assert.Equal(t, 5, dcID)

	_, err = clientConn.Write([]byte("ping from client"))
	require.NoError(t, err)

	fromClient := make([]byte, len("ping from client"))
	_, err = io.ReadFull(tgConn, fromClient)
	require.NoError(t, err)
	assert.Equal(t, "ping from client", string(fromClient))

	_, err = tgConn.Write([]byte("pong from telegram"))
	require.NoError(t, err)

	fromTelegram := make([]byte, len("pong from telegram"))
	_, err = io.ReadFull(clientConn, fromTelegram)
	require.NoError(t, err)
	assert.Equal(t, "pong from telegram", string(fromTelegram))

	// The skip is recorded against the stream's own user, not the empty name and
	// not a neighbour.
	assert.Equal(t, "1", string(userStatsJSON(t, h.proxy.stats, "alice")["ad_tag_skipped"]))

	// omitempty: a deployment that never skips must see a byte-identical user
	// object, so the field may not appear at zero.
	assert.NotContains(t, userStatsJSON(t, h.proxy.stats, "bob"), "ad_tag_skipped")

	client.Close() //nolint: errcheck
	<-done
}
