package mtglib

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Arman2122/mtg-proxy/essentials"
	"github.com/Arman2122/mtg-proxy/mtglib/obfuscation"
	"github.com/stretchr/testify/require"
)

// remoteAddrConn reports an address of its own instead of the loopback one the
// harness actually dialled over.
//
// It is not a convenience. Every socket in these tests is a real 127.0.0.1
// pair, so a report built by assuming the peer address would look correct on
// every one of them and be wrong in the only deployment that matters: behind
// the WEB relay, and behind any front proxy, RemoteAddr is whatever the PROXY
// header said, and that is the address an operator needs to see. Overriding it
// here is what makes the assertion about the plumbing rather than about
// loopback.
type remoteAddrConn struct {
	essentials.Conn

	addr net.Addr
}

func (c remoteAddrConn) RemoteAddr() net.Addr { return c.addr }

// dialProxyFrom is dialProxy with the client address the proxy will see stamped
// on the accepted end.
func dialProxyFrom(
	t *testing.T, h *entryHarness, policy *ListenerPolicy, addr net.Addr,
) (net.Conn, <-chan struct{}) {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	defer listener.Close() //nolint: errcheck

	client, err := net.Dial("tcp", listener.Addr().String())
	require.NoError(t, err)

	t.Cleanup(func() { client.Close() }) //nolint: errcheck

	server, err := listener.Accept()
	require.NoError(t, err)

	var conn essentials.Conn = remoteAddrConn{
		Conn: readCountingConn{
			Conn: essentials.WrapNetConn(server),
			read: &h.serverBytesRead,
		},
		addr: addr,
	}

	if policy != nil {
		conn = policyConn{Conn: conn, policy: *policy}
	}

	done := make(chan struct{})

	go func() {
		defer close(done)

		h.proxy.ServeConn(conn)
	}()

	return client, done
}

// connectThrough is govEntryCase.connect for a client the caller already has:
// the entry flight, the ee server-flight round trip, the Telegram dial and its
// 64-byte handshake, ending once the stream is registered under name.
//
// connect dials its own socket, which is exactly what these tests cannot use --
// the whole point here is a connection whose reported address the test chose.
func connectThrough(
	t testing.TB, ec govEntryCase, h *entryHarness, client net.Conn,
	name string, key [SecretKeyLength]byte,
) net.Conn {
	t.Helper()

	ec.openEntry(t, client, key)

	if ec.mode == SecretModeFakeTLS {
		require.NoError(t, client.SetReadDeadline(time.Now().Add(5*time.Second)))

		var first [1]byte

		_, err := io.ReadFull(client, first[:])
		require.NoError(t, err, "the ee entry must answer a valid ClientHello")
		require.EqualValues(t, 0x16, first[0])

		_, err = client.Write(ec.framePayload(
			obfuscatedFrame(t, key, obfuscation.TagPaddedIntermediate, 2),
		))
		require.NoError(t, err)
	}

	upstream, err := h.upstream.Accept()
	require.NoError(t, err, "an admitted stream must dial Telegram")

	t.Cleanup(func() { upstream.Close() }) //nolint: errcheck

	require.NoError(t, upstream.SetReadDeadline(time.Now().Add(5*time.Second)))

	var handshake [64]byte

	_, err = io.ReadFull(upstream, handshake[:])
	require.NoError(t, err)

	require.NotNil(t, h.liveStream(t, name),
		"the stream must be registered under the matched secret name")

	return upstream
}

// endStream closes both ends and waits for ServeConn to return.
//
// Both ends, always. Closing the client alone leaves the Telegram direction of
// the relay sitting on the idle tracker, which this harness deliberately sets
// to a minute so that governance is the only thing able to end a stream -- so a
// test that closed one end would still pass, a minute at a time.
func endStream(client, upstream net.Conn, done <-chan struct{}) {
	client.Close()   //nolint: errcheck
	upstream.Close() //nolint: errcheck
	<-done
}

// statsFor scrapes the management API's GET /stats -- not ProxyStats.ServeHTTP,
// which does not run the overlay and therefore reports neither connected_ips
// nor quota ceilings.
func statsFor(t *testing.T, p *Proxy) StatsResponse {
	t.Helper()

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/stats", nil)

	p.handleStats(recorder, request)

	require.Equal(t, http.StatusOK, recorder.Code)

	var resp StatsResponse

	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &resp))

	return resp
}

// A live connection's address is reported under the user it was attributed to,
// on both doors, and it is the address the socket reports rather than the one
// the test dialled over.
func TestConnectedIPsReportTheAttributedClient(t *testing.T) {
	t.Parallel()

	for _, entry := range govEntryCases() {
		t.Run(entry.name, func(t *testing.T) {
			t.Parallel()

			secret := entry.secret(t)
			h := entry.harness(t, map[string]Secret{"alice": secret}, nil)
			h.proxy.trackClientIPs = true

			client, done := dialProxyFrom(t, h, entry.policy,
				&net.TCPAddr{IP: net.IPv4(198, 51, 100, 7), Port: 51000})

			upstream := connectThrough(t, entry, h, client, "alice", secret.Key)
			defer endStream(client, upstream, done)

			stats := statsFor(t, h.proxy)

			require.Equal(t, []string{"198.51.100.7"}, stats.Users["alice"].ConnectedIPs,
				"the live connection's own address must be reported, not the transport's")
			require.Equal(t, "198.51.100.7", stats.Users["alice"].LastIP)
		})
	}
}

// Two clients of the same user from different addresses are both reported, and
// the list is sorted so two scrapes of an unchanged proxy agree.
func TestConnectedIPsListEveryAddressSorted(t *testing.T) {
	t.Parallel()

	secret, err := GenerateSecretMode(SecretModeDD, "")
	require.NoError(t, err)

	entry := govEntryCases()[1] // dd: no ServerHello round trip to sequence
	h := entry.harness(t, map[string]Secret{"alice": secret}, nil)
	h.proxy.trackClientIPs = true

	// Deliberately dialled highest-first, so a report that merely preserved
	// arrival order would fail this.
	for _, octet := range []byte{9, 3, 5} {
		client, done := dialProxyFrom(t, h, entry.policy,
			&net.TCPAddr{IP: net.IPv4(203, 0, 113, octet), Port: 40000 + int(octet)})

		upstream := connectThrough(t, entry, h, client, "alice", secret.Key)
		defer endStream(client, upstream, done)
	}

	stats := statsFor(t, h.proxy)

	require.Equal(t,
		[]string{"203.0.113.3", "203.0.113.5", "203.0.113.9"},
		stats.Users["alice"].ConnectedIPs)

	first := statsFor(t, h.proxy).Users["alice"].ConnectedIPs
	second := statsFor(t, h.proxy).Users["alice"].ConnectedIPs
	require.Equal(t, first, second, "two scrapes of an unchanged proxy must agree")
}

// The address of a connection that has ended stops being reported as connected,
// while last_ip -- which is about the most recent connection, not a live one --
// keeps it.
func TestConnectedIPsDropWithTheConnectionAndLastIPDoesNot(t *testing.T) {
	t.Parallel()

	secret, err := GenerateSecretMode(SecretModeDD, "")
	require.NoError(t, err)

	entry := govEntryCases()[1]
	h := entry.harness(t, map[string]Secret{"alice": secret}, nil)
	h.proxy.trackClientIPs = true

	client, done := dialProxyFrom(t, h, entry.policy,
		&net.TCPAddr{IP: net.IPv4(192, 0, 2, 33), Port: 40000})

	upstream := connectThrough(t, entry, h, client, "alice", secret.Key)

	require.Equal(t, []string{"192.0.2.33"}, statsFor(t, h.proxy).Users["alice"].ConnectedIPs)

	endStream(client, upstream, done)

	require.Eventually(t, func() bool {
		return len(statsFor(t, h.proxy).Users["alice"].ConnectedIPs) == 0
	}, 5*time.Second, 10*time.Millisecond,
		"a closed connection must stop being reported as connected")

	require.Equal(t, "192.0.2.33", statsFor(t, h.proxy).Users["alice"].LastIP,
		"last_ip outlives the connection it came from -- that is what it is for")
}

// Off by default, and off means absent rather than empty: a deployment that
// never asked for addresses produces the same /stats document it always did.
func TestAddressesAreAbsentUnlessTracked(t *testing.T) {
	t.Parallel()

	secret, err := GenerateSecretMode(SecretModeDD, "")
	require.NoError(t, err)

	entry := govEntryCases()[1]
	h := entry.harness(t, map[string]Secret{"alice": secret}, nil)

	require.False(t, h.proxy.trackClientIPs,
		"a harness-built proxy must not track addresses unless a test says so")

	client, done := dialProxyFrom(t, h, entry.policy,
		&net.TCPAddr{IP: net.IPv4(192, 0, 2, 44), Port: 40000})

	upstream := connectThrough(t, entry, h, client, "alice", secret.Key)
	defer endStream(client, upstream, done)

	recorder := httptest.NewRecorder()
	h.proxy.handleStats(recorder, httptest.NewRequest(http.MethodGet, "/stats", nil))

	var document map[string]any

	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &document))

	users, ok := document["users"].(map[string]any)
	require.True(t, ok)

	alice, ok := users["alice"].(map[string]any)
	require.True(t, ok)

	require.NotContains(t, alice, "connected_ips",
		"an untracking deployment's /stats must be byte-identical to before the field existed")
	require.NotContains(t, alice, "last_ip")

	// The counter that proves the connection really was live while the fields
	// were absent -- otherwise this test would pass on a proxy that admitted
	// nothing at all.
	require.EqualValues(t, 1, statsFor(t, h.proxy).Users["alice"].Connections)
}

// The capability is advertised, so a panel can offer the switch without probing
// for the fields (whose absence is indistinguishable from an idle secret).
func TestClientIPsCapabilityIsAdvertised(t *testing.T) {
	t.Parallel()

	require.Contains(t, supportedFeatures, FeatureClientIPs)
}
