package mtglib

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/netip"
	"testing"
	"time"

	"github.com/Arman2122/mtg-proxy/essentials"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A kick ends one user's streams at the named places and nothing else: the
// same user's other device keeps its connection, and an IPv6 address is
// matched at the /64 the limit counts, so the device that rotated its low bits
// is still the device that was kicked.
func TestKickEndsTheNamedPlacesOnly(t *testing.T) {
	t.Parallel()

	secret, err := GenerateSecretMode(SecretModeDD, "")
	require.NoError(t, err)

	ec := govEntryCases()[1]
	h := ec.harness(t, map[string]Secret{"alice": secret}, nil)

	phone, phoneDone := dialProxyFrom(t, h, ec.policy, tcpFrom("203.0.113.9", 53001))
	phoneUp := connectThrough(t, ec, h, phone, "alice", secret.Key)
	defer endStream(phone, phoneUp, phoneDone)

	laptop, laptopDone := dialProxyFrom(t, h, ec.policy, tcpFrom("2001:db8:1:2:aaaa::1", 53002))
	laptopUp := connectThrough(t, ec, h, laptop, "alice", secret.Key)
	defer endStream(laptop, laptopUp, laptopDone)

	require.Equal(t, int64(2), statsFor(t, h.proxy).Users["alice"].Connections)

	rec := doAPI(t, h.proxy, "", http.MethodPost, "/secrets/alice/kick", `{"ips":["2001:db8:1:2:ffff::9"]}`)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	var result KickResult
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &result))
	assert.Equal(t, 1, result.Closed, "the laptop's /64 was named, once")

	select {
	case <-laptopDone:
	case <-time.After(5 * time.Second):
		t.Fatal("the kicked stream must end")
	}

	select {
	case <-phoneDone:
		t.Fatal("the phone was not named and must keep its stream")
	case <-time.After(200 * time.Millisecond):
	}

	assert.Equal(t, int64(1), statsFor(t, h.proxy).Users["alice"].Connections)

	rec = doAPI(t, h.proxy, "", http.MethodPost, "/secrets/alice/kick", `{"ips":["198.51.100.1"]}`)
	require.Equal(t, http.StatusOK, rec.Code)
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &result))
	assert.Zero(t, result.Closed, "a place the user is not at is a kick of zero, not an error")
}

// The request is validated as the rest of the API is: an unknown secret is
// 404, and a body naming no address, a non-address, a zoned one or a prefix
// is 400.
func TestKickValidation(t *testing.T) {
	t.Parallel()

	alice := GenerateSecret("alice.example.com")
	p := newAPITestProxy(map[string]Secret{"alice": alice})

	assert.Equal(t, http.StatusNotFound,
		doAPI(t, p, "", http.MethodPost, "/secrets/ghost/kick", `{"ips":["203.0.113.9"]}`).Code)

	for _, body := range []string{
		`{}`, `{"ips":[]}`, `{"ips":["not-an-ip"]}`, `{"ips":["fe80::1%eth0"]}`, `{"ips":["203.0.113.0/24"]}`,
	} {
		assert.Equal(t, http.StatusBadRequest, doAPI(t, p, "", http.MethodPost, "/secrets/alice/kick", body).Code, body)
	}

	rec := doAPI(t, p, "", http.MethodPost, "/secrets/alice/kick", `{"ips":["203.0.113.9"]}`)
	require.Equal(t, http.StatusOK, rec.Code)
	assert.JSONEq(t, `{"closed":0}`, rec.Body.String())
}

// gatedNetwork is the harness's network with a Telegram dial the test holds:
// each dial says so on dialling and goes through only once gate is closed.
type gatedNetwork struct {
	*fakeNetwork

	dialling chan struct{}
	gate     chan struct{}
}

func (n *gatedNetwork) Dial(network, address string) (essentials.Conn, error) {
	n.dialling <- struct{}{}
	<-n.gate

	return n.fakeNetwork.Dial(network, address)
}

func (n *gatedNetwork) DialContext(_ context.Context, network, address string) (essentials.Conn, error) {
	return n.Dial(network, address)
}

// A stream revoked while its Telegram dial is in flight -- here by a kick; a
// reload or the proxy stopping does the same -- has its upstream closed by
// setTelegram rather than kept, and must leave without relaying: there is
// nothing to relay to. It used to reach the relay with a nil upstream and
// panic, which the worker pool recovers in production and which ends a test
// binary.
func TestAStreamRevokedWhileDiallingTelegramLeaves(t *testing.T) {
	t.Parallel()

	ec := govEntryCases()[1] // dd: no server flight to sequence
	secret := ec.secret(t)
	h := ec.harness(t, map[string]Secret{"alice": secret}, nil)

	network := &gatedNetwork{fakeNetwork: h.network, dialling: make(chan struct{}, 1), gate: make(chan struct{})}
	h.proxy.network = network

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	client, err := net.Dial("tcp", listener.Addr().String())
	require.NoError(t, err)

	t.Cleanup(func() { client.Close() }) //nolint: errcheck

	server, err := listener.Accept()
	require.NoError(t, err)
	require.NoError(t, listener.Close())

	conn := policyConn{
		Conn:   remoteAddrConn{Conn: essentials.WrapNetConn(server), addr: tcpFrom("203.0.113.9", 54001)},
		policy: *ec.policy,
	}

	// ServeConn on a goroutine of its own that records a panic instead of
	// ending the binary -- as far as one can be caught: a panic on a goroutine
	// the relay starts cannot be, and still ends it.
	var (
		done     = make(chan struct{})
		panicked any
	)

	go func() {
		defer close(done)
		defer func() { panicked = recover() }()

		h.proxy.ServeConn(conn)
	}()

	ec.openEntry(t, client, secret.Key)

	_, err = client.Write([]byte("bytes the relay must never carry"))
	require.NoError(t, err)

	select {
	case <-network.dialling:
	case <-time.After(5 * time.Second):
		t.Fatal("the admitted stream never dialled Telegram")
	}

	closed, err := h.proxy.Kick("alice", []netip.Addr{netip.MustParseAddr("203.0.113.9")})
	require.NoError(t, err)
	require.Equal(t, 1, closed, "the stream is live, admitted and dialling, and the kick finds it")

	close(network.gate)

	require.True(t, govAwait(done, govDenyBudget), "a stream revoked while dialling must leave, not relay")
	require.Nil(t, panicked, "ServeConn panicked: %v", panicked)

	// Telegram got the handshake the dial sends, then the socket setTelegram
	// closed: not one byte of the client's.
	upstream, err := h.upstream.Accept()
	require.NoError(t, err)

	t.Cleanup(func() { upstream.Close() }) //nolint: errcheck

	require.NoError(t, upstream.SetReadDeadline(time.Now().Add(5*time.Second)))

	var handshake [64]byte

	_, err = io.ReadFull(upstream, handshake[:])
	require.NoError(t, err)

	rest, err := io.ReadAll(upstream)
	require.NoError(t, err, "the upstream is closed, not left open")
	assert.Empty(t, rest, "nothing was relayed")

	h.proxy.liveMu.Lock()
	assert.Empty(t, h.proxy.liveConns["alice"], "the stream left the registry")
	h.proxy.liveMu.Unlock()
}
