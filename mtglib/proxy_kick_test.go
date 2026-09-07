package mtglib

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

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
