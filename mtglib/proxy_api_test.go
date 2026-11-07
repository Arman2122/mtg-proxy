package mtglib

import (
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newAPITestProxy(secrets map[string]Secret) *Proxy {
	p := newReloadTestProxy(secrets)
	p.logger = testLogger()

	return p
}

func doAPI(t *testing.T, p *Proxy, token, method, target, body string) *httptest.ResponseRecorder {
	t.Helper()

	handler := p.buildAPIHandler(token)

	var reader *strings.Reader
	if body != "" {
		reader = strings.NewReader(body)
	} else {
		reader = strings.NewReader("")
	}

	req := httptest.NewRequest(method, target, reader)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	return rec
}

func TestAPISecretsCRUD(t *testing.T) {
	t.Parallel()

	alice := GenerateSecret("alice.example.com")
	bob := GenerateSecret("bob.example.com")

	t.Run("GET lists the active secrets", func(t *testing.T) {
		t.Parallel()

		p := newAPITestProxy(map[string]Secret{"alice": alice})
		rec := doAPI(t, p, "", http.MethodGet, "/secrets", "")

		require.Equal(t, http.StatusOK, rec.Code)

		var resp struct {
			Secrets []SecretInfo `json:"secrets"`
		}
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
		require.Len(t, resp.Secrets, 1)
		assert.Equal(t, "alice", resp.Secrets[0].Name)
		assert.Equal(t, alice.Base64(), resp.Secrets[0].Secret)
		assert.Equal(t, "alice.example.com", resp.Secrets[0].Host)
	})

	t.Run("POST adds a secret", func(t *testing.T) {
		t.Parallel()

		p := newAPITestProxy(map[string]Secret{"alice": alice})
		body := `{"name":"bob","secret":"` + bob.Hex() + `"}`
		rec := doAPI(t, p, "", http.MethodPost, "/secrets", body)

		require.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, []string{"alice", "bob"}, p.secrets.Load().names)
	})

	t.Run("POST with an ad_tag sets the per-secret override", func(t *testing.T) {
		t.Parallel()

		p := newAPITestProxy(map[string]Secret{"alice": alice})
		tag := strings.Repeat("ab", AdTagLength)
		body := `{"name":"bob","secret":"` + bob.Hex() + `","ad_tag":"` + tag + `"}`
		rec := doAPI(t, p, "", http.MethodPost, "/secrets", body)

		require.Equal(t, http.StatusOK, rec.Code)

		set := p.secrets.Load()
		idx := -1
		for i, n := range set.names {
			if n == "bob" {
				idx = i
			}
		}
		require.GreaterOrEqual(t, idx, 0)
		require.NotNil(t, set.adTags[idx])
		assert.Equal(t, tag, hex.EncodeToString(set.adTags[idx][:]))
	})

	t.Run("PUT replaces the whole set", func(t *testing.T) {
		t.Parallel()

		p := newAPITestProxy(map[string]Secret{"alice": alice})
		body := `{"secrets":{"carol":{"secret":"` + GenerateSecret("carol.example.com").Hex() + `"}}}`
		rec := doAPI(t, p, "", http.MethodPut, "/secrets", body)

		require.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, []string{"carol"}, p.secrets.Load().names)
	})

	t.Run("DELETE removes a secret", func(t *testing.T) {
		t.Parallel()

		p := newAPITestProxy(map[string]Secret{"alice": alice, "bob": bob})
		rec := doAPI(t, p, "", http.MethodDelete, "/secrets/bob", "")

		require.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, []string{"alice"}, p.secrets.Load().names)
	})

	t.Run("DELETE of an unknown secret is 404", func(t *testing.T) {
		t.Parallel()

		p := newAPITestProxy(map[string]Secret{"alice": alice})
		rec := doAPI(t, p, "", http.MethodDelete, "/secrets/ghost", "")

		assert.Equal(t, http.StatusNotFound, rec.Code)
	})

	t.Run("DELETE of the last secret is 409 and keeps the set", func(t *testing.T) {
		t.Parallel()

		p := newAPITestProxy(map[string]Secret{"alice": alice})
		rec := doAPI(t, p, "", http.MethodDelete, "/secrets/alice", "")

		assert.Equal(t, http.StatusConflict, rec.Code)
		assert.Equal(t, []string{"alice"}, p.secrets.Load().names)
	})

	t.Run("POST with an invalid secret is 400", func(t *testing.T) {
		t.Parallel()

		p := newAPITestProxy(map[string]Secret{"alice": alice})
		rec := doAPI(t, p, "", http.MethodPost, "/secrets", `{"name":"bob","secret":"not-a-secret"}`)

		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("malformed JSON body is 400", func(t *testing.T) {
		t.Parallel()

		p := newAPITestProxy(map[string]Secret{"alice": alice})
		rec := doAPI(t, p, "", http.MethodPost, "/secrets", `{"name":`)

		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("unsupported method is rejected", func(t *testing.T) {
		t.Parallel()

		p := newAPITestProxy(map[string]Secret{"alice": alice})
		rec := doAPI(t, p, "", http.MethodPatch, "/secrets", "")

		assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
	})
}

func TestAPIAdTag(t *testing.T) {
	t.Parallel()

	alice := GenerateSecret("alice.example.com")
	tag := strings.Repeat("cd", AdTagLength)

	t.Run("PUT then GET then DELETE the global tag", func(t *testing.T) {
		t.Parallel()

		p := newAPITestProxy(map[string]Secret{"alice": alice})

		rec := doAPI(t, p, "", http.MethodPut, "/adtag", `{"ad_tag":"`+tag+`"}`)
		require.Equal(t, http.StatusOK, rec.Code)
		require.NotNil(t, p.GlobalAdTag())
		assert.Equal(t, tag, hex.EncodeToString(p.GlobalAdTag()[:]))

		rec = doAPI(t, p, "", http.MethodGet, "/adtag", "")
		require.Equal(t, http.StatusOK, rec.Code)
		var resp map[string]any
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
		assert.Equal(t, tag, resp["ad_tag"])

		rec = doAPI(t, p, "", http.MethodDelete, "/adtag", "")
		require.Equal(t, http.StatusOK, rec.Code)
		assert.Nil(t, p.GlobalAdTag())
	})

	t.Run("PUT with a wrong-length tag is 400", func(t *testing.T) {
		t.Parallel()

		p := newAPITestProxy(map[string]Secret{"alice": alice})
		rec := doAPI(t, p, "", http.MethodPut, "/adtag", `{"ad_tag":"abcd"}`)

		assert.Equal(t, http.StatusBadRequest, rec.Code)
		assert.Nil(t, p.GlobalAdTag())
	})
}

func TestAPIAuth(t *testing.T) {
	t.Parallel()

	alice := GenerateSecret("alice.example.com")

	t.Run("no token configured means open access", func(t *testing.T) {
		t.Parallel()

		p := newAPITestProxy(map[string]Secret{"alice": alice})
		handler := p.buildAPIHandler("")

		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/secrets", nil))

		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("correct bearer token is accepted", func(t *testing.T) {
		t.Parallel()

		p := newAPITestProxy(map[string]Secret{"alice": alice})
		rec := doAPI(t, p, "s3cr3t", http.MethodGet, "/secrets", "")

		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("missing token is 401", func(t *testing.T) {
		t.Parallel()

		p := newAPITestProxy(map[string]Secret{"alice": alice})
		handler := p.buildAPIHandler("s3cr3t")

		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/secrets", nil))

		assert.Equal(t, http.StatusUnauthorized, rec.Code)
		assert.Equal(t, "Bearer", rec.Header().Get("WWW-Authenticate"))
	})

	t.Run("wrong token is 401", func(t *testing.T) {
		t.Parallel()

		p := newAPITestProxy(map[string]Secret{"alice": alice})
		handler := p.buildAPIHandler("s3cr3t")

		req := httptest.NewRequest(http.MethodGet, "/secrets", nil)
		req.Header.Set("Authorization", "Bearer wrong")

		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})
}

func TestAPIPutSecretAdTagKeepsConnections(t *testing.T) {
	t.Parallel()

	alice := GenerateSecret("alice.example.com")
	tag := [AdTagLength]byte{1, 2, 3}

	t.Run("adtag-only change keeps live streams", func(t *testing.T) {
		t.Parallel()

		p := newAPITestProxy(map[string]Secret{"alice": alice})
		stream := registerFakeStream(p, "alice")

		require.NoError(t, p.PutSecret("alice", alice, &tag, nil))
		assert.NoError(t, stream.Err(), "adtag-only change must not drop the connection")

		set := p.secrets.Load()
		require.NotNil(t, set.adTags[0])
		assert.Equal(t, tag, *set.adTags[0])
	})

	t.Run("key change drops the live stream", func(t *testing.T) {
		t.Parallel()

		p := newAPITestProxy(map[string]Secret{"alice": alice})
		stream := registerFakeStream(p, "alice")

		rekeyed := GenerateSecret("alice.example.com")
		require.NoError(t, p.PutSecret("alice", rekeyed, nil, nil))
		assert.Error(t, stream.Err(), "re-keying must drop the old connection")
	})
}

// Forgetting a name takes everything filed under it out of the config: the
// secret, its advertising override and its limits, and nothing of another
// name's. A config with no overrides and no limits has nil maps, and forgetting
// a name from it is no different.
func TestForgettingASecretLeavesNothingFiledUnderIt(t *testing.T) {
	t.Parallel()

	alice := GenerateSecret("alice.example.com")
	bob := GenerateSecret("bob.example.com")

	t.Run("every map", func(t *testing.T) {
		t.Parallel()

		cfg := SecretConfig{
			Secrets:      map[string]Secret{"alice": alice, "bob": bob},
			SecretAdTags: map[string][AdTagLength]byte{"alice": {1}, "bob": {2}},
			Limits:       map[string]SecretLimits{"alice": {IPLimit: 1}, "bob": {IPLimit: 2}},
		}

		cfg.forget("bob")

		assert.Equal(t, map[string]Secret{"alice": alice}, cfg.Secrets)
		assert.Equal(t, map[string][AdTagLength]byte{"alice": {1}}, cfg.SecretAdTags)
		assert.Equal(t, map[string]SecretLimits{"alice": {IPLimit: 1}}, cfg.Limits,
			"the limits go with the secret, and alice's stay")
	})

	t.Run("nil maps", func(t *testing.T) {
		t.Parallel()

		cfg := SecretConfig{Secrets: map[string]Secret{"alice": alice, "bob": bob}}

		require.NotPanics(t, func() { cfg.forget("bob") })
		assert.Equal(t, map[string]Secret{"alice": alice}, cfg.Secrets)
		assert.Nil(t, cfg.SecretAdTags)
		assert.Nil(t, cfg.Limits)
	})
}

// A deleted secret leaves no limits behind: the proxy's config holds none for
// the name, and the name added back starts with none, as a new name does. A set
// is built from the names in Secrets alone, so this would hold even with limits
// left in the config DeleteSecret swaps in; the test above is the one that sees
// those.
func TestDeletingASecretLeavesNoLimitsBehind(t *testing.T) {
	t.Parallel()

	alice := GenerateSecret("alice.example.com")
	bob := GenerateSecret("bob.example.com")

	p := newAPITestProxy(map[string]Secret{"alice": alice, "bob": bob})

	require.NoError(t, p.PutSecret("bob", bob, nil, &SecretLimits{IPLimit: 2, SpeedBytesPerSecond: 1 << 20}))
	require.Contains(t, p.secrets.Load().toConfig().Limits, "bob", "the control: bob has limits")

	require.NoError(t, p.DeleteSecret("bob"))

	_, held := p.secrets.Load().limitsOf("bob")
	assert.False(t, held, "bob is gone")
	assert.NotContains(t, p.secrets.Load().toConfig().Limits, "bob", "and so are his limits")

	require.NoError(t, p.PutSecret("bob", bob, nil, nil))

	lim, held := p.secrets.Load().limitsOf("bob")
	require.True(t, held, "bob is back")
	assert.True(t, lim.IsZero(), "with no limits from before")
	assert.NotContains(t, p.secrets.Load().toConfig().Limits, "bob")
}
